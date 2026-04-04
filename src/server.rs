use crate::config::Config;
use crate::{relay, socks5};
use anyhow::{bail, Context, Result};
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::time::{timeout, Duration};
use tokio_rustls::TlsAcceptor;

/// Ждём первый байт на сокете (без снятия с буфера) для `--tls-flex`.
#[cfg(unix)]
async fn await_mux_first_byte(stream: &tokio::net::TcpStream) -> std::io::Result<u8> {
    use std::io::ErrorKind;
    let mut buf = [0u8; 1];
    loop {
        match peek_tcp_prefix(stream, &mut buf) {
            Ok(0) => return Err(ErrorKind::UnexpectedEof.into()),
            Ok(_) => return Ok(buf[0]),
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                stream.readable().await?;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Без MSG_PEEK — один неблокирующий peek; при пустом буфере сразу WouldBlock (ограничение платформы).
#[cfg(not(unix))]
async fn await_mux_first_byte(stream: &tokio::net::TcpStream) -> std::io::Result<u8> {
    use std::io::ErrorKind;
    let mut buf = [0u8; 1];
    match peek_tcp_prefix(stream, &mut buf)? {
        1 => Ok(buf[0]),
        0 => Err(ErrorKind::UnexpectedEof.into()),
        _ => Err(ErrorKind::InvalidInput.into()),
    }
}

#[cfg(unix)]
fn peek_tcp_prefix(stream: &tokio::net::TcpStream, buf: &mut [u8]) -> std::io::Result<usize> {
    use std::os::fd::AsRawFd;
    stream.try_io(tokio::io::Interest::READABLE, || {
        let fd = stream.as_raw_fd();
        let n = unsafe {
            libc::recv(
                fd,
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
                libc::MSG_PEEK,
            )
        };
        if n < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    })
}

#[cfg(not(unix))]
fn peek_tcp_prefix(_stream: &tokio::net::TcpStream, _buf: &mut [u8]) -> std::io::Result<usize> {
    Ok(0)
}

pub async fn run(config: Config) -> Result<()> {
    let tls_acceptor = build_tls_acceptor(&config)?;
    let listener = TcpListener::bind(config.listen).await?;

    if tls_acceptor.is_some() {
        if config.tls_flex {
            tracing::info!(
                addr = %config.listen,
                "--tls-flex: на порту принимаются TLS и plaintext SOCKS5"
            );
        }
        tracing::info!(addr = %config.listen, "SOCKS5 прокси запущен (TLS)");
    } else {
        tracing::info!(addr = %config.listen, "SOCKS5 прокси запущен");
    }
    if config.require_auth() {
        tracing::info!(users = config.users.len(), "авторизация включена");
    } else {
        tracing::warn!("авторизация отключена — все подключения разрешены");
    }
    if let Some(ref sni) = config.sni_spoof {
        tracing::info!(sni = %sni, "подмена SNI включена");
    }

    loop {
        let (stream, peer) = listener.accept().await?;
        stream.set_nodelay(true).ok();
        let cfg = config.clone();
        let acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            let result = match acceptor {
                Some(tls) => {
                    if cfg.tls_flex {
                        const MUX_WAIT: Duration = Duration::from_secs(60);
                        let first = match timeout(MUX_WAIT, await_mux_first_byte(&stream)).await {
                            Ok(Ok(b)) => b,
                            Ok(Err(e)) => {
                                tracing::warn!(%peer, "(--tls-flex) ожидание первого байта: {e}");
                                return;
                            }
                            Err(_) => {
                                tracing::warn!(%peer, "(--tls-flex) таймаут ожидания первого байта");
                                return;
                            }
                        };
                        if first == 0x05 {
                            tracing::info!(%peer, "SOCKS5 без TLS (--tls-flex), тот же порт что и для TLS");
                            handle_client(stream, peer, cfg).await
                        } else {
                            match tls.accept(stream).await {
                                Ok(tls_stream) => handle_client(tls_stream, peer, cfg).await,
                                Err(e) => {
                                    tracing::warn!(%peer, "TLS хендшейк не удался: {e}");
                                    return;
                                }
                            }
                        }
                    } else {
                        match tls.accept(stream).await {
                            Ok(tls_stream) => handle_client(tls_stream, peer, cfg).await,
                            Err(e) => {
                                tracing::warn!(%peer, "TLS хендшейк не удался: {e}");
                                return;
                            }
                        }
                    }
                }
                None => handle_client(stream, peer, cfg).await,
            };
            if let Err(e) = result {
                tracing::warn!(%peer, "сессия завершена: {e:#}");
            }
        });
    }
}

#[tracing::instrument(name = "client", skip_all, fields(%peer))]
async fn handle_client<S>(
    mut client: S,
    peer: SocketAddr,
    config: Config,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    socks5::handshake(&mut client, &config).await?;
    let target = socks5::read_connect(&mut client).await?;
    tracing::info!(%target, "CONNECT");

    let mut remote = match target.connect().await {
        Ok(s) => s,
        Err(e) => {
            let reply = match e.kind() {
                std::io::ErrorKind::ConnectionRefused => socks5::Reply::ConnectionRefused,
                _ => socks5::Reply::HostUnreachable,
            };
            socks5::send_reply(&mut client, reply).await.ok();
            bail!("подключение к {target} не удалось: {e}");
        }
    };
    remote.set_nodelay(true)?;

    let bind = remote.local_addr()?;
    socks5::send_connect_ok(&mut client, bind).await?;

    let target_label = target.to_string();
    // #region agent log
    let spoof = config
        .sni_spoof
        .as_deref()
        .map(|s| format!("\"{}\"", crate::debug_agent::ej(s)))
        .unwrap_or_else(|| "null".to_string());
    crate::debug_agent::emit(
        "H1-H2",
        "server.rs:handle_client",
        "tunnel_ready_before_relay",
        "icloud-repro",
        peer,
        &format!(
            r#""target":"{}","port":{},"sni_spoof":{}"#,
            crate::debug_agent::ej(&target_label),
            target.port(),
            spoof
        ),
    );
    // #endregion agent log

    let is_tls = target.port() == 443;
    let sni = if is_tls {
        config.sni_spoof.as_deref()
    } else {
        None
    };
    let relay_res = relay::relay(&mut client, &mut remote, sni, peer, &target_label).await;
    // #region agent log
    if let Err(ref e) = relay_res {
        crate::debug_agent::emit(
            "H4",
            "server.rs:handle_client",
            "relay_error",
            "icloud-repro",
            peer,
            &format!(
                r#""target":"{}","err":"{}""#,
                crate::debug_agent::ej(&target_label),
                crate::debug_agent::ej(&e.to_string())
            ),
        );
    }
    // #endregion agent log
    let (up, down) = relay_res?;

    tracing::info!(up, down, "релей завершён");
    Ok(())
}

fn build_tls_acceptor(config: &Config) -> Result<Option<TlsAcceptor>> {
    let (cert_path, key_path) = match (&config.tls_cert, &config.tls_key) {
        (Some(c), Some(k)) => (c.as_str(), k.as_str()),
        (None, None) => return Ok(None),
        _ => bail!("нужно указать оба --tls-cert и --tls-key"),
    };

    use tokio_rustls::rustls;

    let certs = {
        let file = std::fs::File::open(cert_path)
            .with_context(|| format!("не удалось открыть сертификат: {cert_path}"))?;
        rustls_pemfile::certs(&mut BufReader::new(file))
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| format!("ошибка чтения сертификата: {cert_path}"))?
    };

    let key = {
        let file = std::fs::File::open(key_path)
            .with_context(|| format!("не удалось открыть ключ: {key_path}"))?;
        rustls_pemfile::private_key(&mut BufReader::new(file))
            .with_context(|| format!("ошибка чтения ключа: {key_path}"))?
            .ok_or_else(|| anyhow::anyhow!("приватный ключ не найден в {key_path}"))?
    };

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("ошибка конфигурации TLS-версий")?
        .with_no_client_auth()
        .with_single_cert(certs, key.into())
        .context("ошибка конфигурации TLS-сертификата")?;

    Ok(Some(TlsAcceptor::from(Arc::new(tls_config))))
}
