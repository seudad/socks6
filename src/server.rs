use crate::config::Config;
use crate::{reality, relay, socks5};
use anyhow::{bail, Context, Result};
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};
use tokio_rustls::TlsAcceptor;

// ── Peek helpers for --tls-flex ─────────────────────────────────────────

#[cfg(unix)]
async fn await_mux_first_byte(stream: &TcpStream) -> std::io::Result<u8> {
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

#[cfg(not(unix))]
async fn await_mux_first_byte(stream: &TcpStream) -> std::io::Result<u8> {
    use std::io::ErrorKind;
    let mut buf = [0u8; 1];
    match peek_tcp_prefix(stream, &mut buf)? {
        1 => Ok(buf[0]),
        0 => Err(ErrorKind::UnexpectedEof.into()),
        _ => Err(ErrorKind::InvalidInput.into()),
    }
}

#[cfg(unix)]
fn peek_tcp_prefix(stream: &TcpStream, buf: &mut [u8]) -> std::io::Result<usize> {
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
fn peek_tcp_prefix(_stream: &TcpStream, _buf: &mut [u8]) -> std::io::Result<usize> {
    Ok(0)
}

// ── Main entry point ────────────────────────────────────────────────────

pub async fn run(config: Config) -> Result<()> {
    let force_tls13 = config.reality_enabled();
    let tls_acceptor = build_tls_acceptor(&config, force_tls13)?;
    let listener = TcpListener::bind(config.listen).await?;

    if config.reality_enabled() {
        tracing::info!(
            addr = %config.listen,
            dest = config.reality_dest.as_deref().unwrap_or("-"),
            "SOCKS5 прокси запущен (Reality + TLS 1.3)"
        );
    } else if tls_acceptor.is_some() {
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
        if !config.sni_exclude.is_empty() {
            tracing::info!(
                exclude = ?config.sni_exclude,
                "SNI: исключения (--sni-exclude)"
            );
        }
    }

    loop {
        let (stream, peer) = listener.accept().await?;
        stream.set_nodelay(true).ok();
        let cfg = config.clone();
        let acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            let result = if cfg.reality_enabled() {
                handle_reality_connection(stream, peer, cfg, acceptor.unwrap()).await
            } else {
                match acceptor {
                    Some(tls) => {
                        if cfg.tls_flex {
                            handle_tls_flex(stream, peer, cfg, tls).await
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
                }
            };
            if let Err(e) = result {
                tracing::warn!(%peer, "сессия завершена: {e:#}");
            }
        });
    }
}

// ── Reality accept path ─────────────────────────────────────────────────

/// Reality accept path.
///
/// 1. Read the ClientHello, extract SNI for fallback routing.
/// 2. If SNI matches `--reality-server-names` → TLS handshake + in-tunnel auth → SOCKS5.
/// 3. Otherwise → relay raw bytes to `--reality-dest` (prober sees the real cover cert).
async fn handle_reality_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    config: Config,
    tls: TlsAcceptor,
) -> Result<()> {
    const CH_TIMEOUT: Duration = Duration::from_secs(10);

    let first = match timeout(CH_TIMEOUT, await_mux_first_byte(&stream)).await {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => {
            tracing::debug!(%peer, "Reality: peek error: {e}");
            return Ok(());
        }
        Err(_) => {
            tracing::debug!(%peer, "Reality: таймаут ожидания данных");
            return Ok(());
        }
    };

    let dest = config.reality_dest.as_deref().unwrap();

    if first != 0x16 {
        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await.unwrap_or(0);
        buf.truncate(n);
        tracing::info!(%peer, "Reality: не TLS ({first:#x}), fallback → {dest}");
        reality::fallback_relay(stream, buf, dest).await.ok();
        return Ok(());
    }

    let ch_buf = match timeout(CH_TIMEOUT, reality::read_tls_record(&mut stream)).await {
        Ok(Ok(buf)) => buf,
        Ok(Err(e)) => {
            tracing::debug!(%peer, "Reality: ошибка чтения CH: {e}");
            return Ok(());
        }
        Err(_) => {
            tracing::debug!(%peer, "Reality: таймаут чтения CH");
            return Ok(());
        }
    };

    let fields = match reality::parse_client_hello(&ch_buf) {
        Some(f) => f,
        None => {
            tracing::info!(%peer, "Reality: невалидный ClientHello, fallback → {dest}");
            reality::fallback_relay(stream, ch_buf, dest).await.ok();
            return Ok(());
        }
    };

    let sni_ok = fields
        .sni
        .as_ref()
        .map(|s| config.reality_server_names.iter().any(|n| n == s))
        .unwrap_or(false);

    if !sni_ok {
        tracing::info!(%peer, sni = ?fields.sni, "Reality: SNI не в списке, fallback → {dest}");
        reality::fallback_relay(stream, ch_buf, dest).await.ok();
        return Ok(());
    }

    // SNI matches — do TLS handshake, then verify in-tunnel auth
    let replay = reality::ReplayStream::new(ch_buf, stream);
    let mut tls_stream = match tls.accept(replay).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(%peer, "Reality: TLS хендшейк не удался: {e}");
            return Ok(());
        }
    };

    let secret = config.reality_secret.as_ref().unwrap();
    const AUTH_TIMEOUT: Duration = Duration::from_secs(5);
    let auth_result = timeout(
        AUTH_TIMEOUT,
        reality::recv_and_verify_tunnel_auth(
            &mut tls_stream,
            secret,
            &config.reality_short_ids,
            config.reality_max_time_diff,
        ),
    )
    .await;

    match auth_result {
        Ok(Ok(short_id)) => {
            tracing::info!(
                %peer,
                short_id = %reality::hex_encode(&short_id),
                "Reality: аутентификация ОК"
            );
            handle_client(tls_stream, peer, config).await
        }
        Ok(Err(e)) => {
            tracing::info!(%peer, "Reality: auth failed: {e:#}");
            Ok(())
        }
        Err(_) => {
            tracing::info!(%peer, "Reality: auth таймаут");
            Ok(())
        }
    }
}

// ── TLS-flex path ───────────────────────────────────────────────────────

async fn handle_tls_flex(
    stream: TcpStream,
    peer: SocketAddr,
    config: Config,
    tls: TlsAcceptor,
) -> Result<()> {
    const MUX_WAIT: Duration = Duration::from_secs(60);
    let first = match timeout(MUX_WAIT, await_mux_first_byte(&stream)).await {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => {
            tracing::warn!(%peer, "(--tls-flex) peek: {e}");
            return Ok(());
        }
        Err(_) => {
            tracing::warn!(%peer, "(--tls-flex) таймаут");
            return Ok(());
        }
    };
    if first == 0x05 {
        tracing::info!(%peer, "SOCKS5 plaintext (--tls-flex)");
        handle_client(stream, peer, config).await
    } else {
        match tls.accept(stream).await {
            Ok(tls_stream) => handle_client(tls_stream, peer, config).await,
            Err(e) => {
                tracing::warn!(%peer, "TLS хендшейк не удался: {e}");
                Ok(())
            }
        }
    }
}

// ── Client handler ──────────────────────────────────────────────────────

/// Подмена SNI только для порта 443 и если имя хоста не попадает под `--sni-exclude`.
fn effective_sni_spoof<'a>(config: &'a Config, target: &socks5::TargetAddr) -> Option<&'a str> {
    if target.port() != 443 {
        return None;
    }
    let spoof = config.sni_spoof.as_deref()?;
    match target {
        socks5::TargetAddr::Domain(host, _) => {
            let h = host.to_ascii_lowercase();
            for p in &config.sni_exclude {
                if h == *p || h.ends_with(&format!(".{}", p)) {
                    return None;
                }
            }
            Some(spoof)
        }
        socks5::TargetAddr::Ip(_) => Some(spoof),
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

    let sni = effective_sni_spoof(&config, &target);
    if config.sni_spoof.is_some() && sni.is_none() && target.port() == 443 {
        if let socks5::TargetAddr::Domain(host, _) = &target {
            tracing::info!(%peer, host = %host, "подмена SNI отключена (--sni-exclude)");
        }
    }

    let (up, down) = relay::relay(&mut client, &mut remote, sni).await?;

    tracing::info!(up, down, "релей завершён");
    Ok(())
}

// ── TLS acceptor builder ────────────────────────────────────────────────

fn build_tls_acceptor(config: &Config, force_tls13: bool) -> Result<Option<TlsAcceptor>> {
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

    let builder = if force_tls13 {
        rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .context("ошибка конфигурации TLS 1.3")?
    } else {
        rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .context("ошибка конфигурации TLS-версий")?
    };

    let tls_config = builder
        .with_no_client_auth()
        .with_single_cert(certs, key.into())
        .context("ошибка конфигурации TLS-сертификата")?;

    Ok(Some(TlsAcceptor::from(Arc::new(tls_config))))
}
