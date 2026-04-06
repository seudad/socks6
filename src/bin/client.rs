use anyhow::{bail, Context, Result};
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_rustls::rustls;
use tokio_rustls::TlsConnector;

// ── Client config ───────────────────────────────────────────────────────

struct ClientConfig {
    listen: SocketAddr,
    server: String,
    server_name: String,
    secret: [u8; 32],
    short_id: [u8; 8],
    auth: Option<(String, String)>,
    /// Макс. одновременных установок TLS к серверу (остальные ждут в очереди).
    max_tls_parallel: usize,
}

impl ClientConfig {
    fn from_args() -> Result<Self> {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let mut listen: Option<SocketAddr> = None;
        let mut server: Option<String> = None;
        let mut server_name: Option<String> = None;
        let mut secret: Option<[u8; 32]> = None;
        let mut short_id: Option<[u8; 8]> = None;
        let mut auth: Option<(String, String)> = None;
        let mut max_tls_parallel: Option<usize> = None;

        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--listen" | "-l" => {
                    i += 1;
                    listen = Some(
                        args.get(i)
                            .context("--listen требует адрес")?
                            .parse()
                            .context("невалидный адрес")?,
                    );
                }
                "--server" | "-s" => {
                    i += 1;
                    server = Some(args.get(i).context("--server требует адрес")?.clone());
                }
                "--server-name" => {
                    i += 1;
                    server_name = Some(
                        args.get(i)
                            .context("--server-name требует домен")?
                            .clone(),
                    );
                }
                "--secret" => {
                    i += 1;
                    let b64 = args.get(i).context("--secret требует base64")?;
                    let bytes = base64::Engine::decode(
                        &base64::engine::general_purpose::STANDARD,
                        b64,
                    )
                    .context("невалидный base64")?;
                    if bytes.len() != 32 {
                        bail!("secret: ожидается 32 байта, получено {}", bytes.len());
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    secret = Some(arr);
                }
                "--short-id" => {
                    i += 1;
                    let hex = args.get(i).context("--short-id требует hex")?;
                    let bytes =
                        socks6::reality::hex_decode(hex).context("невалидный hex")?;
                    if bytes.len() != 8 {
                        bail!(
                            "short-id: ожидается 8 байт (16 hex), получено {}",
                            bytes.len()
                        );
                    }
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(&bytes);
                    short_id = Some(arr);
                }
                "--auth" => {
                    i += 1;
                    let pair = args.get(i).context("--auth требует user:pass")?;
                    let (u, p) = pair.split_once(':').context("формат: user:pass")?;
                    auth = Some((u.to_owned(), p.to_owned()));
                }
                "--max-tls" => {
                    i += 1;
                    max_tls_parallel = Some(
                        args.get(i)
                            .context("--max-tls требует число")?
                            .parse()
                            .context("--max-tls: невалидное число")?,
                    );
                }
                "-h" | "--help" => {
                    Self::print_usage();
                    std::process::exit(0);
                }
                other => bail!("неизвестный аргумент: {other}"),
            }
            i += 1;
        }

        let max_tls_parallel = max_tls_parallel
            .or_else(|| {
                std::env::var("SOCKS6_CLIENT_MAX_TLS")
                    .ok()
                    .and_then(|s| s.parse().ok())
            })
            .unwrap_or(12);
        if max_tls_parallel == 0 {
            bail!("--max-tls / SOCKS6_CLIENT_MAX_TLS должен быть >= 1");
        }

        Ok(ClientConfig {
            listen: listen.unwrap_or_else(|| "127.0.0.1:1080".parse().unwrap()),
            server: server.context("--server обязателен")?,
            server_name: server_name.context("--server-name обязателен")?,
            secret: secret.context("--secret обязателен")?,
            short_id: short_id.context("--short-id обязателен")?,
            auth,
            max_tls_parallel,
        })
    }

    fn print_usage() {
        eprintln!("Reality SOCKS6 клиент\n");
        eprintln!("Использование: socks6-client [ОПЦИИ]\n");
        eprintln!("Опции:");
        eprintln!("  --listen, -l <addr>      локальный адрес (по умолчанию 127.0.0.1:1080; iPhone/LAN: 0.0.0.0:1080)");
        eprintln!("  --server, -s <addr>      адрес Reality сервера (host:port)");
        eprintln!("  --server-name <domain>   SNI для TLS (напр. www.google.com)");
        eprintln!("  --secret <base64>        общий секрет Reality");
        eprintln!("  --short-id <hex>         Short ID (16 hex символов)");
        eprintln!("  --auth <user:pass>       авторизация на сервере (если включена)");
        eprintln!("  --max-tls <N>            одновременных TLS к серверу (по умолчанию 12; env SOCKS6_CLIENT_MAX_TLS)");
        eprintln!("  -h, --help               показать справку");
    }
}

// ── Main ────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "socks6_client=info".parse().unwrap()),
        )
        .init();

    let config = match ClientConfig::from_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ошибка: {e:#}");
            eprintln!();
            ClientConfig::print_usage();
            std::process::exit(1);
        }
    };

    if let Err(e) = run(config).await {
        tracing::error!("фатальная ошибка: {e:#}");
        std::process::exit(1);
    }
}

/// Каждое SOCKS6-соединение держит отдельный сокет к приложению и отдельный TLS к серверу.
/// При низком `ulimit -n` (часто 256 на macOS) получают EMFILE / «Too many open files».
#[cfg(unix)]
fn raise_nofile_limit() {
    use libc::{getrlimit, rlimit, setrlimit, RLIMIT_NOFILE, RLIM_INFINITY};

    const TARGET: libc::rlim_t = 512 * 1024;

    unsafe {
        let mut rlim = std::mem::MaybeUninit::<rlimit>::uninit();
        if getrlimit(RLIMIT_NOFILE, rlim.as_mut_ptr()) != 0 {
            return;
        }
        let cur = rlim.assume_init();
        let hard = if cur.rlim_max == RLIM_INFINITY {
            TARGET
        } else {
            cur.rlim_max
        };
        let new_cur = hard.min(TARGET);
        if new_cur <= cur.rlim_cur {
            return;
        }
        let new = rlimit {
            rlim_cur: new_cur,
            rlim_max: cur.rlim_max,
        };
        if setrlimit(RLIMIT_NOFILE, &new) == 0 {
            tracing::info!(nofile_soft = new_cur, "RLIMIT_NOFILE повышен");
        } else {
            tracing::warn!(
                "не удалось поднять RLIMIT_NOFILE; при ошибке EMFILE в shell: ulimit -n 65535"
            );
        }
    }
}

#[cfg(not(unix))]
fn raise_nofile_limit() {}

async fn run(config: ClientConfig) -> Result<()> {
    raise_nofile_limit();
    if config.listen.ip().is_loopback() {
        tracing::warn!(
            addr = %config.listen,
            "слушаем только loopback — с телефона/LAN не подключиться; задайте --listen 0.0.0.0:1080"
        );
    }
    let tls_config = build_tls_config()?;
    let listener = TcpListener::bind(config.listen).await?;

    tracing::info!(
        addr = %config.listen,
        server = %config.server,
        sni = %config.server_name,
        max_tls = config.max_tls_parallel,
        "Reality клиент запущен"
    );

    let config = Arc::new(config);
    let tls_config = Arc::new(tls_config);
    let tls_slots = Arc::new(Semaphore::new(config.max_tls_parallel));

    loop {
        let (stream, peer) = listener.accept().await?;
        stream.set_nodelay(true).ok();
        let cfg = config.clone();
        let tls_cfg = tls_config.clone();
        let slots = tls_slots.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_local_client(stream, peer, cfg, tls_cfg, slots).await {
                tracing::warn!(%peer, "сессия завершена: {e:#}");
            }
        });
    }
}

// ── Per-connection handler ──────────────────────────────────────────────

#[tracing::instrument(name = "proxy", skip_all, fields(%peer))]
async fn handle_local_client(
    mut local: TcpStream,
    peer: SocketAddr,
    config: Arc<ClientConfig>,
    tls_config: Arc<rustls::ClientConfig>,
    tls_slots: Arc<Semaphore>,
) -> Result<()> {
    // 1. Accept SOCKS6 from local app
    local_socks6_handshake(&mut local).await?;
    tracing::debug!(%peer, "шаг 1/6: с телефона SOCKS приветствие OK");

    let (host, port) = local_socks6_read_connect(&mut local).await?;
    tracing::info!(target = %format!("{host}:{port}"), "CONNECT");
    tracing::debug!(%peer, host = %host, port, "шаг 2/6: запрошен CONNECT");

    // 2. Ограничить параллельные TLS к одному серверу (иначе при бурстах — tls handshake eof).
    let mut tunnel = {
        let _tls_slot = tls_slots
            .acquire()
            .await
            .context("TLS: семафор закрыт")?;
        tracing::debug!(%peer, "шаг 3/6: слот TLS к VPS взят");

        let connector = TlsConnector::from(tls_config);
        const MAX_TLS_HANDSHAKE_TRIES: u32 = 3;
        const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
        const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(25);
        let mut attempt: u32 = 0;
        let mut tunnel = loop {
            attempt += 1;
            let tcp = match timeout(TCP_CONNECT_TIMEOUT, TcpStream::connect(&config.server)).await {
                Ok(Ok(t)) => t,
                Ok(Err(e)) => {
                    return Err(e).with_context(|| {
                        format!(
                            "TCP к {} (нет SYN/ответа сервера или отказ)",
                            config.server
                        )
                    });
                }
                Err(_) => {
                    bail!(
                        "TCP к {}: таймаут {} с. Проверьте IP/порт, ufw на VPS, доступ с Mac (ping/маршрут не обязателен для TCP), VPN на Mac",
                        config.server,
                        TCP_CONNECT_TIMEOUT.as_secs()
                    );
                }
            };
            tcp.set_nodelay(true).ok();
            let tcp_local = tcp.local_addr().ok();
            let tcp_peer = tcp.peer_addr().ok();
            tracing::info!(
                %peer,
                attempt,
                target = %config.server,
                ?tcp_local,
                ?tcp_peer,
                "TCP сессия открыта: проверьте, что tcp_peer — ваш VPS:порт; если там другой IP — неверный аргумент -s или подмена в /etc/hosts"
            );
            tracing::debug!(%peer, attempt, server = %config.server, "шаг 4a: TCP до VPS установлен");

            let name = rustls::pki_types::ServerName::try_from(config.server_name.clone())
                .context("невалидный SNI")?;
            tracing::debug!(%peer, sni = %config.server_name, "шаг 4a→4b: старт TLS ClientHello к VPS");
            match timeout(TLS_HANDSHAKE_TIMEOUT, connector.connect(name, tcp)).await {
                Ok(Ok(t)) => {
                    if attempt > 1 {
                        tracing::debug!(%peer, attempt, "TLS: успех после повтора");
                    }
                    tracing::debug!(%peer, "шаг 4b: TLS к VPS готов");
                    break t;
                }
                Ok(Err(e)) => {
                    let retriable = matches!(
                        e.kind(),
                        ErrorKind::UnexpectedEof
                            | ErrorKind::ConnectionReset
                            | ErrorKind::ConnectionAborted
                    ) || e.to_string().to_lowercase().contains("eof");
                    if retriable && attempt < MAX_TLS_HANDSHAKE_TRIES {
                        tracing::debug!(%peer, attempt, err = %e, "TLS: повтор handshake");
                        tokio::time::sleep(Duration::from_millis(40 + 60 * attempt as u64)).await;
                        continue;
                    }
                    tracing::warn!(
                        %peer,
                        err = %e,
                        server = %config.server,
                        sni = %config.server_name,
                        "TLS к VPS не завершился после TCP (часто: SNI не в --reality-server-names → на VPS fallback на reality-dest и «чужой» TLS; или не тот порт/сервис). Смотрите логи socks6 на VPS: «SNI не в списке», «невалидный ClientHello»."
                    );
                    return Err(e).context("TLS хендшейк к VPS");
                }
                Err(_) => {
                    let msg = format!(
                        "TLS к {}: таймаут {} с после TCP (нет ServerHello). На этом host:port слушает не ваш socks6/TLS, пакеты режутся, или процесс на VPS не тот",
                        config.server,
                        TLS_HANDSHAKE_TIMEOUT.as_secs()
                    );
                    tracing::warn!(%peer, %attempt, "{}", msg);
                    if attempt < MAX_TLS_HANDSHAKE_TRIES {
                        tokio::time::sleep(Duration::from_millis(40 + 60 * attempt as u64)).await;
                        continue;
                    }
                    bail!("{}", msg);
                }
            }
        };

        socks6::reality::send_tunnel_auth(&mut tunnel, &config.secret, &config.short_id)
            .await
            .context("Reality аутентификация (если отказ: secret/short-id или часы на Mac и VPS)")?;
        tracing::debug!(%peer, "шаг 5/6: Reality auth к VPS OK");

        remote_socks6_connect(&mut tunnel, &host, port, config.auth.as_ref())
            .await
            .context("SOCKS6 через туннель")?;
        tracing::debug!(%peer, "шаг 6/6: на VPS удалённый CONNECT OK");

        tunnel
    };

    // 5. Send CONNECT OK to local app
    local_socks6_send_ok(&mut local).await?;
    tracing::debug!(%peer, "ответ CONNECT отправлен телефону, релей");

    // 6. Bidirectional relay
    let (up, down) = tokio::io::copy_bidirectional(&mut local, &mut tunnel).await?;
    tracing::info!(up, down, "релей завершён");
    Ok(())
}

// ── Local SOCKS6 (client acts as server to local apps) ──────────────────

async fn local_socks6_handshake(stream: &mut TcpStream) -> Result<()> {
    /// RFC 1928: сервер должен выбрать метод из списка клиента (или 0xFF).
    const AUTH_NONE: u8 = 0x00;
    const AUTH_REJECT: u8 = 0xff;

    let mut hdr = [0u8; 2];
    stream
        .read_exact(&mut hdr)
        .await
        .context("SOCKS6 greeting")?;
    if hdr[0] != 0x05 {
        bail!("не SOCKS6: {:#x}", hdr[0]);
    }
    let n = hdr[1] as usize;
    let mut methods = vec![0u8; n];
    stream.read_exact(&mut methods).await?;
    if methods.contains(&AUTH_NONE) {
        stream.write_all(&[0x05, AUTH_NONE]).await?;
        stream.flush().await.context("flush после выбора метода SOCKS")?;
    } else {
        stream.write_all(&[0x05, AUTH_REJECT]).await?;
        bail!(
            "клиент не предложил метод «без аутентификации»; в Shadowrocket для этого узла отключите user/password"
        );
    }
    Ok(())
}

async fn local_socks6_read_connect(stream: &mut TcpStream) -> Result<(String, u16)> {
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 || hdr[1] != 0x01 {
        bail!("не SOCKS6 CONNECT: ver={:#x} cmd={:#x}", hdr[0], hdr[1]);
    }
    match hdr[3] {
        0x01 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            let port = stream.read_u16().await?;
            Ok((format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]), port))
        }
        0x03 => {
            let len = stream.read_u8().await? as usize;
            let mut domain = vec![0u8; len];
            stream.read_exact(&mut domain).await?;
            let port = stream.read_u16().await?;
            Ok((String::from_utf8(domain).context("невалидный домен")?, port))
        }
        0x04 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            let port = stream.read_u16().await?;
            let addr = std::net::Ipv6Addr::from(ip);
            Ok((format!("[{addr}]"), port))
        }
        other => bail!("неподдерживаемый ATYP: {other:#x}"),
    }
}

async fn local_socks6_send_ok(stream: &mut TcpStream) -> Result<()> {
    stream
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    stream.flush().await.context("flush SOCKS6 CONNECT OK")?;
    Ok(())
}

// ── Remote SOCKS6 (client talks to the server through tunnel) ───────────

async fn remote_socks6_connect<S>(
    stream: &mut S,
    host: &str,
    port: u16,
    auth: Option<&(String, String)>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    if auth.is_some() {
        stream.write_all(&[0x05, 0x01, 0x02]).await?;
    } else {
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
    }

    let mut choice = [0u8; 2];
    stream.read_exact(&mut choice).await?;
    if choice[0] != 0x05 {
        bail!("сервер не SOCKS6: {:#x}", choice[0]);
    }

    match choice[1] {
        0x00 => {}
        0x02 => {
            let (user, pass) = auth.context("сервер требует авторизацию")?;
            let mut msg = Vec::with_capacity(3 + user.len() + pass.len());
            msg.push(0x01);
            msg.push(user.len() as u8);
            msg.extend_from_slice(user.as_bytes());
            msg.push(pass.len() as u8);
            msg.extend_from_slice(pass.as_bytes());
            stream.write_all(&msg).await?;
            let mut resp = [0u8; 2];
            stream.read_exact(&mut resp).await?;
            if resp[1] != 0x00 {
                bail!("авторизация на сервере не пройдена");
            }
        }
        0xFF => bail!("сервер отклонил методы аутентификации"),
        other => bail!("неподдерживаемый метод: {other:#x}"),
    }

    let mut req = Vec::with_capacity(4 + 1 + host.len() + 2);
    req.extend_from_slice(&[0x05, 0x01, 0x00]);

    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        req.push(0x01);
        req.extend_from_slice(&v4.octets());
    } else if let Ok(v6) = host
        .trim_matches(|c| c == '[' || c == ']')
        .parse::<std::net::Ipv6Addr>()
    {
        req.push(0x04);
        req.extend_from_slice(&v6.octets());
    } else {
        let len = host.len();
        if len > 255 {
            bail!("имя хоста для SOCKS длиннее 255 байт");
        }
        req.push(0x03);
        req.push(len as u8);
        req.extend_from_slice(host.as_bytes());
    }
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req).await?;

    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await?;
    if reply[0] != 0x05 {
        bail!("невалидный SOCKS6 ответ: {:#x}", reply[0]);
    }
    if reply[1] != 0x00 {
        bail!("сервер CONNECT отклонён: {:#x}", reply[1]);
    }

    match reply[3] {
        0x01 => {
            let mut skip = [0u8; 6];
            stream.read_exact(&mut skip).await?;
        }
        0x03 => {
            let len = stream.read_u8().await? as usize;
            let mut skip = vec![0u8; len + 2];
            stream.read_exact(&mut skip).await?;
        }
        0x04 => {
            let mut skip = [0u8; 18];
            stream.read_exact(&mut skip).await?;
        }
        atyp => bail!("SOCKS CONNECT OK: неизвестный ATYP в ответе сервера: {atyp:#x}"),
    }

    Ok(())
}

// ── TLS config (skip cert verification for Reality) ─────────────────────

fn build_tls_config() -> Result<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("TLS 1.3 config")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerify))
        .with_no_client_auth();
    Ok(config)
}

#[derive(Debug)]
struct NoCertVerify;

impl rustls::client::danger::ServerCertVerifier for NoCertVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
