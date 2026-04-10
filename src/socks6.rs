use crate::config::Config;
use anyhow::{bail, Context, Result};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

const VER: u8 = 0x06;
const AUTH_NONE: u8 = 0x00;
const AUTH_USERPASS: u8 = 0x02;
const AUTH_REJECT: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum Reply {
    Succeeded = 0x00,
    #[allow(dead_code)]
    GeneralFailure = 0x01,
    #[allow(dead_code)]
    NotAllowed = 0x02,
    #[allow(dead_code)]
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    CommandNotSupported = 0x07,
    AddrTypeNotSupported = 0x08,
}

pub enum SocksCommand {
    Connect(TargetAddr),
    UdpAssociate(TargetAddr),
}

pub enum TargetAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(a) => write!(f, "{a}"),
            Self::Domain(h, p) => write!(f, "{h}:{p}"),
        }
    }
}

impl TargetAddr {
    pub fn port(&self) -> u16 {
        match self {
            Self::Ip(a) => a.port(),
            Self::Domain(_, p) => *p,
        }
    }

    pub async fn connect(&self) -> std::io::Result<TcpStream> {
        match self {
            Self::Ip(a) => TcpStream::connect(a).await,
            Self::Domain(h, p) => TcpStream::connect((h.as_str(), *p)).await,
        }
    }

    pub async fn resolve(&self) -> std::io::Result<SocketAddr> {
        match self {
            Self::Ip(a) => Ok(*a),
            Self::Domain(h, p) => tokio::net::lookup_host(format!("{h}:{p}"))
                .await?
                .next()
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::NotFound, "DNS: не удалось разрешить адрес")
                }),
        }
    }
}

// ── handshake ────────────────────────────────────────────────────────────

pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    config: &Config,
) -> Result<()> {
    let mut hdr = [0u8; 2];
    stream
        .read_exact(&mut hdr)
        .await
        .context("чтение приветствия")?;

    if hdr[0] != VER {
        bail!("неверная версия SOCKS: {:#x}", hdr[0]);
    }

    let nmethods = hdr[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    if config.require_auth() {
        if !methods.contains(&AUTH_USERPASS) {
            stream.write_all(&[VER, AUTH_REJECT]).await?;
            bail!("клиент не поддерживает авторизацию по паролю");
        }
        stream.write_all(&[VER, AUTH_USERPASS]).await?;
        auth_userpass(stream, config).await?;
    } else if methods.contains(&AUTH_NONE) {
        stream.write_all(&[VER, AUTH_NONE]).await?;
    } else {
        stream.write_all(&[VER, AUTH_REJECT]).await?;
        bail!("нет подходящих методов аутентификации");
    }

    Ok(())
}

async fn auth_userpass<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    config: &Config,
) -> Result<()> {
    let ver = stream.read_u8().await?;
    if ver != 0x01 {
        bail!("неверная версия sub-negotiation: {ver}");
    }

    let ulen = stream.read_u8().await? as usize;
    let mut user_buf = vec![0u8; ulen];
    stream.read_exact(&mut user_buf).await?;

    let plen = stream.read_u8().await? as usize;
    let mut pass_buf = vec![0u8; plen];
    stream.read_exact(&mut pass_buf).await?;

    let user = String::from_utf8_lossy(&user_buf);
    let pass = String::from_utf8_lossy(&pass_buf);

    let ok = config
        .users
        .get(user.as_ref())
        .is_some_and(|p| p == pass.as_ref());

    if ok {
        stream.write_all(&[0x01, 0x00]).await?;
        tracing::info!(user = %user, "авторизован");
        Ok(())
    } else {
        stream.write_all(&[0x01, 0x01]).await?;
        bail!("неверные учётные данные: {user}");
    }
}

// ── CONNECT / UDP ASSOCIATE ──────────────────────────────────────────────

pub async fn read_request<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
) -> Result<SocksCommand> {
    let mut hdr = [0u8; 3];
    stream.read_exact(&mut hdr).await?;

    if hdr[0] != VER {
        bail!("неверная версия: {:#x}", hdr[0]);
    }

    let cmd = hdr[1];
    if cmd != CMD_CONNECT && cmd != CMD_UDP_ASSOCIATE {
        send_reply(stream, Reply::CommandNotSupported).await.ok();
        bail!("команда {:#x} не поддерживается", cmd);
    }

    let target = match hdr[2] {
        ATYP_IPV4 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            let port = stream.read_u16().await?;
            TargetAddr::Ip((Ipv4Addr::from(ip), port).into())
        }
        ATYP_DOMAIN => {
            let len = stream.read_u8().await? as usize;
            let mut domain = vec![0u8; len];
            stream.read_exact(&mut domain).await?;
            let port = stream.read_u16().await?;
            TargetAddr::Domain(
                String::from_utf8(domain).context("невалидное доменное имя")?,
                port,
            )
        }
        ATYP_IPV6 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            let port = stream.read_u16().await?;
            TargetAddr::Ip((Ipv6Addr::from(ip), port).into())
        }
        other => {
            send_reply(stream, Reply::AddrTypeNotSupported).await.ok();
            bail!("неподдерживаемый тип адреса: {other:#x}");
        }
    };

    let opts_len = stream.read_u16().await? as usize;
    if opts_len > 0 {
        let mut _opts = vec![0u8; opts_len];
        stream.read_exact(&mut _opts).await?;
    }

    match cmd {
        CMD_CONNECT => Ok(SocksCommand::Connect(target)),
        CMD_UDP_ASSOCIATE => Ok(SocksCommand::UdpAssociate(target)),
        _ => unreachable!(),
    }
}

// ── replies ──────────────────────────────────────────────────────────────

pub async fn send_reply<S: AsyncWrite + Unpin>(stream: &mut S, reply: Reply) -> Result<()> {
    let buf = [VER, reply as u8, ATYP_IPV4, 0, 0, 0, 0, 0, 0, 0, 0];
    stream.write_all(&buf).await?;
    Ok(())
}

pub async fn send_connect_ok<S: AsyncWrite + Unpin>(
    stream: &mut S,
    bind: SocketAddr,
) -> Result<()> {
    let mut buf = Vec::with_capacity(24);
    buf.extend_from_slice(&[VER, Reply::Succeeded as u8]);
    match bind {
        SocketAddr::V4(a) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&a.ip().octets());
            buf.extend_from_slice(&a.port().to_be_bytes());
        }
        SocketAddr::V6(a) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&a.ip().octets());
            buf.extend_from_slice(&a.port().to_be_bytes());
        }
    }
    buf.extend_from_slice(&0u16.to_be_bytes());
    stream.write_all(&buf).await?;
    Ok(())
}

// ── SOCKS5 UDP datagram header (RFC 1928 §7) ────────────────────────────

/// Parse a SOCKS5 UDP datagram header from `buf`.
/// Returns `(frag, target, header_len)`.
pub fn parse_udp_header(buf: &[u8]) -> Result<(u8, TargetAddr, usize)> {
    if buf.len() < 4 {
        bail!("UDP заголовок слишком короткий");
    }
    let frag = buf[2];
    match buf[3] {
        ATYP_IPV4 => {
            if buf.len() < 10 {
                bail!("UDP заголовок слишком короткий для IPv4");
            }
            let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            Ok((frag, TargetAddr::Ip((ip, port).into()), 10))
        }
        ATYP_DOMAIN => {
            if buf.len() < 5 {
                bail!("UDP заголовок слишком короткий для домена");
            }
            let dlen = buf[4] as usize;
            let end = 7 + dlen;
            if buf.len() < end {
                bail!("UDP заголовок слишком короткий для доменного имени");
            }
            let domain = String::from_utf8(buf[5..5 + dlen].to_vec())
                .context("невалидное доменное имя в UDP заголовке")?;
            let port = u16::from_be_bytes([buf[5 + dlen], buf[5 + dlen + 1]]);
            Ok((frag, TargetAddr::Domain(domain, port), end))
        }
        ATYP_IPV6 => {
            if buf.len() < 22 {
                bail!("UDP заголовок слишком короткий для IPv6");
            }
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&buf[4..20]);
            let ip = Ipv6Addr::from(ip_bytes);
            let port = u16::from_be_bytes([buf[20], buf[21]]);
            Ok((frag, TargetAddr::Ip((ip, port).into()), 22))
        }
        other => bail!("неподдерживаемый ATYP в UDP заголовке: {other:#x}"),
    }
}

/// Build a SOCKS6 UDP response header (RSV + FRAG + ATYP + ADDR + PORT).
pub fn build_udp_response_header(frag: u8, src: SocketAddr) -> Vec<u8> {
    let mut buf = Vec::with_capacity(22);
    buf.extend_from_slice(&[0x00, 0x00]);
    buf.push(frag);
    match src {
        SocketAddr::V4(a) => {
            buf.push(0x01);
            buf.extend_from_slice(&a.ip().octets());
            buf.extend_from_slice(&a.port().to_be_bytes());
        }
        SocketAddr::V6(a) => {
            buf.push(0x04);
            buf.extend_from_slice(&a.ip().octets());
            buf.extend_from_slice(&a.port().to_be_bytes());
        }
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn test_config() -> Config {
        Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            users: Arc::new(HashMap::new()),
            sni_spoof: None,
            tls_cert: None,
            tls_key: None,
            tls_flex: false,
            sni_exclude: vec![],
            reality_dest: None,
            reality_secret: None,
            reality_short_ids: vec![],
            reality_server_names: vec![],
            reality_max_time_diff: 3600,
        }
    }

    fn test_config_with_auth(user: &str, pass: &str) -> Config {
        let mut cfg = test_config();
        let mut users = HashMap::new();
        users.insert(user.to_owned(), pass.to_owned());
        cfg.users = Arc::new(users);
        cfg
    }

    // ── Handshake ────────────────────────────────────────────────────

    #[tokio::test]
    async fn handshake_no_auth() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let config = test_config();

        let client_task = tokio::spawn(async move {
            client.write_all(&[0x06, 0x01, 0x00]).await.unwrap();
            let mut choice = [0u8; 2];
            client.read_exact(&mut choice).await.unwrap();
            assert_eq!(choice, [0x06, 0x00]);
        });

        handshake(&mut server, &config).await.unwrap();
        client_task.await.unwrap();
    }

    #[tokio::test]
    async fn handshake_with_auth() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let config = test_config_with_auth("alice", "secret");

        let client_task = tokio::spawn(async move {
            client.write_all(&[0x06, 0x01, 0x02]).await.unwrap();
            let mut choice = [0u8; 2];
            client.read_exact(&mut choice).await.unwrap();
            assert_eq!(choice, [0x06, 0x02]);
            #[rustfmt::skip]
            let msg: &[u8] = &[
                0x01,
                0x05, b'a', b'l', b'i', b'c', b'e',
                0x06, b's', b'e', b'c', b'r', b'e', b't',
            ];
            client.write_all(msg).await.unwrap();
            let mut resp = [0u8; 2];
            client.read_exact(&mut resp).await.unwrap();
            assert_eq!(resp, [0x01, 0x00]);
        });

        handshake(&mut server, &config).await.unwrap();
        client_task.await.unwrap();
    }

    #[tokio::test]
    async fn handshake_rejects_no_suitable_method() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let config = test_config_with_auth("alice", "secret");

        let client_task = tokio::spawn(async move {
            client.write_all(&[0x06, 0x01, 0x00]).await.unwrap();
            let mut choice = [0u8; 2];
            client.read_exact(&mut choice).await.unwrap();
            assert_eq!(choice[1], 0xFF);
        });

        let result = handshake(&mut server, &config).await;
        assert!(result.is_err());
        client_task.await.unwrap();
    }

    // ── Request parsing ──────────────────────────────────────────────

    #[tokio::test]
    async fn request_connect_domain() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        let client_task = tokio::spawn(async move {
            let mut req = vec![0x06, 0x01, 0x03];
            let domain = b"example.com";
            req.push(domain.len() as u8);
            req.extend_from_slice(domain);
            req.extend_from_slice(&80u16.to_be_bytes());
            req.extend_from_slice(&0u16.to_be_bytes());
            client.write_all(&req).await.unwrap();
        });

        let cmd = read_request(&mut server).await.unwrap();
        match cmd {
            SocksCommand::Connect(TargetAddr::Domain(host, port)) => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 80);
            }
            _ => panic!("expected Connect with domain"),
        }
        client_task.await.unwrap();
    }

    #[tokio::test]
    async fn request_connect_ipv4() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        let client_task = tokio::spawn(async move {
            #[rustfmt::skip]
            let req: &[u8] = &[
                0x06, 0x01, 0x01,
                127, 0, 0, 1,
                0x00, 0x50,
                0x00, 0x00,
            ];
            client.write_all(req).await.unwrap();
        });

        let cmd = read_request(&mut server).await.unwrap();
        match cmd {
            SocksCommand::Connect(TargetAddr::Ip(addr)) => {
                assert_eq!(addr.to_string(), "127.0.0.1:80");
            }
            _ => panic!("expected Connect with IPv4"),
        }
        client_task.await.unwrap();
    }

    #[tokio::test]
    async fn request_connect_ipv6() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        let client_task = tokio::spawn(async move {
            let mut req = vec![0x06, 0x01, 0x04];
            req.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
            req.extend_from_slice(&443u16.to_be_bytes());
            req.extend_from_slice(&0u16.to_be_bytes());
            client.write_all(&req).await.unwrap();
        });

        let cmd = read_request(&mut server).await.unwrap();
        match cmd {
            SocksCommand::Connect(TargetAddr::Ip(addr)) => {
                assert_eq!(addr.to_string(), "[::1]:443");
            }
            _ => panic!("expected Connect with IPv6"),
        }
        client_task.await.unwrap();
    }

    #[tokio::test]
    async fn request_udp_associate() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        let client_task = tokio::spawn(async move {
            #[rustfmt::skip]
            let req: &[u8] = &[
                0x06, 0x03, 0x01,
                0, 0, 0, 0,
                0x00, 0x00,
                0x00, 0x00,
            ];
            client.write_all(req).await.unwrap();
        });

        let cmd = read_request(&mut server).await.unwrap();
        assert!(matches!(cmd, SocksCommand::UdpAssociate(_)));
        client_task.await.unwrap();
    }

    #[tokio::test]
    async fn request_with_options() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        let client_task = tokio::spawn(async move {
            let mut req = vec![0x06, 0x01, 0x03];
            let domain = b"test.io";
            req.push(domain.len() as u8);
            req.extend_from_slice(domain);
            req.extend_from_slice(&443u16.to_be_bytes());
            // TLV option: type=0x0001 (Padding), length=4, value=0x00000000
            req.extend_from_slice(&8u16.to_be_bytes()); // OPTLEN=8
            req.extend_from_slice(&1u16.to_be_bytes()); // TYPE
            req.extend_from_slice(&4u16.to_be_bytes()); // LENGTH
            req.extend_from_slice(&[0x00; 4]);          // VALUE
            client.write_all(&req).await.unwrap();
        });

        let cmd = read_request(&mut server).await.unwrap();
        match cmd {
            SocksCommand::Connect(TargetAddr::Domain(host, port)) => {
                assert_eq!(host, "test.io");
                assert_eq!(port, 443);
            }
            _ => panic!("expected Connect with domain"),
        }
        client_task.await.unwrap();
    }

    // ── Reply building ───────────────────────────────────────────────

    #[tokio::test]
    async fn reply_connect_ok_v4() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let bind: SocketAddr = "192.168.1.1:8080".parse().unwrap();

        let server_task = tokio::spawn(async move {
            send_connect_ok(&mut server, bind).await.unwrap();
        });

        // VER(1) + REP(1) + ATYP(1) + IPv4(4) + PORT(2) + OPTLEN(2) = 11
        let mut buf = [0u8; 11];
        client.read_exact(&mut buf).await.unwrap();

        assert_eq!(buf[0], 0x06);
        assert_eq!(buf[1], 0x00);
        assert_eq!(buf[2], 0x01);
        assert_eq!(&buf[3..7], &[192, 168, 1, 1]);
        assert_eq!(&buf[7..9], &8080u16.to_be_bytes());
        assert_eq!(&buf[9..11], &[0, 0]);

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn reply_connect_ok_v6() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let bind: SocketAddr = "[::1]:9090".parse().unwrap();

        let server_task = tokio::spawn(async move {
            send_connect_ok(&mut server, bind).await.unwrap();
        });

        // VER(1) + REP(1) + ATYP(1) + IPv6(16) + PORT(2) + OPTLEN(2) = 23
        let mut buf = [0u8; 23];
        client.read_exact(&mut buf).await.unwrap();

        assert_eq!(buf[0], 0x06);
        assert_eq!(buf[1], 0x00);
        assert_eq!(buf[2], 0x04);
        assert_eq!(&buf[19..21], &9090u16.to_be_bytes());
        assert_eq!(&buf[21..23], &[0, 0]);

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn reply_error() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        let server_task = tokio::spawn(async move {
            send_reply(&mut server, Reply::ConnectionRefused).await.unwrap();
        });

        let mut buf = [0u8; 11];
        client.read_exact(&mut buf).await.unwrap();

        assert_eq!(buf[0], 0x06);
        assert_eq!(buf[1], Reply::ConnectionRefused as u8);
        assert_eq!(buf[2], 0x01);
        assert_eq!(&buf[3..7], &[0, 0, 0, 0]);
        assert_eq!(&buf[7..9], &[0, 0]);
        assert_eq!(&buf[9..11], &[0, 0]);

        server_task.await.unwrap();
    }

    // ── UDP header ───────────────────────────────────────────────────

    #[test]
    fn udp_header_parse_ipv4() {
        let buf = [0x00, 0x00, 0x00, 0x01, 8, 8, 8, 8, 0x00, 0x35, 0xAA, 0xBB];
        let (frag, target, hdr_len) = parse_udp_header(&buf).unwrap();
        assert_eq!(frag, 0);
        assert_eq!(hdr_len, 10);
        assert_eq!(target.to_string(), "8.8.8.8:53");
    }

    #[test]
    fn udp_header_roundtrip_v4() {
        let src: SocketAddr = "1.2.3.4:5678".parse().unwrap();
        let hdr = build_udp_response_header(0, src);
        let (frag, target, len) = parse_udp_header(&hdr).unwrap();
        assert_eq!(frag, 0);
        assert_eq!(len, hdr.len());
        assert_eq!(target.to_string(), "1.2.3.4:5678");
    }

    #[test]
    fn udp_header_roundtrip_v6() {
        let src: SocketAddr = "[::1]:4321".parse().unwrap();
        let hdr = build_udp_response_header(0, src);
        let (frag, target, len) = parse_udp_header(&hdr).unwrap();
        assert_eq!(frag, 0);
        assert_eq!(len, hdr.len());
        assert_eq!(target.to_string(), "[::1]:4321");
    }
}
