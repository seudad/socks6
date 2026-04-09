use crate::config::Config;
use anyhow::{bail, Context, Result};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

const VER: u8 = 0x05;
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
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await?;

    if hdr[0] != VER {
        bail!("неверная версия: {:#x}", hdr[0]);
    }

    let cmd = hdr[1];
    if cmd != CMD_CONNECT && cmd != CMD_UDP_ASSOCIATE {
        send_reply(stream, Reply::CommandNotSupported).await.ok();
        bail!("команда {:#x} не поддерживается", cmd);
    }

    let target = match hdr[3] {
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

    match cmd {
        CMD_CONNECT => Ok(SocksCommand::Connect(target)),
        CMD_UDP_ASSOCIATE => Ok(SocksCommand::UdpAssociate(target)),
        _ => unreachable!(),
    }
}

// ── replies ──────────────────────────────────────────────────────────────

pub async fn send_reply<S: AsyncWrite + Unpin>(stream: &mut S, reply: Reply) -> Result<()> {
    let buf = [VER, reply as u8, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0];
    stream.write_all(&buf).await?;
    Ok(())
}

pub async fn send_connect_ok<S: AsyncWrite + Unpin>(
    stream: &mut S,
    bind: SocketAddr,
) -> Result<()> {
    let mut buf = Vec::with_capacity(22);
    buf.extend_from_slice(&[VER, Reply::Succeeded as u8, 0x00]);
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

/// Build a SOCKS5 UDP response header (RSV + FRAG + ATYP + ADDR + PORT).
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
