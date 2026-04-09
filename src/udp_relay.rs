use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;

const MAX_UDP_SIZE: usize = 65535;

// ── Length-prefixed framing (u16 BE) ─────────────────────────────────────

async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let len = r.read_u16().await.context("UDP frame: чтение длины")? as usize;
    if len == 0 {
        anyhow::bail!("UDP frame: пустой кадр");
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await.context("UDP frame: чтение данных")?;
    Ok(buf)
}

async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, data: &[u8]) -> Result<()> {
    w.write_u16(data.len() as u16).await.context("UDP frame: запись длины")?;
    w.write_all(data).await.context("UDP frame: запись данных")?;
    w.flush().await.context("UDP frame: flush")?;
    Ok(())
}

// ── Server-side tunneled UDP relay ───────────────────────────────────────
//
// After the SOCKS5 UDP ASSOCIATE handshake completes on the TCP/TLS tunnel,
// the tunnel carries length-prefixed SOCKS5 UDP datagrams in both directions.
// The server unpacks the SOCKS5 UDP header, sends raw UDP to the destination,
// and wraps incoming responses back into SOCKS5 UDP format.

pub async fn run_server_tunneled<S>(stream: S, udp: UdpSocket) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (mut tunnel_r, mut tunnel_w) = tokio::io::split(stream);
    let udp = Arc::new(udp);
    let udp2 = udp.clone();

    let outbound = async move {
        loop {
            let frame = read_frame(&mut tunnel_r).await?;
            if frame.len() < 4 {
                continue;
            }
            let (frag, target, hdr_len) = crate::socks6::parse_udp_header(&frame)?;
            if frag != 0 {
                continue;
            }
            let payload = &frame[hdr_len..];
            if payload.is_empty() {
                continue;
            }
            let dest = target.resolve().await?;
            udp.send_to(payload, dest).await?;
        }
        #[allow(unreachable_code)]
        Ok::<_, anyhow::Error>(())
    };

    let inbound = async move {
        let mut buf = vec![0u8; MAX_UDP_SIZE];
        loop {
            let (n, src) = udp2.recv_from(&mut buf).await?;
            let hdr = crate::socks6::build_udp_response_header(0, src);
            let mut frame = Vec::with_capacity(hdr.len() + n);
            frame.extend_from_slice(&hdr);
            frame.extend_from_slice(&buf[..n]);
            write_frame(&mut tunnel_w, &frame).await?;
        }
        #[allow(unreachable_code)]
        Ok::<_, anyhow::Error>(())
    };

    tokio::select! {
        r = outbound => {
            if let Err(e) = r { tracing::debug!("UDP server outbound: {e:#}"); }
        }
        r = inbound => {
            if let Err(e) = r { tracing::debug!("UDP server inbound: {e:#}"); }
        }
    }

    Ok(())
}

// ── Client-side tunneled UDP relay ───────────────────────────────────────
//
// The client binds a local UDP socket for the local app (browser, etc.).
// SOCKS5 UDP datagrams from the app are forwarded through the TLS tunnel
// using length-prefixed framing. Responses from the tunnel are sent back
// to the app via the local UDP socket.
//
// `control_tcp` is the original SOCKS5 TCP connection from the local app;
// when it closes the UDP association must be torn down (RFC 1928).

pub async fn run_client_tunneled<S>(
    stream: S,
    local_udp: UdpSocket,
    mut control_tcp: TcpStream,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (mut tunnel_r, mut tunnel_w) = tokio::io::split(stream);
    let local_udp = Arc::new(local_udp);
    let local_udp2 = local_udp.clone();
    let client_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let client_addr2 = client_addr.clone();

    let outbound = async move {
        let mut buf = vec![0u8; MAX_UDP_SIZE];
        loop {
            let (n, src) = local_udp.recv_from(&mut buf).await?;
            {
                let mut addr = client_addr.lock().await;
                if addr.is_none() {
                    *addr = Some(src);
                }
            }
            write_frame(&mut tunnel_w, &buf[..n]).await?;
        }
        #[allow(unreachable_code)]
        Ok::<_, anyhow::Error>(())
    };

    let inbound = async move {
        loop {
            let frame = read_frame(&mut tunnel_r).await?;
            let addr = {
                let a = client_addr2.lock().await;
                match *a {
                    Some(addr) => addr,
                    None => continue,
                }
            };
            local_udp2.send_to(&frame, addr).await?;
        }
        #[allow(unreachable_code)]
        Ok::<_, anyhow::Error>(())
    };

    let tcp_closed = async move {
        let mut buf = [0u8; 1];
        loop {
            match control_tcp.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                _ => {}
            }
        }
    };

    tokio::select! {
        r = outbound => {
            if let Err(e) = r { tracing::debug!("UDP client outbound: {e:#}"); }
        }
        r = inbound => {
            if let Err(e) = r { tracing::debug!("UDP client inbound: {e:#}"); }
        }
        _ = tcp_closed => {
            tracing::debug!("UDP: контрольное TCP-соединение закрыто");
        }
    }

    Ok(())
}
