use anyhow::Result;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn relay<C>(
    client: &mut C,
    remote: &mut TcpStream,
    sni_spoof: Option<&str>,
) -> Result<(u64, u64)>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let mut extra_up = 0u64;

    if let Some(fake_sni) = sni_spoof {
        extra_up = intercept_tls(client, remote, fake_sni).await?;
    }

    let (up, down) = tokio::io::copy_bidirectional(client, remote).await?;
    Ok((up + extra_up, down))
}

async fn intercept_tls<C: AsyncRead + Unpin>(
    client: &mut C,
    remote: &mut TcpStream,
    fake_sni: &str,
) -> Result<u64> {
    let mut header = [0u8; 5];
    client.read_exact(&mut header).await?;

    if header[0] != 0x16 {
        remote.write_all(&header).await?;
        return Ok(5);
    }

    let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let total = 5 + record_len;

    let mut buf = Vec::with_capacity(total);
    buf.extend_from_slice(&header);
    buf.resize(total, 0);
    client.read_exact(&mut buf[5..]).await?;

    let client_bytes = total as u64;

    if let Some(original) = crate::sni::replace_sni(&mut buf, fake_sni) {
        tracing::info!(original = %original, spoofed = %fake_sni, "SNI подменён");
    }

    remote.write_all(&buf).await?;
    Ok(client_bytes)
}
