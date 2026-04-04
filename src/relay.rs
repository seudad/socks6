use anyhow::Result;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn relay<C>(
    client: &mut C,
    remote: &mut TcpStream,
    sni_spoof: Option<&str>,
    dbg_peer: SocketAddr,
    dbg_target: &str,
) -> Result<(u64, u64)>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let mut extra_up = 0u64;

    if let Some(fake_sni) = sni_spoof {
        // #region agent log
        extra_up = intercept_tls(client, remote, fake_sni, dbg_peer, dbg_target).await?;
        // #endregion agent log
    }

    let (up, down) = tokio::io::copy_bidirectional(client, remote).await?;
    // #region agent log
    crate::debug_agent::emit(
        "H4-H5",
        "relay.rs:relay",
        "copy_bidirectional_done",
        "icloud-repro",
        dbg_peer,
        &format!(
            r#""target":"{}","up":{},"down":{},"extra_up":{}"#,
            crate::debug_agent::ej(dbg_target),
            up + extra_up,
            down,
            extra_up
        ),
    );
    // #endregion agent log
    Ok((up + extra_up, down))
}

async fn intercept_tls<C: AsyncRead + Unpin>(
    client: &mut C,
    remote: &mut TcpStream,
    fake_sni: &str,
    dbg_peer: SocketAddr,
    dbg_target: &str,
) -> Result<u64> {
    let mut header = [0u8; 5];
    client.read_exact(&mut header).await?;
    // #region agent log
    let rec_len_dbg = if header[0] == 0x16 {
        u16::from_be_bytes([header[3], header[4]]) as u32
    } else {
        0
    };
    crate::debug_agent::emit(
        "H3",
        "relay.rs:intercept_tls",
        "first_client_tls_record",
        "icloud-repro",
        dbg_peer,
        &format!(
            r#""target":"{}","first_byte":{},"record_payload_len":{}"#,
            crate::debug_agent::ej(dbg_target),
            header[0],
            rec_len_dbg
        ),
    );
    // #endregion agent log

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

    // #region agent log
    match crate::sni::replace_sni(&mut buf, fake_sni) {
        Some(original) => {
            tracing::info!(original = %original, spoofed = %fake_sni, "SNI подменён");
            crate::debug_agent::emit(
                "H1",
                "relay.rs:intercept_tls",
                "sni_replaced",
                "icloud-repro",
                dbg_peer,
                &format!(
                    r#""target":"{}","original_sni":"{}","fake_sni":"{}","clienthello_bytes":{}"#,
                    crate::debug_agent::ej(dbg_target),
                    crate::debug_agent::ej(&original),
                    crate::debug_agent::ej(fake_sni),
                    buf.len()
                ),
            );
        }
        None => {
            crate::debug_agent::emit(
                "H3",
                "relay.rs:intercept_tls",
                "sni_replace_skipped",
                "icloud-repro",
                dbg_peer,
                &format!(
                    r#""target":"{}","fake_sni":"{}","clienthello_bytes":{},"note":"no_sni_ext_or_parse_fail""#,
                    crate::debug_agent::ej(dbg_target),
                    crate::debug_agent::ej(fake_sni),
                    buf.len()
                ),
            );
        }
    }
    // #endregion agent log

    remote.write_all(&buf).await?;
    Ok(client_bytes)
}
