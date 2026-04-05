use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Nonce,
};
use anyhow::{bail, Context, Result};
use hkdf::Hkdf;
use sha2::Sha256;
use std::io;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

// ── ClientHello deep parser ─────────────────────────────────────────────

pub struct ClientHelloFields {
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub session_id_offset: usize,
    pub sni: Option<String>,
}

/// Parse a raw TLS record containing a ClientHello.
/// Layout: record_hdr(5) + hs_type(1) + hs_len(3) + version(2) + random(32) + sid_len(1) …
pub fn parse_client_hello(buf: &[u8]) -> Option<ClientHelloFields> {
    if buf.len() < 44 || buf[0] != 0x16 || buf[5] != 0x01 {
        return None;
    }

    let mut random = [0u8; 32];
    random.copy_from_slice(&buf[11..43]);

    let sid_len = buf[43] as usize;
    if buf.len() < 44 + sid_len {
        return None;
    }
    let session_id_offset = 44;
    let session_id = buf[session_id_offset..session_id_offset + sid_len].to_vec();

    let mut pos = 44 + sid_len;

    if pos + 2 > buf.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2 + cs_len;

    if pos >= buf.len() {
        return None;
    }
    let comp_len = buf[pos] as usize;
    pos += 1 + comp_len;

    let sni = if pos + 2 <= buf.len() {
        let ext_all_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
        pos += 2;
        let ext_end = pos + ext_all_len;

        let mut found_sni = None;
        while pos + 4 <= ext_end && pos + 4 <= buf.len() {
            let ext_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            let ext_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
            let ext_data = pos + 4;

            if ext_type == 0x0000 && ext_len >= 5 && ext_data + 5 <= buf.len() {
                if buf[ext_data + 2] == 0x00 {
                    let name_len =
                        u16::from_be_bytes([buf[ext_data + 3], buf[ext_data + 4]]) as usize;
                    let name_start = ext_data + 5;
                    if name_start + name_len <= buf.len() {
                        found_sni = Some(
                            String::from_utf8_lossy(&buf[name_start..name_start + name_len])
                                .into_owned(),
                        );
                    }
                }
            }

            pos = ext_data + ext_len;
        }
        found_sni
    } else {
        None
    };

    Some(ClientHelloFields {
        random,
        session_id,
        session_id_offset,
        sni,
    })
}

// ── Reality crypto ──────────────────────────────────────────────────────

fn derive_auth_key(secret: &[u8; 32], random: &[u8; 32]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(&random[..20]), secret);
    let mut auth_key = [0u8; 32];
    hk.expand(b"REALITY", &mut auth_key)
        .map_err(|e| anyhow::anyhow!("HKDF expand: {e}"))?;
    Ok(auth_key)
}

/// Encrypt `[short_id(8) | timestamp_u32_be(4) | zeros(4)]` into a 32-byte
/// session_id (16 bytes ciphertext + 16 bytes GCM tag).
pub fn seal_session_id(
    random: &[u8; 32],
    secret: &[u8; 32],
    short_id: &[u8; 8],
) -> Result<[u8; 32]> {
    let auth_key = derive_auth_key(secret, random)?;
    let cipher =
        Aes128Gcm::new_from_slice(&auth_key[..16]).map_err(|e| anyhow::anyhow!("AES init: {e}"))?;
    let nonce = Nonce::from_slice(&random[20..32]);

    let mut plaintext = [0u8; 16];
    plaintext[..8].copy_from_slice(short_id);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    plaintext[8..12].copy_from_slice(&ts.to_be_bytes());

    let ct = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|_| anyhow::anyhow!("AES-GCM encrypt"))?;
    if ct.len() != 32 {
        bail!("unexpected ciphertext length {}", ct.len());
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&ct);
    Ok(out)
}

/// Decrypt session_id and verify short_id + timestamp.
/// Returns `Some(short_id)` on success.
pub fn verify_session_id(
    session_id: &[u8],
    random: &[u8; 32],
    secret: &[u8; 32],
    allowed_short_ids: &[[u8; 8]],
    max_time_diff: u64,
) -> Option<[u8; 8]> {
    if session_id.len() != 32 {
        return None;
    }

    let auth_key = derive_auth_key(secret, random).ok()?;
    let cipher = Aes128Gcm::new_from_slice(&auth_key[..16]).ok()?;
    let nonce = Nonce::from_slice(&random[20..32]);

    let pt = cipher.decrypt(nonce, session_id).ok()?;
    if pt.len() != 16 {
        return None;
    }

    let mut short_id = [0u8; 8];
    short_id.copy_from_slice(&pt[..8]);

    if !allowed_short_ids.contains(&short_id) {
        return None;
    }

    let ts = u32::from_be_bytes([pt[8], pt[9], pt[10], pt[11]]);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;

    let diff = now.abs_diff(ts) as u64;
    if diff > max_time_diff {
        return None;
    }

    Some(short_id)
}

// ── In-tunnel auth (Phase 1) ────────────────────────────────────────────
//
// After the TLS handshake completes, the client sends a 28-byte auth frame
// as the first message inside the tunnel. The server verifies it before
// proceeding with SOCKS6. This avoids modifying the ClientHello (which
// would break the TLS 1.3 transcript hash).
//
// Frame layout: short_id(8) | timestamp_be32(4) | tag(16) = 28 bytes
// Tag = HKDF-SHA256(ikm=secret, salt=short_id||timestamp, info="REALITY-AUTH")[:16]

pub const TUNNEL_AUTH_LEN: usize = 28;
const TUNNEL_AUTH_OK: [u8; 2] = [0x00, 0x52]; // "R"

fn compute_auth_tag(secret: &[u8; 32], short_id: &[u8; 8], ts_bytes: &[u8; 4]) -> [u8; 16] {
    let mut salt = [0u8; 12];
    salt[..8].copy_from_slice(short_id);
    salt[8..12].copy_from_slice(ts_bytes);

    let hk = Hkdf::<Sha256>::new(Some(&salt), secret);
    let mut tag = [0u8; 16];
    hk.expand(b"REALITY-AUTH", &mut tag).unwrap();
    tag
}

pub fn build_tunnel_auth(secret: &[u8; 32], short_id: &[u8; 8]) -> [u8; TUNNEL_AUTH_LEN] {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    let ts_bytes = ts.to_be_bytes();
    let tag = compute_auth_tag(secret, short_id, &ts_bytes);

    let mut frame = [0u8; TUNNEL_AUTH_LEN];
    frame[..8].copy_from_slice(short_id);
    frame[8..12].copy_from_slice(&ts_bytes);
    frame[12..28].copy_from_slice(&tag);
    frame
}

pub fn verify_tunnel_auth(
    frame: &[u8; TUNNEL_AUTH_LEN],
    secret: &[u8; 32],
    allowed_short_ids: &[[u8; 8]],
    max_time_diff: u64,
) -> Option<[u8; 8]> {
    let mut short_id = [0u8; 8];
    short_id.copy_from_slice(&frame[..8]);

    if !allowed_short_ids.contains(&short_id) {
        return None;
    }

    let ts = u32::from_be_bytes([frame[8], frame[9], frame[10], frame[11]]);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    if now.abs_diff(ts) as u64 > max_time_diff {
        return None;
    }

    let ts_bytes: [u8; 4] = [frame[8], frame[9], frame[10], frame[11]];
    let expected = compute_auth_tag(secret, &short_id, &ts_bytes);

    if frame[12..28] != expected {
        return None;
    }

    Some(short_id)
}

/// Send the auth frame + read the 2-byte ACK inside a TLS tunnel.
pub async fn send_tunnel_auth<S: AsyncWrite + AsyncRead + Unpin>(
    stream: &mut S,
    secret: &[u8; 32],
    short_id: &[u8; 8],
) -> Result<()> {
    let frame = build_tunnel_auth(secret, short_id);
    stream.write_all(&frame).await.context("send auth frame")?;
    let mut ack = [0u8; 2];
    stream.read_exact(&mut ack).await.context("read auth ACK")?;
    if ack != TUNNEL_AUTH_OK {
        bail!("Reality: сервер отклонил аутентификацию");
    }
    Ok(())
}

/// Read the auth frame from a TLS tunnel and verify it.
/// Sends back the 2-byte ACK on success.
pub async fn recv_and_verify_tunnel_auth<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    secret: &[u8; 32],
    allowed_short_ids: &[[u8; 8]],
    max_time_diff: u64,
) -> Result<[u8; 8]> {
    let mut frame = [0u8; TUNNEL_AUTH_LEN];
    stream
        .read_exact(&mut frame)
        .await
        .context("read auth frame")?;
    match verify_tunnel_auth(&frame, secret, allowed_short_ids, max_time_diff) {
        Some(short_id) => {
            stream.write_all(&TUNNEL_AUTH_OK).await?;
            Ok(short_id)
        }
        None => {
            bail!("Reality: невалидная аутентификация");
        }
    }
}

// ── Read a full TLS record ──────────────────────────────────────────────

pub async fn read_tls_record(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut hdr = [0u8; 5];
    stream
        .read_exact(&mut hdr)
        .await
        .context("чтение TLS record header")?;

    let record_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    if record_len > 16640 {
        bail!("TLS record слишком большой: {record_len}");
    }

    let mut buf = Vec::with_capacity(5 + record_len);
    buf.extend_from_slice(&hdr);
    buf.resize(5 + record_len, 0);
    stream
        .read_exact(&mut buf[5..])
        .await
        .context("чтение TLS record body")?;

    Ok(buf)
}

// ── ReplayStream (server-side) ──────────────────────────────────────────

/// Feeds buffered bytes first (the already-read ClientHello), then reads
/// from the underlying TCP stream. Writes go straight to TCP.
pub struct ReplayStream {
    prefix: Vec<u8>,
    prefix_pos: usize,
    inner: TcpStream,
}

impl ReplayStream {
    pub fn new(prefix: Vec<u8>, inner: TcpStream) -> Self {
        Self {
            prefix,
            prefix_pos: 0,
            inner,
        }
    }
}

impl AsyncRead for ReplayStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.prefix_pos < this.prefix.len() {
            let remaining = &this.prefix[this.prefix_pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            this.prefix_pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ReplayStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// ── Fallback relay ──────────────────────────────────────────────────────

/// Relay a non-authenticated connection to the cover server.
pub async fn fallback_relay(mut client: TcpStream, buffered: Vec<u8>, dest: &str) -> Result<()> {
    let mut remote = TcpStream::connect(dest)
        .await
        .with_context(|| format!("fallback: подключение к {dest}"))?;
    remote.set_nodelay(true).ok();

    remote.write_all(&buffered).await?;
    tokio::io::copy_bidirectional(&mut client, &mut remote).await?;
    Ok(())
}

// ── Key generation ──────────────────────────────────────────────────────

pub fn generate_keys() {
    use rand::RngCore;

    let mut secret = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret);

    let mut short_id = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut short_id);

    let secret_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, secret);
    let short_id_hex = hex_encode(&short_id);

    println!("Reality secret (--reality-secret / --secret):");
    println!("  {secret_b64}");
    println!();
    println!("Short ID (--reality-short-id / --short-id):");
    println!("  {short_id_hex}");
}

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        bail!("hex нечётной длины");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .with_context(|| format!("невалидный hex: {}", &s[i..i + 2]))
        })
        .collect()
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ch(random: &[u8; 32], session_id: &[u8; 32], sni: &str) -> Vec<u8> {
        let sni_bytes = sni.as_bytes();
        let sni_ext_data_len = 2 + 1 + 2 + sni_bytes.len();
        let extensions_len = 4 + sni_ext_data_len;
        let cipher_suites: &[u8] = &[0x13, 0x01];
        let compression: &[u8] = &[0x00];

        let body_len =
            2 + 32 + 1 + 32 + 2 + cipher_suites.len() + 1 + compression.len() + 2 + extensions_len;
        let record_len = 4 + body_len;

        let mut buf = Vec::new();
        buf.push(0x16);
        buf.extend_from_slice(&[0x03, 0x01]);
        buf.extend_from_slice(&(record_len as u16).to_be_bytes());
        buf.push(0x01);
        let hs = body_len as u32;
        buf.push(((hs >> 16) & 0xff) as u8);
        buf.push(((hs >> 8) & 0xff) as u8);
        buf.push((hs & 0xff) as u8);
        buf.extend_from_slice(&[0x03, 0x03]);
        buf.extend_from_slice(random);
        buf.push(32);
        buf.extend_from_slice(session_id);
        buf.extend_from_slice(&(cipher_suites.len() as u16).to_be_bytes());
        buf.extend_from_slice(cipher_suites);
        buf.push(compression.len() as u8);
        buf.extend_from_slice(compression);
        buf.extend_from_slice(&(extensions_len as u16).to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x00]);
        buf.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
        let list_len = 1 + 2 + sni_bytes.len();
        buf.extend_from_slice(&(list_len as u16).to_be_bytes());
        buf.push(0x00);
        buf.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(sni_bytes);
        buf
    }

    #[test]
    fn parse_client_hello_fields() {
        let random = [0xAA; 32];
        let sid = [0xBB; 32];
        let buf = make_ch(&random, &sid, "www.google.com");
        let f = parse_client_hello(&buf).unwrap();
        assert_eq!(f.random, random);
        assert_eq!(f.session_id.as_slice(), &sid);
        assert_eq!(f.sni.as_deref(), Some("www.google.com"));
        assert_eq!(f.session_id_offset, 44);
    }

    #[test]
    fn seal_and_verify_roundtrip() {
        let random = [0xAA; 32];
        let secret = [0x42; 32];
        let short_id = *b"\x01\x02\x03\x04\x05\x06\x07\x08";

        let sealed = seal_session_id(&random, &secret, &short_id).unwrap();
        assert_eq!(sealed.len(), 32);

        let got = verify_session_id(&sealed, &random, &secret, &[short_id], 60);
        assert_eq!(got, Some(short_id));
    }

    #[test]
    fn verify_rejects_wrong_secret() {
        let random = [0xAA; 32];
        let sealed = seal_session_id(&random, &[0x42; 32], b"\x01\x02\x03\x04\x05\x06\x07\x08").unwrap();
        let got = verify_session_id(&sealed, &random, &[0x43; 32], &[[0x01; 8]], 60);
        assert!(got.is_none());
    }

    #[test]
    fn verify_rejects_wrong_short_id() {
        let random = [0xAA; 32];
        let secret = [0x42; 32];
        let sealed = seal_session_id(&random, &secret, b"\x01\x02\x03\x04\x05\x06\x07\x08").unwrap();
        let got = verify_session_id(&sealed, &random, &secret, &[[0xFF; 8]], 60);
        assert!(got.is_none());
    }

    #[test]
    fn tunnel_auth_roundtrip() {
        let secret = [0xEE; 32];
        let short_id = [0xFF; 8];

        let frame = build_tunnel_auth(&secret, &short_id);
        assert_eq!(frame.len(), TUNNEL_AUTH_LEN);

        let got = verify_tunnel_auth(&frame, &secret, &[short_id], 60);
        assert_eq!(got, Some(short_id));
    }

    #[test]
    fn tunnel_auth_rejects_wrong_secret() {
        let frame = build_tunnel_auth(&[0xEE; 32], &[0xFF; 8]);
        assert!(verify_tunnel_auth(&frame, &[0xAA; 32], &[[0xFF; 8]], 60).is_none());
    }

    #[test]
    fn tunnel_auth_rejects_wrong_short_id() {
        let frame = build_tunnel_auth(&[0xEE; 32], &[0xFF; 8]);
        assert!(verify_tunnel_auth(&frame, &[0xEE; 32], &[[0x00; 8]], 60).is_none());
    }

    #[test]
    fn hex_roundtrip() {
        let data = [0xab, 0xcd, 0x12, 0x34];
        assert_eq!(hex_encode(&data), "abcd1234");
        assert_eq!(hex_decode("abcd1234").unwrap(), data);
    }
}
