/// Replaces the SNI hostname inside a TLS ClientHello record.
/// Returns the original hostname on success, `None` if the buffer
/// is not a valid ClientHello or contains no SNI extension.
pub fn replace_sni(buf: &mut Vec<u8>, new_sni: &str) -> Option<String> {
    // record(5) + hs_header(4) + version(2) + random(32) + sid_len(1) = 44
    if buf.len() < 44 || buf[0] != 0x16 || buf[5] != 0x01 {
        return None;
    }

    let new_sni = new_sni.as_bytes();
    let mut pos = 43;

    pos = skip_u8_len(buf, pos)?;  // Session ID
    pos = skip_u16_len(buf, pos)?; // Cipher Suites
    pos = skip_u8_len(buf, pos)?;  // Compression Methods

    if pos + 2 > buf.len() {
        return None;
    }
    let ext_all_pos = pos;
    let ext_all_len = get_u16(buf, pos) as usize;
    pos += 2;

    let ext_end = pos + ext_all_len;
    if ext_end > buf.len() {
        return None;
    }

    while pos + 4 <= ext_end {
        let ext_type = get_u16(buf, pos);
        let ext_len_pos = pos + 2;
        let ext_len = get_u16(buf, ext_len_pos) as usize;
        let ext_data = pos + 4;

        if ext_type == 0x0000 && ext_len >= 5 && ext_data + 5 <= buf.len() {
            let list_len_pos = ext_data;
            if buf[ext_data + 2] != 0x00 {
                pos = ext_data + ext_len;
                continue;
            }

            let name_len_pos = ext_data + 3;
            let name_len = get_u16(buf, name_len_pos) as usize;
            let name_pos = ext_data + 5;

            if name_pos + name_len > buf.len() {
                return None;
            }

            let original =
                String::from_utf8_lossy(&buf[name_pos..name_pos + name_len]).into_owned();
            let delta = new_sni.len() as isize - name_len as isize;

            let tail = buf[name_pos + name_len..].to_vec();
            buf.truncate(name_pos);
            buf.extend_from_slice(new_sni);
            buf.extend_from_slice(&tail);

            set_u16(buf, name_len_pos, new_sni.len() as u16);
            adjust_u16(buf, list_len_pos, delta);
            adjust_u16(buf, ext_len_pos, delta);
            adjust_u16(buf, ext_all_pos, delta);
            adjust_u24(buf, 6, delta); // handshake length
            adjust_u16(buf, 3, delta); // record length

            return Some(original);
        }

        pos = ext_data + ext_len;
    }

    None
}

// ── helpers ──────────────────────────────────────────────────────────────

fn get_u16(b: &[u8], p: usize) -> u16 {
    u16::from_be_bytes([b[p], b[p + 1]])
}

fn set_u16(b: &mut [u8], p: usize, v: u16) {
    let bytes = v.to_be_bytes();
    b[p] = bytes[0];
    b[p + 1] = bytes[1];
}

fn adjust_u16(b: &mut [u8], p: usize, delta: isize) {
    let old = get_u16(b, p) as isize;
    set_u16(b, p, (old + delta) as u16);
}

fn adjust_u24(b: &mut [u8], p: usize, delta: isize) {
    let old = u32::from_be_bytes([0, b[p], b[p + 1], b[p + 2]]) as isize;
    let val = (old + delta) as u32;
    b[p] = ((val >> 16) & 0xff) as u8;
    b[p + 1] = ((val >> 8) & 0xff) as u8;
    b[p + 2] = (val & 0xff) as u8;
}

fn skip_u8_len(buf: &[u8], pos: usize) -> Option<usize> {
    if pos >= buf.len() {
        return None;
    }
    Some(pos + 1 + buf[pos] as usize)
}

fn skip_u16_len(buf: &[u8], pos: usize) -> Option<usize> {
    if pos + 2 > buf.len() {
        return None;
    }
    Some(pos + 2 + get_u16(buf, pos) as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_client_hello(sni: &str) -> Vec<u8> {
        let sni_bytes = sni.as_bytes();
        let sni_ext_data_len = 2 + 1 + 2 + sni_bytes.len(); // list_len + type + name_len + name
        let sni_ext_len = 4 + sni_ext_data_len; // ext_type(2) + ext_data_len(2) + data
        let extensions_len = sni_ext_len;

        let session_id: &[u8] = &[];
        let cipher_suites: &[u8] = &[0x13, 0x01]; // TLS_AES_128_GCM_SHA256
        let compression: &[u8] = &[0x00];

        let body_len = 2 + 32 + 1 + session_id.len() + 2 + cipher_suites.len() + 1
            + compression.len()
            + 2
            + extensions_len;

        let record_len = 4 + body_len; // hs_type(1) + hs_len(3) + body

        let mut buf = Vec::new();
        // TLS record header
        buf.push(0x16);
        buf.extend_from_slice(&[0x03, 0x01]);
        buf.extend_from_slice(&(record_len as u16).to_be_bytes());
        // Handshake header
        buf.push(0x01);
        let hs_len = body_len as u32;
        buf.push(((hs_len >> 16) & 0xff) as u8);
        buf.push(((hs_len >> 8) & 0xff) as u8);
        buf.push((hs_len & 0xff) as u8);
        // ClientHello body
        buf.extend_from_slice(&[0x03, 0x03]); // version TLS 1.2
        buf.extend_from_slice(&[0xAA; 32]); // random
        buf.push(session_id.len() as u8);
        buf.extend_from_slice(session_id);
        buf.extend_from_slice(&(cipher_suites.len() as u16).to_be_bytes());
        buf.extend_from_slice(cipher_suites);
        buf.push(compression.len() as u8);
        buf.extend_from_slice(compression);
        // Extensions
        buf.extend_from_slice(&(extensions_len as u16).to_be_bytes());
        // SNI extension
        buf.extend_from_slice(&[0x00, 0x00]); // type
        buf.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
        let list_len = 1 + 2 + sni_bytes.len();
        buf.extend_from_slice(&(list_len as u16).to_be_bytes());
        buf.push(0x00); // host_name
        buf.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(sni_bytes);

        buf
    }

    #[test]
    fn replace_sni_works() {
        let mut buf = make_client_hello("example.com");
        let original = replace_sni(&mut buf, "google.com").unwrap();
        assert_eq!(original, "example.com");

        let mut check = buf.clone();
        let round = replace_sni(&mut check, "example.com").unwrap();
        assert_eq!(round, "google.com");
    }

    #[test]
    fn replace_sni_longer_name() {
        let mut buf = make_client_hello("a.io");
        let original = replace_sni(&mut buf, "very-long-domain.example.com").unwrap();
        assert_eq!(original, "a.io");

        let mut check = buf.clone();
        let round = replace_sni(&mut check, "a.io").unwrap();
        assert_eq!(round, "very-long-domain.example.com");
    }

    #[test]
    fn not_tls_returns_none() {
        let mut buf = vec![0x15, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00];
        buf.resize(60, 0);
        assert!(replace_sni(&mut buf, "fake.com").is_none());
    }
}
