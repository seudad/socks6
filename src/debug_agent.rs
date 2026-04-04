//! NDJSON debug log. Путь: переменная `SOCKS5_DEBUG_LOG` или путь по умолчанию в workspace.
use std::io::Write;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

pub const SESSION_ID: &str = "494c8d";
const DEFAULT_PATH: &str = "/Users/seeu/rust/socks5/.cursor/debug-494c8d.log";

fn log_path() -> String {
    std::env::var("SOCKS5_DEBUG_LOG").unwrap_or_else(|_| DEFAULT_PATH.to_string())
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

pub(crate) fn ej(s: &str) -> String {
    esc(s)
}

/// `data_extra` — дополнительные поля JSON через запятую (уже экранированные строки или числа).
pub fn emit(
    hypothesis_id: &str,
    location: &'static str,
    message: &str,
    run_id: &str,
    peer: SocketAddr,
    data_extra: &str,
) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let inner = if data_extra.is_empty() {
        format!(r#""peer":"{}""#, esc(&peer.to_string()))
    } else {
        format!(
            r#""peer":"{}",{}"#,
            esc(&peer.to_string()),
            data_extra
        )
    };
    let line = format!(
        "{{\"sessionId\":\"{sess}\",\"hypothesisId\":\"{hid}\",\"location\":\"{loc}\",\"message\":\"{msg}\",\"data\":{{{inner}}},\"timestamp\":{ts},\"runId\":\"{run}\"}}\n",
        sess = SESSION_ID,
        hid = hypothesis_id,
        loc = location,
        msg = esc(message),
        inner = inner,
        ts = ts,
        run = run_id,
    );
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path())
    {
        let _ = f.write_all(line.as_bytes());
    }
}
