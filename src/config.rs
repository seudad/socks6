use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Clone)]
pub struct Config {
    pub listen: SocketAddr,
    pub users: Arc<HashMap<String, String>>,
    pub sni_spoof: Option<Arc<str>>,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    /// Разрешить на том же порту и plaintext SOCKS6 (первый байт 0x05), и TLS (0x16).
    pub tls_flex: bool,
    /// Суффиксы домена (например `apple.com`): для `host` на :443 не подменять SNI.
    pub sni_exclude: Vec<String>,
    // ── Reality ──────────────────────────────────────────────────────
    /// Cover server (e.g. `www.google.com:443`).
    pub reality_dest: Option<String>,
    /// 32-byte shared secret.
    pub reality_secret: Option<[u8; 32]>,
    /// Allowed short IDs (at least one required when Reality is active).
    pub reality_short_ids: Vec<[u8; 8]>,
    /// Allowed SNI values from clients.
    pub reality_server_names: Vec<String>,
    /// Max |client−server| time for tunnel auth frame (default 3600 s).
    pub reality_max_time_diff: u64,
}

impl Config {
    /// Суффикс в нижнем регистре, без ведущих `*` / `.`; пустое — ошибка.
    fn normalize_sni_exclude_suffix(token: &str) -> Result<String> {
        let v = token.trim().to_ascii_lowercase();
        if v.is_empty() {
            bail!("пустой суффикс SNI-exclude");
        }
        let v = v.trim_start_matches('*').trim_start_matches('.');
        if v.is_empty() {
            bail!("невалидный суффикс SNI-exclude");
        }
        Ok(v.to_string())
    }

    pub fn from_args() -> Result<Self> {
        let args: Vec<String> = std::env::args().skip(1).collect();

        // ── --reality-generate-keys ────────────────────────────────
        if args.iter().any(|a| a == "--reality-generate-keys") {
            crate::reality::generate_keys();
            std::process::exit(0);
        }

        let mut listen: Option<SocketAddr> = None;
        let mut users = HashMap::new();
        let mut sni_spoof: Option<String> = None;
        let mut tls_cert: Option<String> = None;
        let mut tls_key: Option<String> = None;
        let mut tls_flex = false;
        let mut sni_exclude: Vec<String> = Vec::new();
        let mut reality_dest: Option<String> = None;
        let mut reality_secret: Option<[u8; 32]> = None;
        let mut reality_short_ids: Vec<[u8; 8]> = Vec::new();
        let mut reality_server_names: Vec<String> = Vec::new();
        let mut reality_max_time_diff: u64 = 3600;

        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--auth" => {
                    i += 1;
                    let pair = args.get(i).context("--auth требует значения user:pass")?;
                    let (u, p) = pair
                        .split_once(':')
                        .context("формат --auth: user:pass")?;
                    users.insert(u.to_owned(), p.to_owned());
                }
                "--auth-file" => {
                    i += 1;
                    let path = args
                        .get(i)
                        .context("--auth-file требует путь к файлу")?;
                    let content = std::fs::read_to_string(path)
                        .with_context(|| format!("не удалось прочитать {path}"))?;
                    for line in content.lines() {
                        let line = line.trim();
                        if line.is_empty() || line.starts_with('#') {
                            continue;
                        }
                        let (u, p) = line
                            .split_once(':')
                            .context("формат файла: user:pass на каждой строке")?;
                        users.insert(u.to_owned(), p.to_owned());
                    }
                }
                "--sni" => {
                    i += 1;
                    sni_spoof = Some(
                        args.get(i)
                            .context("--sni требует доменное имя")?
                            .clone(),
                    );
                }
                "--sni-exclude" => {
                    i += 1;
                    let raw = args
                        .get(i)
                        .context("--sni-exclude требует суффикс, напр. apple.com")?;
                    let v = Self::normalize_sni_exclude_suffix(raw)
                        .context("--sni-exclude: невалидное значение")?;
                    sni_exclude.push(v);
                }
                "--sni-exclude-file" => {
                    i += 1;
                    let path = args
                        .get(i)
                        .context("--sni-exclude-file требует путь к файлу")?;
                    let content = std::fs::read_to_string(path)
                        .with_context(|| format!("не удалось прочитать {path}"))?;
                    for (lineno, line) in content.lines().enumerate() {
                        let line = line.trim();
                        if line.is_empty() {
                            continue;
                        }
                        let line = line.split('#').next().unwrap_or("").trim();
                        if line.is_empty() {
                            continue;
                        }
                        let v = Self::normalize_sni_exclude_suffix(line).with_context(|| {
                            format!("{}:{}: неверный суффикс SNI-exclude", path, lineno + 1)
                        })?;
                        sni_exclude.push(v);
                    }
                }
                "--tls-cert" => {
                    i += 1;
                    tls_cert = Some(
                        args.get(i)
                            .context("--tls-cert требует путь к PEM-сертификату")?
                            .clone(),
                    );
                }
                "--tls-key" => {
                    i += 1;
                    tls_key = Some(
                        args.get(i)
                            .context("--tls-key требует путь к PEM-ключу")?
                            .clone(),
                    );
                }
                "--tls-flex" => {
                    tls_flex = true;
                }
                // ── Reality options ─────────────────────────────────
                "--reality-dest" => {
                    i += 1;
                    reality_dest = Some(
                        args.get(i)
                            .context("--reality-dest требует host:port")?
                            .clone(),
                    );
                }
                "--reality-secret" => {
                    i += 1;
                    let b64 = args
                        .get(i)
                        .context("--reality-secret требует base64")?;
                    let bytes = base64::Engine::decode(
                        &base64::engine::general_purpose::STANDARD,
                        b64,
                    )
                    .context("--reality-secret: невалидный base64")?;
                    if bytes.len() != 32 {
                        bail!("--reality-secret: ожидается 32 байта, получено {}", bytes.len());
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    reality_secret = Some(arr);
                }
                "--reality-short-id" => {
                    i += 1;
                    let hex = args
                        .get(i)
                        .context("--reality-short-id требует hex (16 символов)")?;
                    let bytes = crate::reality::hex_decode(hex)
                        .context("--reality-short-id: невалидный hex")?;
                    if bytes.len() != 8 {
                        bail!(
                            "--reality-short-id: ожидается 8 байт (16 hex), получено {}",
                            bytes.len()
                        );
                    }
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(&bytes);
                    reality_short_ids.push(arr);
                }
                "--reality-server-names" => {
                    i += 1;
                    let raw = args
                        .get(i)
                        .context("--reality-server-names требует домены через запятую")?;
                    for name in raw.split(',') {
                        let name = name.trim().to_ascii_lowercase();
                        if !name.is_empty() {
                            reality_server_names.push(name);
                        }
                    }
                }
                "--reality-max-time-diff" => {
                    i += 1;
                    reality_max_time_diff = args
                        .get(i)
                        .context("--reality-max-time-diff требует число секунд")?
                        .parse()
                        .context("--reality-max-time-diff: невалидное число")?;
                }
                "-h" | "--help" => {
                    Self::print_usage();
                    std::process::exit(0);
                }
                other if listen.is_none() => {
                    listen = Some(
                        other
                            .parse()
                            .with_context(|| format!("невалидный адрес: {other}"))?,
                    );
                }
                other => bail!("неизвестный аргумент: {other}"),
            }
            i += 1;
        }

        if tls_cert.is_some() != tls_key.is_some() {
            bail!("нужно указать оба --tls-cert и --tls-key");
        }
        if tls_flex && tls_cert.is_none() {
            bail!("--tls-flex имеет смысл только вместе с --tls-cert и --tls-key");
        }

        let has_reality = reality_dest.is_some()
            || reality_secret.is_some()
            || !reality_short_ids.is_empty()
            || !reality_server_names.is_empty();

        if has_reality {
            if reality_dest.is_none() {
                bail!("--reality-dest обязателен при включении Reality");
            }
            if reality_secret.is_none() {
                bail!("--reality-secret обязателен при включении Reality");
            }
            if reality_short_ids.is_empty() {
                bail!("хотя бы один --reality-short-id обязателен");
            }
            if reality_server_names.is_empty() {
                bail!("--reality-server-names обязателен при включении Reality");
            }
            if tls_cert.is_none() {
                bail!("Reality требует --tls-cert и --tls-key");
            }
        }

        Ok(Config {
            listen: listen.context("не указан адрес (например 0.0.0.0:443)")?,
            users: Arc::new(users),
            sni_spoof: sni_spoof.map(|s| Arc::from(s.as_str())),
            tls_cert,
            tls_key,
            tls_flex,
            sni_exclude,
            reality_dest,
            reality_secret,
            reality_short_ids,
            reality_server_names,
            reality_max_time_diff,
        })
    }

    pub fn require_auth(&self) -> bool {
        !self.users.is_empty()
    }

    pub fn reality_enabled(&self) -> bool {
        self.reality_secret.is_some()
    }

    pub fn print_usage() {
        eprintln!("SOCKS6 прокси-сервер с авторизацией, подменой SNI и Reality\n");
        eprintln!("Использование: socks6 <АДРЕС:ПОРТ> [ОПЦИИ]\n");
        eprintln!("Опции:");
        eprintln!("  --auth <user:pass>               добавить пользователя (можно повторять)");
        eprintln!("  --auth-file <путь>               загрузить пользователей из файла");
        eprintln!("  --sni <домен>                    подменять SNI в исходящих TLS (:443), только если CONNECT с доменом; для CONNECT по IP не трогаем");
        eprintln!("  --sni-exclude <суффикс>          не подменять SNI для *.<суффикс> (youtube.com, tiktokv.com, …)");
        eprintln!("  --sni-exclude-file <путь>        загрузить суффиксы из файла");
        eprintln!("  --tls-cert <путь>                PEM-сертификат для TLS");
        eprintln!("  --tls-key  <путь>                PEM-ключ для TLS");
        eprintln!("  --tls-flex                       принимать plaintext SOCKS6 и TLS на одном порту");
        eprintln!();
        eprintln!("Reality:");
        eprintln!("  --reality-dest <host:port>       cover-сервер для fallback (напр. www.google.com:443)");
        eprintln!("  --reality-secret <base64>        общий секрет (32 байта)");
        eprintln!("  --reality-short-id <hex>         разрешённый Short ID (16 hex, можно повторять)");
        eprintln!("  --reality-server-names <a,b,...>  допустимые SNI через запятую");
        eprintln!("  --reality-max-time-diff <сек>    допуск времени для Reality-auth (по умолчанию 3600)");
        eprintln!("  --reality-generate-keys          сгенерировать secret + short-id и выйти");
        eprintln!();
        eprintln!("  -h, --help                       показать справку");
        eprintln!();
        eprintln!("Переменные окружения:");
        eprintln!("  RUST_LOG                         уровень логирования (по умолчанию: info)");
    }
}
