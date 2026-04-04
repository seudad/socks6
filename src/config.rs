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
}

impl Config {
    pub fn from_args() -> Result<Self> {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let mut listen: Option<SocketAddr> = None;
        let mut users = HashMap::new();
        let mut sni_spoof: Option<String> = None;
        let mut tls_cert: Option<String> = None;
        let mut tls_key: Option<String> = None;

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

        Ok(Config {
            listen: listen.context("не указан адрес (например 127.0.0.1:1080)")?,
            users: Arc::new(users),
            sni_spoof: sni_spoof.map(|s| Arc::from(s.as_str())),
            tls_cert,
            tls_key,
        })
    }

    pub fn require_auth(&self) -> bool {
        !self.users.is_empty()
    }

    pub fn print_usage() {
        eprintln!("SOCKS5 прокси-сервер с авторизацией и подменой SNI\n");
        eprintln!("Использование: socks5 <АДРЕС:ПОРТ> [ОПЦИИ]\n");
        eprintln!("Опции:");
        eprintln!("  --auth <user:pass>       добавить пользователя (можно повторять)");
        eprintln!("  --auth-file <путь>       загрузить пользователей из файла");
        eprintln!("  --sni <домен>            подменять SNI в исходящих TLS-соединениях");
        eprintln!("  --tls-cert <путь>        PEM-сертификат для входящих TLS-соединений");
        eprintln!("  --tls-key  <путь>        PEM-ключ для входящих TLS-соединений");
        eprintln!("  -h, --help               показать справку\n");
        eprintln!("Переменные окружения:");
        eprintln!("  RUST_LOG                 уровень логирования (по умолчанию: info)");
    }
}
