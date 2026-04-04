use crate::config::Config;
use crate::{relay, socks5};
use anyhow::{bail, Result};
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};

pub async fn run(config: Config) -> Result<()> {
    let listener = TcpListener::bind(config.listen).await?;
    tracing::info!(addr = %config.listen, "SOCKS5 прокси запущен");

    if config.require_auth() {
        tracing::info!(users = config.users.len(), "авторизация включена");
    } else {
        tracing::warn!("авторизация отключена — все подключения разрешены");
    }
    if let Some(ref sni) = config.sni_spoof {
        tracing::info!(sni = %sni, "подмена SNI включена");
    }

    loop {
        let (stream, peer) = listener.accept().await?;
        let cfg = config.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, peer, cfg).await {
                tracing::warn!(%peer, "сессия завершена: {e:#}");
            }
        });
    }
}

#[tracing::instrument(name = "client", skip_all, fields(%peer))]
async fn handle_client(
    mut client: TcpStream,
    peer: SocketAddr,
    config: Config,
) -> Result<()> {
    client.set_nodelay(true)?;

    socks5::handshake(&mut client, &config).await?;
    let target = socks5::read_connect(&mut client).await?;
    tracing::info!(%target, "CONNECT");

    let mut remote = match target.connect().await {
        Ok(s) => s,
        Err(e) => {
            let reply = match e.kind() {
                std::io::ErrorKind::ConnectionRefused => socks5::Reply::ConnectionRefused,
                _ => socks5::Reply::HostUnreachable,
            };
            socks5::send_reply(&mut client, reply).await.ok();
            bail!("подключение к {target} не удалось: {e}");
        }
    };
    remote.set_nodelay(true)?;

    let bind = remote.local_addr()?;
    socks5::send_connect_ok(&mut client, bind).await?;

    let is_tls = target.port() == 443;
    let sni = if is_tls {
        config.sni_spoof.as_deref()
    } else {
        None
    };
    let (up, down) = relay::relay(&mut client, &mut remote, sni).await?;

    tracing::info!(up, down, "релей завершён");
    Ok(())
}
