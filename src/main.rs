use std::process;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "socks6=info".parse().unwrap()),
        )
        .init();

    let config = match socks6::config::Config::from_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ошибка: {e:#}");
            eprintln!();
            socks6::config::Config::print_usage();
            process::exit(1);
        }
    };

    if let Err(e) = socks6::server::run(config).await {
        tracing::error!("фатальная ошибка: {e:#}");
        process::exit(1);
    }
}
