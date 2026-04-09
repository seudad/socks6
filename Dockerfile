# syntax=docker/dockerfile:1

FROM rust:1-bookworm AS builder
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --locked

# ── Reality SOCKS5-клиент (локальный SOCKS для приложений) ──────────────

FROM debian:bookworm-slim AS client

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/socks6-client /usr/local/bin/socks6-client
COPY docker/client-entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 1080

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# ── SOCKS6-сервер (TLS + Reality) — стадия по умолчанию для docker build ─

FROM debian:bookworm-slim AS server

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/socks6 /usr/local/bin/socks6
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 443

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
