# Примеры подключения

## Без авторизации

`cargo run --release -- 0.0.0.0:1080`

## С авторизацией

`cargo run --release -- 0.0.0.0:1080 --auth admin:secret --auth user2:pass2`

## С подменой SNI

`cargo run --release -- 0.0.0.0:1080 --auth admin:secret --sni cloudflare.com`

## Уровень логирования

`RUST_LOG=socks5=debug cargo run --release -- 0.0.0.0:1080`

## С TLS

`cargo run --release -- 0.0.0.0:1080 \`
    `--tls-cert server.crt --tls-key server.key \`
    `--auth admin:secret --sni cloudflare.com`