# SOCKS6 (socks5+Reality)

[![Github issues](https://img.shields.io/github/issues/seudad/socks6)](https://github.com/seudad/socks6/issues)
[![language](https://img.shields.io/github/languages/top/seudad/socks6
)](https://github.com/seudad/socks6/)
[![Github issues](https://img.shields.io/github/v/release/seudad/socks6
)]()
[![Github issues](https://img.shields.io/github/license/seudad/socks6
)](https://github.com/seudad/socks6/)

Дополненный Socks5 протокол с Reality с коробки

>___
> ### Что реализовано уже:
>___
> - Backend (`socks6`)
> - Клиенткая часть на Rust (`socks6-client`)
> - Авторизация `--auth` по паре `user:pass`
> - Поддержка TLS (`--tls-cert --tls-key`)
> - Подмена SNI (`--sni example.com`)
> - TLS-flex (`--tls-flex`) опция для обхода `InvalidContentType`
> - SNI exclude (`--sni-exclude-file`) исключает домены для подмена SNI
> ___
> ### Reality:
> - `--reality-dest` сервер для Fallback (например `www.google.com:443`)
> - `--reality-secret` общий секрет для подключения в формате `base64`
> - `--reality-short-id` разрешенные short ID в формате `16 hex`
> - `--reality-server-names` допустимые SNI через запятую, те что указывали в `--sni`
> - `--reality-max-time-diff` максимальное расхождение по времени в секундах(по умолчанию стоит 120)
> - `--reality-generate-keys` этот флаг используется отдельно для генерации общего секрета и short ID, которые потом используются в `--reality-secret --reality-short-id`
>___

## Примеры подключения

### Без авторизации

`cargo run --release -- 0.0.0.0:1080`

### С авторизацией

`cargo run --release -- 0.0.0.0:1080 --auth admin:secret --auth user2:pass2`

### С подменой SNI

`cargo run --release -- 0.0.0.0:1080 --auth admin:secret --sni cloudflare.com`

### Уровень логирования

`RUST_LOG=socks6=debug cargo run --release -- 0.0.0.0:1080`

### С TLS

``cargo run --release -- 0.0.0.0:1080 \
    --tls-cert server.crt --tls-key server.key \
    --auth admin:secret --sni cloudflare.com``

### C TLS + tls-flex

``cargo run --release -- 0.0.0.0:1080 \
--tls-cert server.crt --tls-key server.key \
--auth admin:secret --sni cloudflare.com --tls-flex``
___