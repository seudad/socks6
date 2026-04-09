# SOCKS6 (socks5+Reality)

[![Github issues](https://img.shields.io/github/issues/seudad/socks6)](https://github.com/seudad/socks6/issues)
[![language](https://img.shields.io/github/languages/top/seudad/socks6
)](https://github.com/seudad/socks6/)
[![Github issues](https://img.shields.io/github/v/release/seudad/socks6
)]()
[![Github issues](https://img.shields.io/github/license/seudad/socks6
)](https://github.com/seudad/socks6/)

Более быстрый, легкий и также легко обходит современные блокировки

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

## Начало использования

### Ручная установка

**На данном этапе разработки требуется домен**

Обновите пакеты

```sudo apt update && sudo apt upgrade -y```

Установите certbot для получения сертификата

```sudo apt install certbot -y```

Создайте директорию для хранения сертификата

```mkdir -p /opt/socks6/cert && cd /opt/socks6/cert```

Получите сертификаты для своего домена<br>

```certbot certonly -m EMAIL -d DOMAIN -d DOMAIN2```

Подставьте свои значения вместо `EMAIL` укажите свою почту куда будут приходить уведомления связанные с доменом, вместо `DOMAIN` введите свой домен, `DOMAIN2` является опциональным 

После получения сертификата скопируйте их в директорию `/opt/socks6/cert/`:

```
cp /etc/letsencrypt/live/<ВАШ_ДОМЕН>/fullchain.pem /opt/socks6/cert
cp /etc/letsencrypt/live/<ВАШ_ДОМЕН>/privkey.pem /opt/socks6/cert
```

Подставьте свой домен в `<ВАШ_ДОМЕН>` который вы указывали ранее для получения сертификатов

Далее создадим двух пользователей для `socks6` и `socks6-client`:

```
sudo useradd --system --home /var/lib/socks6 --shell /usr/sbin/nologin socks6 socks6-client 2>/dev/null || true
```

Даем соответсвующие права на чтение сертификатов для пользователя `socks6`:

```
sudo chmod 600 /opt/socks6/cert
sudo chown socks6:socks6 /opt/socks6/cert
sudo chown socks6:socks6 /var/lib/socks6
```

Загрузите бинарник для вашей OS:
[Загрузка бинарников](https://github.com/seudad/socks6?tab=readme-ov-file#загрузка-бинарников)

Далее делаем файл `socks6` исполняемым и получаем `secret` и `short-id` для нашего Reality:
```
cd /opt/socks6
sudo chmod +x socks6
./socks6 --reality-generate-keys
```

После выполнения команды появятся две строчки `secret` и `short-id` их нужно скопировать и сохранить локально, они нам понадобятся чуть позднее.

Создаем два unit фаила:

```
sudo touch /etc/systemd/system/socks6.service
sudo touch /etc/systemd/system/socks6-client.service
```

Редактируем файл `socks6.service`:

`sudo nano /etc/systemd/system/socks6.service`

Далее вставляем и редактируем следующий код: 

```
[Unit]
Description=SOCKS6 proxy (TLS, Reality, SNI)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=socks6
Group=socks6
WorkingDirectory=/var/lib/socks6

ExecStart=/bin/sh -c 'exec /opt/socks6/socks6 0.0.0.0:443 --tls-cert /etc/socks6/cert/fullchain.pem --tls-key /opt/socks6/cert/privkey.pem --reality-dest EXAMPLE.COM:443 --reality-secret SECRET --reality-short-id SHORT-ID --reality-server-names EXAMPLE.COM --auth USER:PASS'

Restart=on-failure
RestartSec=5
# Лимит соединений для прокси
LimitNOFILE=1048576

# Слушать порт <1024 без root (например 443):
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/socks6

[Install]
WantedBy=multi-user.target
```

> Замените в `ExecStart` следующие поля:
> - `--reality-dest` - Укажите под что будет маскироваться подключение.
> - `--reality-server-names` - Можно указать тот же что и в `--reality-dest`
> - `--secret` - Укажите `secret`, который вы сгенирировали командой `--generate-reality-keys`
> - `--short-id` - Укажите `short-id`, который вы сгенирировали командой `--generate-reality-keys`
> - `--auth` - Придумайте логин и пароль для аутентификации `socsk6-client.service`.
___

Редактируем файл `socks6-client.service`:

`sudo nano /etc/systemd/system/socks6-client.service`

Затем вставляем и редактируем подобным образом:

```
[Unit]
Description=SOCKS6-client for SOCKS6 proxy (TLS, Reality, SNI)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=socks6-client
Group=socks6
WorkingDirectory=/var/lib/socks6

ExecStart=/bin/sh -c 'exec /opt/socks6/socks6-client --listen 0.0.0.0:1080 --server 127.0.0.1:443 --server-name ДОМЕН_ИЗ_REALITY_SERVER_NAMES --secret SECRET --short-id SHORT-ID --auth user:pass'

Restart=on-failure
RestartSec=5

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/socks6

[Install]
WantedBy=multi-user.target
```

> Замените в `ExecStart` следующие поля:
> - `--server-name` - Укажите тот же что указывали в `socks6.service` `--reality-server-names`
> - `--secret` - Укажите `secret`, который вы сгенирировали командой `--generate-reality-keys`
> - `--short-id` - Укажите `short-id`, который вы сгенирировали командой `--generate-reality-keys`
> - `--auth` - Введите логин и пароль который указывали в `socks6.service` в поле `--auth` соответсвенно.
___

#### После запускаем наш прокси и клиент для него:
```
sudo systemctl daemon-reload
sudo systemctl enable --now socks6 && sudo systemctl enable --now socks6-client
```


### Загрузка бинарников

> - #### Ubuntu 22.04
> ```
> cd /opt/socks6 && curl -fsSL 'https://github.com/seudad/socks6/releases/download/v2.1.2/socks6-v2.1.2-x86_64-unknown-linux-gnu.tar.gz' | tar xz 
> ```
>
> - #### Windows
> ```
> curl -fsSL 'https://github.com/seudad/socks6/releases/download/v2.1.2/socks6-v2.1.2-x86_64-pc-windows-msvc.zip' | tar xz
> ```