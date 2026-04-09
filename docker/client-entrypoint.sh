#!/bin/sh
set -e

# Прослушивание SOCKS5 внутри контейнера (должно совпадать с правой частью проброса CLIENT_PUBLISH).
: "${CLIENT_LISTEN:=0.0.0.0:1080}"

if [ -z "${CLIENT_SERVER:-}" ] || [ -z "${CLIENT_SERVER_NAME:-}" ] \
   || [ -z "${CLIENT_SECRET:-}" ] || [ -z "${CLIENT_SHORT_ID:-}" ]; then
  echo "socks6-client: задайте CLIENT_SERVER, CLIENT_SERVER_NAME, CLIENT_SECRET, CLIENT_SHORT_ID" >&2
  exit 1
fi

ARGS="--listen $CLIENT_LISTEN --server $CLIENT_SERVER --server-name $CLIENT_SERVER_NAME"
ARGS="$ARGS --secret $CLIENT_SECRET --short-id $CLIENT_SHORT_ID"

if [ -n "${CLIENT_AUTH:-}" ]; then
  ARGS="$ARGS --auth $CLIENT_AUTH"
fi

if [ -n "${CLIENT_MAX_TLS:-}" ]; then
  ARGS="$ARGS --max-tls $CLIENT_MAX_TLS"
fi

if [ -n "${CLIENT_AUTH_TIME_OFFSET:-}" ]; then
  ARGS="$ARGS --auth-time-offset $CLIENT_AUTH_TIME_OFFSET"
fi

# Также поддерживаются переменные из кода: SOCKS6_CLIENT_MAX_TLS, SOCKS6_AUTH_TIME_OFFSET_SECS
if [ -n "${SOCKS6_CLIENT_MAX_TLS:-}" ]; then
  export SOCKS6_CLIENT_MAX_TLS
fi
if [ -n "${SOCKS6_AUTH_TIME_OFFSET_SECS:-}" ]; then
  export SOCKS6_AUTH_TIME_OFFSET_SECS
fi

if [ -n "${CLIENT_EXTRA_ARGS:-}" ]; then
  # shellcheck disable=SC2086
  ARGS="$ARGS $CLIENT_EXTRA_ARGS"
fi

if [ -n "${RUST_LOG:-}" ]; then
  export RUST_LOG
fi

exec /usr/local/bin/socks6-client $ARGS
