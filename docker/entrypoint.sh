#!/bin/sh
set -e

# Defaults tuned for container: listen on all interfaces, certs under /certs.
: "${LISTEN:=0.0.0.0:443}"
: "${TLS_CERT:=/certs/fullchain.pem}"
: "${TLS_KEY:=/certs/privkey.pem}"

if [ -z "${REALITY_SECRET:-}" ] || [ -z "${REALITY_SHORT_ID:-}" ] \
   || [ -z "${REALITY_DEST:-}" ] || [ -z "${REALITY_SERVER_NAMES:-}" ]; then
  echo "socks6: задайте REALITY_SECRET, REALITY_SHORT_ID, REALITY_DEST, REALITY_SERVER_NAMES" >&2
  exit 1
fi

if [ ! -r "$TLS_CERT" ] || [ ! -r "$TLS_KEY" ]; then
  echo "socks6: нет доступа к TLS: $TLS_CERT или $TLS_KEY (смонтируйте том /certs)" >&2
  exit 1
fi

ARGS="$LISTEN --tls-cert $TLS_CERT --tls-key $TLS_KEY"
ARGS="$ARGS --reality-dest $REALITY_DEST"
ARGS="$ARGS --reality-secret $REALITY_SECRET"
ARGS="$ARGS --reality-short-id $REALITY_SHORT_ID"
ARGS="$ARGS --reality-server-names $REALITY_SERVER_NAMES"

if [ -n "${AUTH_FILE:-}" ] && [ -r "$AUTH_FILE" ]; then
  ARGS="$ARGS --auth-file $AUTH_FILE"
elif [ -n "${AUTH:-}" ]; then
  ARGS="$ARGS --auth $AUTH"
fi

if [ -n "${SOCKS6_SNI:-}" ]; then
  ARGS="$ARGS --sni $SOCKS6_SNI"
fi

if [ -n "${SNI_EXCLUDE_FILE:-}" ] && [ -r "$SNI_EXCLUDE_FILE" ]; then
  ARGS="$ARGS --sni-exclude-file $SNI_EXCLUDE_FILE"
fi

if [ "${SOCKS6_TLS_FLEX:-}" = "1" ] || [ "${SOCKS6_TLS_FLEX:-}" = "true" ]; then
  ARGS="$ARGS --tls-flex"
fi

if [ -n "${REALITY_MAX_TIME_DIFF:-}" ]; then
  ARGS="$ARGS --reality-max-time-diff $REALITY_MAX_TIME_DIFF"
fi

# Произвольные флаги socks6, например: --sni-exclude youtube.com
if [ -n "${SOCKS6_EXTRA_ARGS:-}" ]; then
  # shellcheck disable=SC2086
  ARGS="$ARGS $SOCKS6_EXTRA_ARGS"
fi

if [ -n "${RUST_LOG:-}" ]; then
  export RUST_LOG
fi

exec /usr/local/bin/socks6 $ARGS
