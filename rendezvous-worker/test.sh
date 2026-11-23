#!/usr/bin/env bash
# Run the rendezvous server tests of the repository against this Worker.
#
# Starts the Worker twice on this computer with `wrangler dev`, nothing is deployed and
# no Cloudflare account is needed: once as it is, and once with slots that expire after
# a second. Then runs qs-rendezvous/tests/server.rs against both.
set -euo pipefail
cd "$(dirname "$0")"

PORT=${PORT:-8787}
QUICK_PORT=${QUICK_PORT:-8788}
state=$(mktemp -d)
pids=()

cleanup() {
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$state"
}
trap cleanup EXIT

start() { # port, name, extra arguments for wrangler
  local port=$1 name=$2
  shift 2
  npx wrangler dev --env test --ip 127.0.0.1 --port "$port" \
    --inspector-port $((port + 1000)) --persist-to "$state/$name" \
    --show-interactive-dev-session=false "$@" >"$state/$name.log" 2>&1 &
  pids+=($!)

  for _ in $(seq 1 120); do
    if curl -sf --noproxy '*' "http://127.0.0.1:$port/v1" >/dev/null 2>&1; then return 0; fi
    sleep 0.5
  done
  echo "the Worker did not start on port $port:" >&2
  cat "$state/$name.log" >&2
  exit 1
}

start "$PORT" open
start "$QUICK_PORT" quick --var TTL_SECS:1 --var REPLY_TTL_SECS:60

QS_RENDEZVOUS_URL="http://127.0.0.1:$PORT" \
QS_RENDEZVOUS_QUICK_URL="http://127.0.0.1:$QUICK_PORT" \
  cargo test --manifest-path ../Cargo.toml -p qs-rendezvous --test server -- --test-threads=1 "$@"

# The limits of the configuration that gets deployed, which the tests above run without
LIMITS_PORT=${LIMITS_PORT:-8789}
start_default() {
  npx wrangler dev --ip 127.0.0.1 --port "$LIMITS_PORT" --inspector-port $((LIMITS_PORT + 1000)) \
    --persist-to "$state/limits" --show-interactive-dev-session=false >"$state/limits.log" 2>&1 &
  pids+=($!)
  for _ in $(seq 1 120); do
    if curl -sf --noproxy '*' "http://127.0.0.1:$LIMITS_PORT/v1" >/dev/null 2>&1; then return 0; fi
    sleep 0.5
  done
  echo "the Worker did not start with its default configuration:" >&2
  cat "$state/limits.log" >&2
  exit 1
}
start_default

base="http://127.0.0.1:$LIMITS_PORT/v1/slots"
status() { curl -s --noproxy '*' -o /dev/null -w '%{http_code}' "$@"; }
fail() { echo "limits: $1" >&2; exit 1; }
hello='{"message":"aGVsbG8"}'

nameplate=$(curl -s --noproxy '*' -X POST -H 'content-type: application/json' -d "$hello" "$base" |
  sed -n 's/.*"nameplate":"\([^"]*\)".*/\1/p')
[ -n "$nameplate" ] || fail "could not create a slot"

# The limits count per minute on the clock, so a count can start again in the middle of
# this. Enough requests for two minutes' worth always fill one of them.

# 5 slots per minute
refused=0
for i in $(seq 1 11); do
  code=$(status -X POST -H 'content-type: application/json' -d "$hello" "$base")
  case "$code" in
    201) ;;
    429) refused=1 ;;
    *) fail "create $i gave $code" ;;
  esac
done
[ "$refused" = 1 ] || fail "creating slots was never refused"

# 30 replies per minute, also when they lead nowhere. "zz" is no nameplate, so this
# never meets a slot.
refused=0
for i in $(seq 1 62); do
  code=$(status -X PUT -H 'content-type: application/json' -d "$hello" "$base/zz/reply")
  case "$code" in
    404) ;;
    429) refused=1 ;;
    *) fail "reply $i gave $code" ;;
  esac
done
[ "$refused" = 1 ] || fail "replying was never refused"

# Looking is counted on its own: it still works, and the slot is still unused
[ "$(status "$base/$nameplate")" = 200 ] || fail "looking was refused together with replying"

echo "limits: ok"
