#!/usr/bin/env bash
# defex_ngnix.sh - nginx HTTP/2 lab for CVE-2026-123007
#
# Builds the image, starts the container, proves the vulnerability from the
# server log, then drops you into a shell inside the container.
#
# Usage: ./defex_ngnix.sh [port]
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="defex-ngnix:vuln"
NAME="defex-ngnix"
PORT="${1:-18443}"
MAXW=2147483647
PY="$(command -v python3 || true)"
FAILED=0

say()  { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m[PASS]\033[0m %s\n' "$*"; }
bad()  { printf '\033[1;31m[FAIL]\033[0m %s\n' "$*"; FAILED=1; }
info() { printf '\033[1;33m[ .. ]\033[0m %s\n' "$*"; }
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1; }
trap 'printf "\ninterrupted\n"; exit 130' INT

say "stage 1/9 preflight"
command -v docker >/dev/null || { bad "docker is not installed"; exit 1; }
docker info >/dev/null 2>&1 || { bad "docker daemon not reachable"; exit 1; }
ok "docker $(docker version --format '{{.Server.Version}}')"

if [ -z "$PY" ] || ! "$PY" -c 'import ssl,socket' 2>/dev/null; then
    bad "python3 with ssl/socket required"; exit 1
fi
if ! "$PY" -c "import sys;sys.path.insert(0,'$HERE/poc/_vendor');import h2" 2>/dev/null; then
    bad "vendored h2 stack unusable in $HERE/poc/_vendor"; exit 1
fi
ok "python $("$PY" -V 2>&1 | cut -d' ' -f2) with vendored h2"

say "stage 2/9 build image"
info "image $IMAGE - nginx 1.31.8 (vulnerable) with HTTP/2 + TLS"
if docker build -q -t "$IMAGE" "$HERE" >/tmp/defex_ngnix_build.log 2>&1; then
    ok "image $(docker image inspect -f '{{.Id}}' "$IMAGE" | cut -c1-19)"
else
    bad "build failed, see /tmp/defex_ngnix_build.log"; tail -20 /tmp/defex_ngnix_build.log; exit 1
fi

say "stage 3/9 start container"
cleanup
if command -v ss >/dev/null && ss -ltn "sport = :$PORT" 2>/dev/null | grep -q LISTEN; then
    info "host port $PORT busy - freeing it"
    fuser -k "$PORT/tcp" >/dev/null 2>&1 || true
    sleep 1
fi
if docker run -d --name "$NAME" -p "127.0.0.1:$PORT:18443" "$IMAGE" >/dev/null; then
    ok "container $NAME up, 127.0.0.1:$PORT -> 18443"
else
    bad "container start failed"; exit 1
fi

say "stage 4/9 wait for readiness"
UP=0
for i in $(seq 1 40); do
    if curl -sk --max-time 2 "https://127.0.0.1:$PORT/" >/dev/null 2>&1; then
        ok "service answering after ${i} attempt(s)"; UP=1; break
    fi
    sleep 0.25
done
[ "$UP" = 1 ] || { bad "service did not come up"; docker logs "$NAME" 2>&1 | tail -5; exit 1; }

say "stage 5/9 build facts"
VER=$(docker exec "$NAME" /usr/sbin/nginx -v 2>&1 | grep -o 'nginx/[0-9.]*')
printf '  version: %s\n' "$VER"
[ "$VER" = "nginx/1.31.8" ] && ok "vulnerable version 1.31.8 confirmed" || bad "unexpected version $VER"
V2=$(docker exec "$NAME" /usr/sbin/nginx -V 2>&1 | tr ' ' '\n' | grep -c 'http_v2_module')
[ "$V2" -ge 1 ] && ok "HTTP/2 module compiled in" || bad "HTTP/2 module missing"

say "stage 6/9 protocol check"
PROTO=$(curl -sk --http2 -o /dev/null -w '%{http_version}' "https://127.0.0.1:$PORT/")
[ "$PROTO" = "2" ] && ok "negotiated HTTP/2" || bad "expected HTTP/2, got '$PROTO'"
BODY=$(curl -sk --http2 "https://127.0.0.1:$PORT/big.bin" | wc -c)
[ "$BODY" = "4194304" ] && ok "big.bin served, $BODY bytes" || bad "big.bin size $BODY"

say "stage 7/9 PoC A - send window overflows MAX"
docker exec "$NAME" sh -c ': > /var/log/nginx/lab.log'
"$PY" "$HERE/poc/flow_control.py" 1000 127.0.0.1 "$PORT" 2>&1 | sed 's/^/  /'
sleep 1
V=$(docker exec "$NAME" grep -c 'violated connection flow control' /var/log/nginx/lab.log 2>/dev/null || true)
if [ "${V:-0}" -gt 0 ]; then
    ok "server rejected the WINDOW_UPDATE ($V log line(s))"
    docker exec "$NAME" grep -m1 -o 'increment [0-9]* not allowed for window [0-9]*' /var/log/nginx/lab.log | sed 's/^/  /'
else
    bad "no violation logged"
fi

say "stage 8/9 PoC B - cleanup does not return the window"
docker exec "$NAME" sh -c ': > /var/log/nginx/lab.log'
"$PY" "$HERE/poc/blocked_frames.py" 400 127.0.0.1 "$PORT" 2>&1 | sed 's/^/  /'
sleep 2
V=$(docker exec "$NAME" grep -c 'violated connection flow control' /var/log/nginx/lab.log 2>/dev/null || true)
printf '  violation lines: %s\n' "${V:-0}"
if [ "${V:-0}" -gt 0 ]; then
    ok "window leaked after stream reset - increment rejected"
    docker exec "$NAME" grep -m1 -o 'increment [0-9]* not allowed for window [0-9]*' /var/log/nginx/lab.log | sed 's/^/  /'
else
    bad "no violation after stream reset"
fi
CONN=$(curl -sk --http2 -o /dev/null -w '%{http_version}' "https://127.0.0.1:$PORT/")
[ "$CONN" = "2" ] && ok "server still serves HTTP/2 after the leak" || bad "server unhealthy after leak"

say "stage 9/9 cleanup returns only part of the charged window"
W_RST=0
W_PLAIN=0
for mode in 1 0; do
    docker exec "$NAME" sh -c ': > /var/log/nginx/lab.log'
    "$PY" "$HERE/poc/leak_control.py" 400 "$mode" "$PORT" >/dev/null 2>&1
    sleep 1
    W=$(docker exec "$NAME" grep -o 'not allowed for window [0-9]*' /var/log/nginx/lab.log | tail -1 | awk '{print $5}')
    if [ "$mode" = 1 ]; then
        W_RST=${W:-0}
        printf '  with resets   -> window %s\n' "${W:-none}"
    else
        W_PLAIN=${W:-0}
        printf '  without resets -> window %s\n' "${W:-none}"
    fi
done
if [ "$W_RST" -gt 0 ] && [ "$W_PLAIN" -gt 0 ] && [ "$W_RST" -gt "$W_PLAIN" ]; then
    ok "cleanup gives back only unblocked frames - window stays short"
    printf '  ~%s bytes back from cleanup, %s still missing from the window\n' \
        "$((W_RST - W_PLAIN))" "$((MAXW - W_RST))"
else
    bad "cleanup behaviour did not match the leak"
fi

say "summary"
if [ "$FAILED" = 0 ]; then
    ok "all stages passed - nginx 1.31.8 is vulnerable here"
else
    bad "some stages failed, container kept for inspection"
fi

say "container shell"
info "url https://127.0.0.1:$PORT/ | log /var/log/nginx/lab.log"
info "type 'exit' to leave, the container keeps running"
if [ -t 0 ]; then
    docker exec -it "$NAME" sh
else
    info "stdin is not a terminal, skipping the shell"
fi
