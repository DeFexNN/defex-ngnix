#!/usr/bin/env bash
# Starts the OFFICIAL nginx image pinned to the vulnerable version.
# Nothing is built: only the lab config and assets are mounted read-only.
#
# Usage: ./up.sh [port]      (default port 18443)
# Then:  ./attack.sh 127.0.0.1 <port>

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
CONF="$HERE/../conf"
DATA="$HERE/../data"
IMAGE="nginx:1.31.8-alpine"
NAME="defex-ngnix"
PORT="${1:-18443}"

say() { printf '\033[1;36m== %s\033[0m\n' "$*"; }
ok()  { printf '\033[1;32m[PASS]\033[0m %s\n' "$*"; }
bad() { printf '\033[1;31m[FAIL]\033[0m %s\n' "$*"; }
info(){ printf '\033[1;34m[ .. ]\033[0m %s\n' "$*"; }

say "start official $IMAGE"
command -v docker >/dev/null || { bad "docker is not installed"; exit 1; }
docker info >/dev/null 2>&1 || { bad "docker daemon not reachable"; exit 1; }
ok "docker $(docker version --format '{{.Server.Version}}')"

if docker image inspect "$IMAGE" >/dev/null 2>&1; then
    ok "image present"
else
    info "pulling $IMAGE"
    docker pull -q "$IMAGE" >/dev/null 2>&1 || { bad "pull failed"; exit 1; }
    ok "image pulled"
fi

VER=$(docker run --rm "$IMAGE" nginx -v 2>&1 | grep -o 'nginx/[0-9][0-9.]*' | tail -1)
[ "$VER" = "nginx/1.31.8" ] && ok "$VER - vulnerable build" \
    || { bad "unexpected version $VER"; exit 1; }

docker rm -f "$NAME" >/dev/null 2>&1   # one name everywhere, same as README and driver
if command -v ss >/dev/null && ss -ltn "sport = :$PORT" 2>/dev/null | grep -q LISTEN; then
    info "host port $PORT busy - freeing it"
    fuser -k "$PORT/tcp" >/dev/null 2>&1 || true
    sleep 1
fi

mkdir -p "$DATA"
docker run -d --name "$NAME" --restart unless-stopped -w /opt/lab/data -p "127.0.0.1:$PORT:18443" \
    -v "$CONF/nginx.conf:/etc/nginx/nginx.conf:ro" \
    -v "$CONF/cert.pem:/opt/lab/cert.pem:ro" \
    -v "$CONF/key.pem:/opt/lab/key.pem:ro" \
    -v "$CONF/big.bin:/opt/lab/html/big.bin:ro" \
    -v "$CONF/index.html:/opt/lab/html/index.html:ro" \
    -v "$DATA:/opt/lab/data" \
    "$IMAGE" >/dev/null || { bad "container start failed"; exit 1; }
ok "$NAME up"

UP=0
for _ in $(seq 1 25); do
    if curl -sk --max-time 2 "https://127.0.0.1:$PORT/" >/dev/null 2>&1; then UP=1; break; fi
    sleep 0.2
done
[ "$UP" = 1 ] || { bad "service did not come up"; docker logs "$NAME" 2>&1 | tail -5; exit 1; }
ok "answering on 127.0.0.1:$PORT"

say "next"
info "./attack.sh 127.0.0.1 $PORT"
info "or from elsewhere: ./attack.sh <target-ip> <port>"
info "tear down: docker rm -f $NAME"
