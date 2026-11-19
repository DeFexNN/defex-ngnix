# defex-ngnix

[![nginx](https://img.shields.io/badge/nginx-1.31.8-009639?logo=nginx)](https://nginx.org/)
[![CVE](https://img.shields.io/badge/CVE-2026--123007-red)](https://nginx.org/)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

Proof of concept for a **connection-level HTTP/2 send-window leak** in
nginx 1.31.8: stream cleanup returns only the DATA frames that are still
unblocked, so bytes charged to the connection window before the socket blocked
are never given back. The connection permanently loses usable window and a
later, perfectly legal `WINDOW_UPDATE` gets rejected with `FLOW_CTRL_ERROR`.

The PoC is a self-contained Docker lab on `127.0.0.1` — no external host, no
build dependencies beyond Docker and Python 3 (h2 is vendored).

**Use the official image, pinned to the vulnerable version.** The bug is in the
binary, so nothing has to be built — only the lab config and assets are mounted
read-only on top of stock `nginx:1.31.8-alpine`:

```sh
docker run -d --name defex-ngnix -p 127.0.0.1:18443:18443 \
    -v "$PWD/conf/nginx.conf:/etc/nginx/nginx.conf:ro" \
    -v "$PWD/conf/cert.pem:/opt/lab/cert.pem:ro" \
    -v "$PWD/conf/key.pem:/opt/lab/key.pem:ro" \
    -v "$PWD/conf/big.bin:/opt/lab/html/big.bin:ro" \
    -v "$PWD/conf/index.html:/opt/lab/html/index.html:ro" \
    -v "$PWD/data:/opt/lab/data" \
    nginx:1.31.8-alpine

./defex_ngnix.sh          # prove it against the running container
./defex_ngnix.sh 8443     # same on another host port
```

Pin the tag. `nginx:alpine` floats and already moved to 1.31.9, which is
patched — the run then fails at stage 5. The bundled `Dockerfile` does the same
mounting as a one-shot build if you prefer `docker build` / `docker run`.

**The script makes no `docker` calls.** You start the container, the script
only speaks HTTP to it. All 8 stages must pass. A failure leaves the container
alone for inspection. The last stage is a control: the same load with and
without resets, proving the leak is in the cleanup path and not in the load
itself.

## Requirements

- Docker, to build and run the lab image
- Python 3 with the vendored `poc/_vendor` tree (no `pip install`)
- nothing else; TLS is a throwaway self-signed cert shipped for the lab

## Status

Verified against `nginx:alpine` = **1.31.8** on 2026-11-19. Every run ends
with 11 `[PASS]` and 0 `[FAIL]` against a freshly started container. Newer or
patched builds are expected to fail stage 5 and/or 6 — that is the signal.

> Only the lab above is tested. Other deployments, older branches and
> reverse proxies in front of nginx are untested.

## The bug

`ngx_http_v2_filter_module.c` subtracts the payload of every DATA frame from
the connection window when the frame is *queued*:

```c
ngx_http_v2_queue_frame(h2c, frame);
h2c->send_window -= frame_size;      /* charged on queueing */
stream->send_window -= frame_size;
```

`ngx_http_v2_filter_cleanup()` is supposed to give that payload back when a
stream dies, but it walks the output queue with

```c
if (frame->stream == stream && !frame->blocked) {
    *fn = frame->next;
    window += frame->length;
```

so frames that were **already charged and then blocked** on the socket are
skipped. Their bytes stay subtracted from `h2c->send_window` forever. That
field is a plain `size_t`, so the damage only ever shows up as a connection
window that can no longer reach MAX. Only the per-stream window is signed
(`ssize_t`), because a `SETTINGS_INITIAL_WINDOW_SIZE` change may push that one
negative.

The connection-level `WINDOW_UPDATE` path only compares the new increment
against `NGX_HTTP_V2_MAX_WINDOW - h2c->send_window`:

```c
if (window > NGX_HTTP_V2_MAX_WINDOW - h2c->send_window) {
    ... "client violated connection flow control" ...
    return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_FLOW_CTRL_ERROR);
}
h2c->send_window += window;
```

A drifted window therefore makes `MAX - h2c->send_window` larger than it
should be, so the server accepts increments that a correct build would reject.
The window itself can never exceed 2^31-1 (that is exactly what the check
enforces), which means the connection permanently loses usable window instead:
the peer keeps being refused the bytes it is entitled to.

## Proof

**Stage 5 — overflow.** Client advertises `INITIAL_WINDOW_SIZE = 2^31-1`,
opens 1000 streams behind a 1 KiB socket buffer so the HEADERS frames cannot
leave, drains, then sends two full-size increments. The second one is only
legal because of the drift:

```
[PASS] server rejected the WINDOW_UPDATE (1 log line(s))
  increment 2147418112 not allowed for window 2081882111
```

**Stage 6 — leak after cleanup.** 400 streams, all but the last RST afterwards.
The bytes of the blocked DATA frames are not returned, so the window stays
short of MAX and the final increment is rejected:

```
[PASS] window leaked after stream reset - increment rejected
  increment 2147418112 not allowed for window 2147401727
```

`2147483647 - 2147401727 = 81920` — exactly five 16 KiB DATA frames whose
payload is still missing from the window after 399 streams were cleaned up.
The server stays healthy and still negotiates HTTP/2 afterwards.

**Stage 7 — the control.** The same 400-stream load twice, once with the
resets and once without. Both runs leak, but the reset run ends higher:
cleanup does hand something back, it just skips the blocked frames.

```
  with resets   -> window 1921441791
  without resets -> window 1898053631
[PASS] cleanup gives back only unblocked frames - window stays short
```

Stage 6 is therefore not just "some load happened": the window is far below
MAX in both arms, and the ordering matches the `!frame->blocked` filter in the
source. `poc/window_growth.py` repeats the cycle several times if you want to
watch the window sink under sustained churn.

## Layout

| path | role |
|---|---|
| `defex_ngnix.sh` | 8-stage HTTP-only driver, colours |
| `Dockerfile` | `nginx:alpine` (1.31.8) + lab config and assets |
| `conf/nginx.conf` | TLS + `http2 on`, 4 KiB output buffer, `info` log to `lab.log`, log exposed at `/__lab.log` |
| `conf/big.bin` | 4 MiB payload |
| `poc/flow_control.py` | stage 5, window overflow |
| `poc/blocked_frames.py` | stage 6, leak after stream cleanup |
| `poc/leak_control.py` | stage 7, with/without-reset control |
| `poc/window_growth.py` | optional, repeated churn cycles |
| `poc/_vendor` | h2 / hpack / hyperframe, no pip needed |
| `data/` | host dir, bind-mount it to `/opt/lab/data` when you start the container |

Anything you write in the shell goes to `/opt/lab/data`, which you bind-mount
from `data/`. The container is yours to recreate, so that directory is the only
place work survives a restart.

`error_log` points at a real file, not `/dev/stderr`: a symlinked log cannot be
truncated and `tail`/`grep` would block on the pipe forever. It is published at
`/__lab.log` so the script can read it without `docker exec`; each stage
remembers the byte offset and only looks at lines produced after that point.

## Notes

- The stock image is built **without** `--with-debug`, so `send GOAWAY` never
  reaches the log; the `info`-level flow-control violation is the usable signal.
  GOAWAY itself is queued behind the blocked socket and often does not arrive.
- `worker_connections 4096` and `http2_max_concurrent_streams 5000` keep 1000
  streams comfortably below both limits.
- Resetting *every* stream instead of all but one scales the leak up hard:
  100-400 streams leave the window 230-316 MB short of MAX, because no stream
  is left to drain the still-queued frames.
- Tear down with `docker rm -f defex-ngnix`.
