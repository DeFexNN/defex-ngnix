# Real-host simulation

Two scripts, one job each: bring up the official vulnerable image, then attack
any host over the wire. Nothing is built locally and no server log is read —
the verdict comes only from the frames the target sends back.

| file | role |
|---|---|
| `up.sh` | starts the **official** `nginx:1.31.8-alpine` image on `127.0.0.1:<port>` |
| `attack.sh` | probes a target by IP, fully client-side |
| `remote_leak.py` | worker for `attack.sh`, not meant to be called by hand |

## Start the official container

```sh
./up.sh              # port 18443
./up.sh 19443        # custom port
```

The script checks docker, pulls the image, asserts `nginx/1.31.8`, frees the
port, mounts `../conf` read-only and waits until the service answers. The
container is named `defex-ngnix` and runs with `--restart unless-stopped`, so
it survives a shell restart or a crash — `docker ps -a` shows it instead of it
silently vanishing.

Tear down: `docker rm -f defex-ngnix`

### Fixed build as a control

```sh
docker run -d --name nginx19 --restart unless-stopped -p 127.0.0.1:18445:18443 \
  -v "$PWD/../conf/nginx.conf:/etc/nginx/nginx.conf:ro" \
  -v "$PWD/../conf/cert.pem:/opt/lab/cert.pem:ro" \
  -v "$PWD/../conf/key.pem:/opt/lab/key.pem:ro" \
  -v "$PWD/../conf/big.bin:/opt/lab/html/big.bin:ro" \
  -v "$PWD/../conf/index.html:/opt/lab/html/index.html:ro" \
  nginx:1.31.9-alpine
./attack.sh 127.0.0.1 18445     # must FAIL
```

Start it and attack it **sequentially** — an attack fired in parallel with
`docker run` can hit stage 2 before the listener exists.

## Attack a host

```sh
./attack.sh 127.0.0.1 18443          # the container above
./attack.sh 10.10.10.5               # a real target, port 443
./attack.sh 10.10.10.5 8443 /big.bin
```

Arguments: `ip [port] [path]`. Port defaults to 443, path to `/big.bin`.
Tune with `STREAMS` and `STEP` if the payload differs.

On a PASS the script looks up the container publishing that port and, when
stdin and stdout are a TTY, drops you into it at `/opt/lab/data` — the
bind-mounted dir, where `flag.txt` persists across recreations:

```
[PASS] cleanup returns a large part of the window - leak present
[ .. ] entering defex-ngnix - 'cat flag.txt', Ctrl-D to leave
/opt/lab/data # cat flag.txt
FLAG{...}
```

`NO_SHELL=1` keeps it non-interactive; remote hosts and pipes only get the
`docker exec` hint line.

## Why a ratio and not a yes/no

Both the vulnerable and the fixed build drift, so "increment accepted" proves
nothing. What separates them is **stream cleanup**:

* `1.31.8` — `ngx_http_v2_filter_cleanup()` walks only frames without
  `frame->blocked` and returns that part of the charged window. Cleanup
  therefore shrinks the deficit by a factor of ~3.5.
* fixed builds net out, ratio ~1.0.

The script loads `STREAMS` requests of the payload so the 2 GiB connection
window saturates, measures the missing window once without and once with
`RST_STREAM` cleanup, and compares. `ratio >= 2.0` → vulnerable.

The payload must be at least 4 MiB and `size * streams` above 2 GiB, otherwise
the window never saturates and the numbers scatter. `attack.sh` refuses to run
in that case.

## Limits

* The target must speak HTTP/2 over TLS with ALPN `h2`.
* A reverse proxy in front that terminates h2 hides the nginx window entirely.
* `server:` is printed for orientation only — versions lie, the probe decides.

## Measured on this box

| target | without cleanup | with cleanup | ratio | verdict |
|---|---|---|---|---|
| 1.31.8 | 44–50 MB | 12–17 MB | 3.1–3.5 | vulnerable |
| 1.31.9 | 12.5–14.7 MB | 12.5–14.7 MB | 0.8–1.0 | fixed |

Five runs per row, one connection each.
