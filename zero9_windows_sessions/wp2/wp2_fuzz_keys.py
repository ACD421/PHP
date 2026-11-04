#!/usr/bin/env python3
# wp2_fuzz_keys.py - envelope sweep of the live poisoned-key window (angle 1)
# drives wp2_shot.sh per case; flags any ASAN/crash; writes matrix to /tmp/p2s_c2/fuzz_keys.report
import os, subprocess, sys, time

CL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wp2_shot.sh")
BASE = dict(PORT="18791")

def hx(b): return b.hex()

def key_classes(n):
    """return dict name -> bytes of length ~n"""
    c = {}
    if n == 0:
        return {"empty": b""}
    c["pipe_end"]   = b"A" * (n - 1) + b"|"
    c["pipe_start"] = b"|" + b"A" * (n - 1)
    c["pure_pipe"]  = b"|" * n
    c["nul_pipe"]   = b"\x00" * (n - 1) + b"|"
    c["pipe_nul"]   = b"|" + b"\x00" * (n - 1)
    k = max(1, (n - 3) // 2)
    c["nul_mid"]    = b"A" * k + b"\x00|" + b"\x00" + b"A" * k
    c["high"]       = bytes((0x80 + (i % 0x80)) for i in range(n - 1)) + b"|"
    c["del7f"]      = b"\x7f" * (n - 1) + b"|"
    c["utf8mb"]     = (b"\xc3\xa9\xe2\x82\xac\xf0\x9f\x98\x80" * ((n // 12) + 1))[:max(1, n - 1)] + b"|"
    c["all_bytes"]  = bytes(i for i in range(256)) + b"|" if n >= 257 else bytes(i % 256 for i in range(n - 1)) + b"|"
    if n >= 40:
        c["serial"] = b'inj|O:14:"SplObj":2:{s:1:"a";i:1;s:1:"b";i:2;}' + b"B" * (n - 41)
    c["no_pipe"]    = b"A" * n
    return c

CASES = []

def add(tag, keyhex, **env):
    e = dict(BASE); e.update(env); e["TAG"] = tag
    if len(keyhex) > 60000:
        kf = f"/tmp/p2s_c2/keys/{tag}.hex"
        os.makedirs("/tmp/p2s_c2/keys", exist_ok=True)
        open(kf, "w").write(keyhex)
        e["POISON_FILE"] = kf
    else:
        e["POISON"] = keyhex
    CASES.append((tag, e))

# --- core cross: lengths x classes --------------------------------------
for n in [1, 2, 15, 16, 17, 255, 256, 65536]:
    for name, kb in key_classes(n).items():
        add(f"fk_L{n}_{name}", hx(kb))

# --- length sweep for two classes ---------------------------------------
for n in [3, 7, 8, 9, 31, 32, 33, 63, 64, 65, 127, 128, 129, 257, 511, 512, 1023, 1024, 4096, 8192, 16384, 32768, 1000000]:
    add(f"fk_LEN{n}_pipe_end", hx(b"A" * (n - 1) + b"|"))
    add(f"fk_LEN{n}_nul_pipe", hx(b"\x00" * (n - 1) + b"|"))

# --- multipart envelopes (structure) ------------------------------------
k = hx(b"A" * 30 + b"|" + b"\x00\x00")
add("fm_parts3", k, PARTS="3")
add("fm_parts10", k, PARTS="10")
add("fm_prog_after", k, PROGRESS_AFTER="1")
add("fm_prog_mid", k, PROGRESS_MID="1", FILES="3")
add("fm_files10", k, FILES="10")
add("fm_parts3_after_mid", k, PARTS="3", PROGRESS_AFTER="1", PROGRESS_MID="1", FILES="4")
add("fm_sidfield", k, SIDFIELD="1", NOCOOKIE="1")
add("fm_nocookie", k, NOCOOKIE="1", QUERY="PHPSESSID=vicsid00000000000000000000000")
add("fm_abort", k, MODE="abort", ABORTAT="40960")
add("fm_abort_at1", k, MODE="abort", ABORTAT="1")
add("fm_slow", k, MODE="slow", CHUNK="4096", DELAY="0.02")
add("fm_clen_lie", k, EXTRA_ARGS="--clen-override 99999999")

# --- config variants ------------------------------------------------------
add("fc_cleanup0", k, CLEANUP="0")
add("fc_cleanup0_abort", k, CLEANUP="0", MODE="abort", ABORTAT="40960")
add("fc_freq_pct", k, FREQ="-1")
add("fc_freq_big", k, FREQ="1000000")
add("fc_minfreq1", k, MINFREQ="1")
add("fc_prefix_empty", k, PREFIX="")
add("fc_prefix_pipe", k, PREFIX="|x|")
add("fc_prefix_nul", k, PREFIX="a\x00b")   # prefix via env has NUL problem -> use hex-safe alt
CASES[-1] = ("fc_prefix_nul", dict(BASE, TAG="fc_prefix_nul", POISON=k, PREFIX="a"))
add("fc_prefix_long", k, PREFIX="P" * 300 + "|")
add("fc_smallfile", k, FILESIZE="16")
add("fc_emptyfile", k, FILESIZE="0")
add("fc_emptyfiledata", k, FILEDATA_HEX="")

def run_case(tag, env):
    e = dict(os.environ)
    e.update(env)
    t0 = time.time()
    try:
        r = subprocess.run(["bash", CL], env=e, capture_output=True, text=True, timeout=300)
        rc = r.returncode
    except subprocess.TimeoutExpired:
        rc = 99
    except OSError as ex:
        print(f"{tag}: OSError {ex}", flush=True)
        rc = 98
    dt = time.time() - t0
    return rc, dt

def result_line(tag):
    p = f"/tmp/p2s_c2/runs/{tag}/shot.log"
    try:
        last = [l for l in open(p) if l.startswith("after=")]
        return last[-1].strip() if last else "after=?"
    except FileNotFoundError:
        return "NOLOG"

if __name__ == "__main__":
    only = sys.argv[1] if len(sys.argv) > 1 else None
    rep = open(f"/tmp/p2s_c2/fuzz_keys_{only or 'all'}.report", "w")
    n_ok = n_asan = n_dead = 0
    for tag, env in CASES:
        if only and only not in tag:
            continue
        rc, dt = run_case(tag, env)
        res = result_line(tag)
        flag = ""
        if rc == 42:
            flag = "*** ASAN ***"; n_asan += 1
        elif rc in (43, 99):
            flag = "*** DEAD/TIMEOUT ***"; n_dead += 1
        else:
            n_ok += 1
        line = f"{tag:34s} rc={rc:<3d} {dt:5.1f}s {res} {flag}"
        print(line, flush=True); rep.write(line + "\n")
        if rc == 42:
            excerpt = open(f"/tmp/p2s_c2/runs/{tag}/server_err.log", errors="replace").read()
            rep.write("\n=== ASAN EXCERPT ===\n" + excerpt[:4000] + "\n")
    tail = f"\nDONE ok={n_ok} asan={n_asan} dead={n_dead} total={n_ok+n_asan+n_dead}"
    print(tail); rep.write(tail)
    rep.close()
