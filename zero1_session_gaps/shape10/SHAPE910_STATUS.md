# SHAPE 9 + 10 — STATUS (2026-10-24)

Two missions, both closed with receipts. No overlap with shape12 / shape34 / shape5678.

---

## MISSION 9 — NativePHP async task spool FULL RCE: env-tuning gap CLOSED

**Verdict: the full leak→write→call chain now fires END-TO-END through the NativePHP
bridge delivery, in-band, on the first attempt — `uid=0(root)` marker, receipted.**
No gdb, no baked process addresses, no /proc, no side channel; ASLR on; the only
per-build knowledge (two symbol offsets) is extracted offline from the target binary
by an ELF RELA-scan and rides inside the attacker's spool bytes.

### What changed vs. the 10-23 state

The old gap was the calibration stage: the staged classes (NativeAsyncLeak/Write/Call)
needed gdb-discovered D/CHUNK addresses, and that lottery failed in the lab
environment (leak oracle 0x0, D→CHUNK drift). Replaced the gdb bootstrap with the
**in-band bootstrap** from poc_matrix/pwn_zero4_live.php, ported into the bridge
delivery shape:

1. **M1 dance** — a re-entrant `a:127` unserialize reclaims the freed 8160-byte
   var_entries block2 and leaks its address through bucket0.val (`$arr[129] - 5056`).
2. **M2 VM-slot oracles** — u-call temp slots leak `&T_u5/&T_u13` (spacing check 128);
   the strlen oracle on the string-at-`&T_u9` reads `*(&T_u9+16)` = `&zend_empty_array`
   → **binary base = oracle − OFF_EMPTY**. Validated: double-oracle agreement,
   lo12 match, page alignment.
3. **M3 forge + fire** — `str_repeat(pat,4)` reclaims block2 (canaries verified),
   base re-verified via **ELF magic read at BASE+0** (R:1023), then R:1022 hands
   userland a ref to a **forged zend_object** whose handler table points at
   `zif_system`; `var_dump($r1)` invokes `handlers->get_debug_info(obj) =
   zif_system(fake_execute_data)` → `system("sh /tmp/e")` → uid marker.

Everything the chain needs arrives as **spool-file bytes only**: the dance payload,
the FIRE payload, the two elfsyms offsets and the marker command are object
properties of the dup-key trigger object (`NativeAsyncRce`), exactly how a real
exploit ships per-version offset tables.

### shape9_elfsyms.py (the RELA scan)

Offline symbol extraction for possibly-stripped PHP monoliths (the shipped
NativePHP 8.4.27/8.3.36 binaries are the target class):
- Walks `.rela.dyn`/`.rela.plt` (section headers, PT_DYNAMIC fallback);
  R_X86_64_RELATIVE addends are the post-relocation internal pointers sitting in
  `.data.rel.ro` — where ext/standard's `zend_function_entry[]` lives.
- Finds the table row whose `fname` is the C string `system` and whose next qword
  (the handler) points into an exec segment → **zif_system**. Falls back to the raw
  data-segment pair scan for non-PIE builds. `zend_empty_array` from `.dynsym`.
- Receipt (`receipts/nativephp_elfsyms.log`): plain2 → `0x523c60`/`0xffe460`
  (nm-verified), **identical on a fully `strip`ped copy**, and correct distinct
  values on the asan2 and plain builds (`0xba2b6a`/`0x1dfe1c0`,
  `0x4d8ed0`/`0xffec40`).
- **Self-gating proof**: feeding a wrong offset table (lo12 off by one) → clean
  `M2-BAIL oracle lo12` bail, no fire — the chain never detonates on a mismatched
  binary, which is what makes per-version offset shipping safe.
- bin.nativephp.com unreachable from the lab today, so the receipts run against
  plain2 (8.5.12 — same var.c/var_unserializer.c code family as the bundled
  8.4.27/8.3.36 per the 10-23 verdict). The tool is binary-generic; against the
  real bundle the only delta is the two hex offsets in the payload.

### The bridge receipt (`nativephp_lane/receipts/nativephp_rce_fullchain.log`)

Attempt 1 of the HTTP delivery:

```
[elfsyms] plain2: zif_system=0x523c60 zend_empty_array=0xffe460
[upload] 200 .../uploads/user-content.bin (11644 bytes)
POST /_native/api/call File.Copy          -> 200 success
POST /_native/api/call AsyncTask.Dispatch -> runner:
  M1 block2 = 0x7397ecead000
  M2-DONE base=0x5ae518600000 zif_system=0x5ae518b23c60
  M3 string reclaim OK (canaries verified at block2)
  M3 BASE verified via ELF magic at BASE+0
  M3 forged: OBJ=0x7397ecead098 HT=0x7397ecead270 zif_system=0x5ae518b23c60
  TRIGGER var_dump($r1) -> zif_system(fake_execute_data)
[exfil File.Copy /tmp/pwned_nativephp_rce -> public/] 200
[RECEIPT via /_assets/shape9_rce_receipt.txt] uid=0(root) gid=0(root) groups=0(root)
[PASS] FULL zero4 chain through the NativePHP bridge
```

The uid marker is read back **through the framework's own exfil hole**
(File.Copy → `/_assets/`), i.e. the bridge both delivers the exploit and returns
its receipt. Premise unchanged from the 10-23 analysis: attacker content in any
webview the app shows + any app file-save feature; runner under stock defaults
(`-n`, USE_ZEND_ALLOC=1, no gdb — the AsyncTaskRunner lane shape).

Files: `nativephp_lane/lab/shape9_elfsyms.py`, `shape9_runner.php` (runner clone +
NativeAsyncRce/NativeAsyncFire gadget classes), `shape9_attack.py` (driver),
`shape9_run.sh` (receipt orchestrator), `shape9_extra_receipts.sh`.

---

## MISSION 10 — Mixed-handler crossfire: escalated from corruption to weaponizable primitives

**Verdict: the crossfire is now a full unauth cross-tenant session-takeover toolkit.**
Three weaponizable shapes, all receipted on plain AND ASAN 8.5.12 (zero ASAN — the
escalation is logic-level, consistent with WIPE2's no-memory-surface conclusion):

### a1 — php_binary writer → php reader: the A0 object injection (receipted)

Unauth multipart with `PHP_SESSION_UPLOAD_PROGRESS` name `x|O:10:"EvilGadget":...`
to a vhost whose handler is php_binary (`cleanup=0`): the write side has no pipe
check, so the poisoned key persists → shared session file becomes
`Gupload_progress_x|O:10:"EvilGadget":1:{s:3:"cmd";s:13:"pwn-xhfire-a1";}a:5:{...}`.
The victim vhost (default php handler) `session_start()`s: the pipe inside the key
turns the key bytes into a NAME|VALUE pair → **php_var_unserialize runs on the
attacker's serialized object inside the victim process** → `__wakeup` during decode,
`__destruct` during the decode-failure destroy teardown, both markers carry the
attacker-chosen `cmd`. Bonus receipt en route: the first touch with a php-format
victim file crossfire-DELETES it (WIPE2 addendum B, now with the inject follow-up).

### a2 — php (default!) writer → php_binary reader: injection with NO writer ini beyond cleanup=0

No pipe in the key at all. The php_binary reader's namelen framing (`'u'`=117)
lands its VALUE-parse window **102 bytes into the attacker name** — the object
bytes placed there unserialize in the victim process. Demonstrates the inverse
handler mismatch: a default-configured writer poisons a php_binary sibling.

### b — wipe-to-inject chain (receipted)

1. **WIPE**: unauth pipe-key multipart to the victim's OWN php vhost → live session
   (uid=1337, role=user) → **0 bytes**.
2. **INJECT**: unauth multipart to the php_binary writer vhost (same shared
   save_path, same victim SID) → session file replaced with the 406-byte poisoned
   php_binary content.
3. **DETONATE**: victim's own read → EvilGadget wakeup+destruct markers, warning
   "Failed to decode session object. Session has been destroyed", victim fully
   logged out.

### c — cross-tenant FULL takeover, clean decode (receipted)

Attacker tenant's own PHP on a vhost sharing save_path with the victim
(`shape10_takeover.php`): `session_id(victim) + session_start() + $_SESSION = ...`
rewrites the victim session **in the victim's own format**. Victim's next read is a
**CLEAN decode** (no warning, session intact) of a fully attacker-controlled
session: `uid='attacker-admin'`, `role='admin'`, plus the EvilGadget object (only
the class NAME travels in serialization — the victim process instantiates ITS
EvilGadget with attacker property values; destruct at normal shutdown). Forged
auth state + attacker-chosen object instantiation in one file. Prerequisites:
shared save_path + `session.use_strict_mode=0` (the default) — no memory bug.

### ctl — control (receipted)

Pipe-free multipart to the victim vhost → session intact (uid/role preserved):
the wipe is pipe-gated, the injection is cross-handler-gated; both receipts are
deterministic, not luck.

### Structural notes for the report

- Clean-decode state takeover is ONLY reachable via the tenant-code route (c):
  any rfc1867-written file ends with the writer's serialized progress array, and
  both stock readers require a delimiter-terminated valid tail — pure-rfc1867
  injection always ends in decode-FAILURE destroy (which still detonates the
  gadget: that is shapes a1/a2/b's primitive — wakeup fires during decode,
  destruct during teardown, both in the victim process).
- Persistence of the poisoned key needs `upload_progress.cleanup=0` on the writer
  vhost (CLI lab) — on Apache the same effect comes from aborting the upload
  before FILE_END (WIPE2 addendum C family); the wipe itself needs no ini at all.
- The victim never receives an attacker request in a1/a2 (only the attacker's own
  vhost + the victim's own traffic); in b the single victim-vhost request is the
  unauth multipart wipe.

Files: `wp2/shape10/shape10_attack.py` (orchestrator), `shape10_run.sh`,
`docroot_victim/victim.php` (victim tenant app + EvilGadget gadget class),
`docroot_victim_bin/victim.php`, `docroot_attacker/up.php`,
`docroot_attacker/shape10_takeover.php`. Receipts: `wp2/receipts/shape10_*.log`
(plain + `_asan` variants, plus `shape10_plain_run.log` / `shape10_asan_matrix.log`).

---

## Environment / reproducibility

- WSL lab, `/tmp/php8512_build/plain2` (8.5.12) and `/tmp/php8512_build/asan2`;
  servers = `php -S` with per-vhost ini files (the `-d` pipe-ini parsing trap from
  wp2 is avoided the same way).
- Mission 9 rerun: `bash nativephp_lane/lab/shape9_run.sh` (fires attempt-1-typical;
  driver retries up to 30 dispatches = fresh ASLR each).
- Mission 10 rerun: `bash wp2/shape10/shape10_run.sh` (plain pass + ASAN pass).
- bin.nativephp.com unreachable today → bundled-binary receipts stand in via
  plain2 + stripped-copy elfsyms validation; per-binary offsets are one hex pair.
