# SHAPE5678_STATUS — missions 5/6/7/8 (2026-10-24)

Builds: `plain2` = 8.5.12 release, `asan2` = 8.5.12 ASAN, `fixedasan` =
8.5.12+08f4b64 ASAN (the reorder: `data=NULL` + `level--` BEFORE
`var_destroy`), `php8.1` = Ubuntu jammy 8.1.2-1ubuntu2.27 system + Apache
2.4.52 mod_php. No overlap with shape12 / shape34. Everything below is
receipted; negative results are receipted negatives.

---

## MISSION 5 — enum-autoload context sharing: the pin is unbeatable in-window; the sharing escalates into the destroy-walk UAF on 8.5.12, and also shares inside session decode

The pin: at `level>1` the re-entrant call's result is parked by
`var_tmp_var()` (var.c `php_unserialize_with_options`) into the SHARED
context's dtor chain — `tmp_var()` only ever APPENDS slots; nothing releases
one before the outer walk. All four requested routes, receipted:

- **(a) release early (unset in autoloader)** — DEAD. `shape5_a_unset.php`
  (plain2 + fixedasan): `weak->get() = object (PINNED)`, `gc=0`, destruct
  marker absent, outer `r:3` still resolves onto the inner `Pin(gen=1)`.
- **(b) second re-entrant call replaces the pin** — DEAD. `shape5_b_replace.php`:
  two/three re-entrant calls each pin in NEW slots; both weakrefs PINNED;
  phase-receipted release order = `phase=outer-call` (walk) then
  `phase=post-call` — never `phase=autoloader`. The `R:`-wraps-the-slot
  variant (`ZVAL_NEW_REF` in place on the pin slot) survives to the walk
  unchanged.
- **(c) GC on the pinned value** — DEAD. `shape5_c_gc.php`: a true self-cycle
  (`R:3` onto the result slot) is NOT collectible during the window
  (`gc_collect_cycles()=0`, weakref alive — the phantom slot ref reads as an
  external root); the SAME cycle is collected (`gc=1` + destruct) immediately
  after the outer call returns. The pin is exactly what blocks GC.
- **(d) different autoloader trigger** — mapped. `shape5_d_triggers.php`:
  `O:` lookup = serialize_lock-bracketed → FRESH context (counter-receipt:
  decode fails because `r:3` hits an int); `E:` = SHARED (decode succeeds,
  `r:3` → the autoloader's `Pin`); **`E:` inside a php-handler SESSION decode
  = SHARED** — `$_SESSION['k2']` resolves onto the autoloader's object
  inside `session_start()` (session decode registers a level-1 context, the
  unbracketed E: lookup shares it). Same on 8.5.12 and php-fixed (b4a63ec
  absent from both). This is a new sharing surface and feeds shape 8.

**Escalation (what the sharing DOES buy)** — `shape5_e_boundary.php`: the
INNER pushes count toward the SHARED entries-chain boundary and the INNER
result slot delivers a destructor INTO the outer walk:

```
outer a:3:{ E: ... } (2 pushes) + autoloader unserialize a:1014:{D + 1013 ints}
(1015 pushes) + 2 outer ints = 1019 > VAR_ENTRIES_MAX(1018)
=> chained entries block allocated during the INNER call, freed first at the
   outer var_destroy; walk releases the inner result slot -> zend_array_destroy
   -> D::__destruct (unbracketed, level==1) -> re-entrant unserialize takes the
   REUSE branch -> var_push into the freed 8160-byte block.
```

Receipts (`shape5_receipts.log`):
- **asan2: `AddressSanitizer: heap-use-after-free` READ var_unserializer.c:906**
  in `php_var_unserialize` (the re-entrant `(*var_hash)->last` deref), stack
  `var_destroy:319 → zend_array_destroy → D::__destruct → zif_unserialize`;
- control (filler 1012, total 1018): clean on asan2;
- **plain2 + glibc (`USE_ZEND_ALLOC=0`): SIGSEGV, core dumped**;
- **fixedasan: clean** — the 08f4b64 reorder makes the walk destructor's
  unserialize FRESH (the destroy-walk entry closes);
- master/8.5.13 head: b4a63ec brackets the E: lookup → no sharing at all.

Honest verdict: no decode-time dangling exists through this path (the pin
holds by construction); the sharing's memory-safety escalation is a new
ENTRY into the destroy-walk UAF family — E:-sharing + inner-push boundary +
shared-slot destructor — live on 8.5.12 (ASAN + SEGV receipts), closed by
08f4b64, while the id-confusion/GH-23981 sharing itself survives on php-fixed
until b4a63ec.

## MISSION 6 — php_binary serializer injection weapon: FULL RCE receipted on 8.5.12 AND jammy 8.1.2

`php_binary` = 1-byte key length + key + `php_var_serialize(value)`; it
validates nothing, so the pipe hides in the VALUE, inside `s:LEN:"..."`. The
`php` reader splits at the FIRST `|` regardless of encoder and unserializes
the remainder; the leftover wrapper tail fails the decode →
`php_session_cancel_decode` → destroy — after `__wakeup`/`__destruct` have
already run with attacker properties.

Two delivery modes, both receipted end-to-end
(`shape6_binary_weapon.sh` → `shape6_8512.log`, `shape6_812.log`):
1. ini-level `php_binary` writer (`shape6_writer.php`) + `php` reader
   (`shape6_reader.php`) — the mixed-handler deployment shape;
2. hand-crafted file planted directly (python crafter: `\x09 userprefs
   s:LEN:"inj|O:14:"DeferredWriter":..."` ) — no writer request at all.

Gadget = `DeferredWriter` (`__wakeup`+`__destruct` → arbitrary file write).
Receipts per build: decode warning + **shell written inside `session_start`**
+ WAKE6/DEST6 markers + dropped `shell6.php` executed →
**`uid=0(root)` + kernel string on BOTH 8.5.12 and 8.1.2-1ubuntu2.27**
(5/5 PASS lines on 8.5.12, all-PASS on 8.1.2). Distinct from the php_serialize
variant (A0/A5): different format, different injection position (value-side
pipe vs key-side), same POP outcome.

## MISSION 7 — serialize_lock tripwire / reorder windows on the fixed tree: NO window (receipted)

- **Data-clear → walk window**: none. Between `BG(unserialize).data = NULL;
  --level` and `var_destroy(&d)` there is no user code (straight-line C).
  Receipt pair for what a walk destructor sees instead
  (`shape7_lockbranch.php`, `shape7_receipts.log` 7a): same input, the
  walk-time destructor's re-entrant decode resolves ids **SHARED into the
  outer chain on stock 8.5.12** (`context=SHARED (outer id!) MissQ1`) vs
  **FRESH on fixedasan** — the reorder demonstrably clears the context before
  any walk user code.
- **Lock branch ("frees immediately at any level")**: deepest legal nesting
  built and receipted on both trees — outer registered call → E: unbracketed
  → REUSED inner call (level 2) → O: bracketed lookup (lock=1) → under-lock
  call W (fresh, unregistered, level untouched) → W's destroy UNDER LOCK at
  level 2 (the branch in question) with a delayed-`__wakeup` (lock 2) and a
  slot destructor (ambient lock 1) each re-entering unserialize. Every level
  self-consistent, ASAN clean on both trees.
- **exit() mid-walk**: DEAD BY DESIGN on 8.5.x. `shape7_strand_exit.php` +
  gdb (`shape7_diag3.gdb`): the destruct provably runs at the walk
  (`shape7_phase.php` marker `phase=in-outer-call`), but 8.4+ unwind-exit
  lets the C-level destroy COMPLETE — at `php_call_shutdown_functions`:
  `lock=0 level=0 data=(nil)` on BOTH trees; the shutdown unserialize is
  FRESH and decodes cleanly. The "obvious" strand producer cannot strand.
- **OOM mid-walk** (`shape7_oom_walk.php`, ZendMM, limit enforced): the
  delayed-OOM machinery defers the bailout past the destroy tail (var_destroy
  itself checks `ZEND_HAS_OOM()` and marks later slots DESTRUCTOR_CALLED);
  state clean at shutdown on plain2 AND fixedasan.
- A call inited at lock==0 can never destroy at lock>0: the only lock-raisers
  are brackets that strictly nest inside the call (verified in source:
  `BG(serialize_lock)` writers are only the delayed-wakeup/unserialize
  brackets in var_destroy and the O:/C: lookup brackets).

Verdict: 08f4b64's reorder holds against every interleaving constructible
here; the fixed tree's residual issues remain the leak/destructor-bypass
family already filed as FC-3 (low tier).

## MISSION 8 — jammy fleet composition weapon: ALL FOUR STAGES FIRED on Ubuntu 8.1.2 Apache

`shape8_jammy_fleet.sh` (single script, lab in /tmp/shape8, Apache 2.4.52
prefork mod_php 8.1.2-1ubuntu2.27, receipts `shape8_jammy.log`):

1. **session-wipe** — victim session established (`keep|s:6:"keepme";
   uid|i:4242;`, 29 bytes) → unauthenticated multipart with pipe key
   (`upload_progress_wipe|me`) → invalid-key reject → **victim file truncated
   to 0 bytes**. PASS.
2. **INI-UAF** — unauth nameflood arm (24×262144B filenames, memory_limit=8M
   per-dir) → pre-RINIT `Allowed memory size of 8388608 bytes exhausted ... in
   Unknown on line 0`, child survives → stale-status oracle fires on the next
   requests (`Session ini settings cannot be changed when a session is
   active` ×2) — the per-dir-restore block whose consumer reads
   `session.save_path` from freed-and-reused memory (the corrupted-path
   artifact `open(upload_progress_/sess_...)` is the LC reference receipt,
   `receipts_8512/lc_session_state/apache812_ap2_error.log`).
3. **session-gap injection** — through the wiped gap, unauth multipart to the
   `php_serialize` write dir with key `k|a:1020:{...}` → **poisoned session
   planted** (12442 bytes on disk, `upload_progress_k|a:1020:{i:0;
   O:8:"KillDtor"...` visible in the hexdump). PASS.
4. **zero4 fire** — victim read request (default `php` handler):
   `KillDtor::__destruct fired at session-decode walk`, re-entrant
   unserialize → **Apache child DEAD** (worker inventory 0; `apache2 -X` is
   single-process so the segfault takes the server) inside `session_start()`
   on the stock jammy build.

Stage-4 memory-safety receipts on the instrumented builds
(`shape8_asan_receipt.php` → `shape8_asan_receipts.log`):
- **asan2 (8.5.12): `heap-use-after-free var_unserializer.c:906`** through
  `var_destroy:319` — the destroy-walk re-entry UAF fired INSIDE
  `session_start()` through the poisoned session;
- **fixedasan: clean** (the decode even succeeds; destruct fires safely);
- **system 8.1.2 CLI + glibc: SIGSEGV (exit 139)**.

The composition is the full unauthenticated chain for the never-patched
Ubuntu 22.04 fleet: wipe → stale-state INI corruption → gap injection →
in-session UAF, one script, every stage receipted.

---

## File index (poc_matrix/ unless noted)

- Shape 5: `shape5_a_unset.php` `shape5_b_replace.php` `shape5_c_gc.php`
  `shape5_d_triggers.php` `shape5_e_boundary.php` `shape5_run.sh` →
  `receipts_8512/shape5678/shape5_receipts.log`
- Shape 6: `shape6_writer.php` `shape6_reader.php`
  `shape6_binary_weapon.sh` (+`shape6_debug.php`) → `shape6_8512.log`
  `shape6_812.log`
- Shape 7: `shape7_lockbranch.php` `shape7_strand_exit.php`
  `shape7_oom_walk.php` `shape7_phase.php` `shape7_run.sh`
  `shape7_oom_run.sh` `shape7_diag.gdb` `shape7_diag2.gdb`
  `shape7_diag3.gdb` → `shape7_receipts.log` `shape7_oom_receipts.log`
- Shape 8: `shape8_victim.php` `shape8_reader.php`
  `shape8_asan_receipt.php` `shape8_poison_debug.php`
  `shape8_jammy_fleet.sh` `shape8_asan_run.sh` `shape8_ini_probe.sh` →
  `shape8_jammy.log` `shape8_asan_receipts.log` `shape8_ini_probe.log`
