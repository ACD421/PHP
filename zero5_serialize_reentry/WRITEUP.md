# php_var_serialize_destroy re-entry use-after-free — the serialize-side mirror, first demonstration

**Andrew Dorman (@acd421) — 2026-10-21. Status at packaging: fixed upstream Oct 22 (GH-24373, commit 08f4b64 — the same fix reorders BOTH destroy functions to clear the context pointer before the walk); ships in the next routine release. Every released version through 8.5.12 remains vulnerable. Discovery credit for the serialize-side class: janhelke (GH-24373, filed 2026-10-16 as a TYPO3 crash, five days before this independent derivation); our contribution: the ASAN receipt, the pin-method characterization (incl. the negative COW/$GLOBALS shapes), the 5→6 boundary, and the escalation work. Unnamed in the Wiz gap list (which covered only the unserialize side).**

## Finding

A heap-use-after-free in `php_var_serialize_destroy` on fully-patched PHP
8.5.12 (and 8.5.11, 8.1.2 — the serialize var layer is unchanged across
branches), triggered by serializing a crafted object graph from plain
userland. Mirror of zero4's unserialize-side bug, in the *serialize*
destroy path, with a distinct mechanism: **mid-iteration arData
reallocation through re-entrant user code**.

**Receipt (re-verified independently by the coordinator from the packaged
PoC):**

```
ERROR: AddressSanitizer: heap-use-after-free
SUMMARY: heap-use-after-free Zend/zend_variables.h:42 in i_zval_ptr_dtor
  ← zend_hash_destroy (:1985) ← php_var_serialize_destroy (:1429)
```

## Mechanism

1. An object is pinned as **last reference inside the serialize
   context's HashTable** (`d->ht`) — pin via a refcount≥2 encounter
   during serialization plus a `__sleep` that nulls the object's other
   property references (direct `$GLOBALS` writes fail COW-detection and
   do NOT work; object-property nulling does — receipts vd5b–vd5e
   document the failed shapes).
2. `php_var_serialize_destroy` → `zend_hash_destroy(&d->ht)` releases the
   pinned object last-ref → **`__destruct` executes inside the destroy
   loop**.
3. The destructor calls `serialize()` — re-entrant, `BG(serialize).level
   != 0` → the context is **reused**; the re-entrant serialize inserts
   new entries into the hash being destroyed.
4. ≥6 nested objects in the re-entrant payload force an **arData
   erealloc mid-iteration**; the outer destroy loop keeps walking the
   freed old arData.

**Boundary: clean at 5 nested objects, fires at 6** (arData growth step
crosses the allocation boundary — receipts `vd6_sweep.log`).

Silent under glibc on 8.5.11/8.1.2 (no tcache hit in this shape);
ASAN-deterministic on 8.5.12.

## PoC

`poc/vd6_carrier.php` — object graph with the `__sleep`-pinned carrier
whose destructor re-enters `serialize()` with a 6-deep nested payload.
Reproduce:

```
USE_ZEND_ALLOC=0 ASAN_OPTIONS=detect_leaks=0 sapi/cli/php -n zero5_serialize_reentry/poc/vd6_carrier.php
```

## Fix direction

Same family fix as zero4: never execute user code (object release) inside
`php_var_serialize_destroy`'s hash walk with the context still
re-usable — invalidate the `BG(serialize)` reuse guard (or detach the
hash) before `zend_hash_destroy`, and/or bracket releases with the
serialize_lock discipline used elsewhere.

## Credits

Finding, boundary characterization, pin-method discovery (including the
negative COW/GLOBALS receipts), and ASAN receipt: Andrew Dorman
(@acd421) with Claude (Anthropic) agent tooling, 2026-10-21;
coordinator re-verified the packaged PoC. Substrate (var-layer context
mechanics) documented in the php2shell corpus; unserialize-side sibling
publicly named (not demonstrated) by the Wiz companion repo.

## RCE CHAIN — COMPLETE (2026-10-23): full RCE on released 8.5.12, stock defaults

Plain userland serialize() -> self-reclaim -> forged object -> zif_system.
Receipt: /tmp/pwned_zero5 = uid=0(root) (wrapper pwn_zero5.sh PASS twice).

- M1 self-reclaim (sr2_m1.log): the re-entrant serialize Groomer __sleep
  str_pad allocation (first alloc of any size after the efree) lands on
  the freed old-arData; zend_hash_do_fresize frees it mid-walk
  (watchpoint-proven, backtrace through php_var_serialize_call_sleep).
- M2 byte correlation (sr2_m2_41/beef.log): walked bucket-4 val = groom
  bytes; fault at zval_ptr_dtor+13 with rdi following the chosen marker.
- M3 controlled call (sr2_m3.log): fake zend_object + handlers
  (dtor_obj = zif_system) + fake execute_data (num_args at +44, arg1 =
  "sh /tmp/e") inside the groom string head; zif_system invoked from
  zend_objects_store_del inside the destroy walk. Default ZendMM (the
  FPM/mod_php config), no error path, no gdb in the fire.
- Wrapper: poc/pwn_zero5.sh (discovery -> receipts -> call -> marker).
  Env-drift root cause: script-path FORM (absolute vs relative) shifts
  startup allocations one ZendMM page; wrapper pins the relative form.
- Post-fix (08f4b64): verified to close both sides (sr3 logs); the
  surviving post-fix issue is the timeout-bailout leak class only
  (both contexts leaked, lock stuck at 1, level/data dangling through
  shutdown — LSan receipt sr3_timeout_lsan.log).

Credit: class discovery janhelke (GH-24373); the self-reclaim escalation
to zif_system and the fleet receipt are this package (acd421,
agent-assisted).
