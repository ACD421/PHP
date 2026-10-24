# VD_STATUS — var_destroy re-entry UAF (Wiz "n=1015" gap) — REPRODUCED on 8.5.12

Date: 2026-10-21. Builds: /tmp/php8512_build/{plain2,asan2} (8.5.12),
/tmp/php8511_build/out (8.5.11), distro php 8.1.2 Ubuntu.

**VERDICT: the bug is real, reproducible, and reachable from a plain
`unserialize()` of attacker data with no error path required. ASAN UAF
receipt + glibc SEGV receipt + default-ZendMM silent-corruption watchpoint
receipt + controlled-deref (0x4242424242424242) receipt. Fires on 8.5.12,
8.5.11, and stock Ubuntu 8.1.2 — the var layer is unchanged since 8.1.
BONUS: the serialize-side mirror (zend_hash_destroy re-entry) also
reproduces with an ASAN receipt (vd6) — see bottom section.**

## M1 — exact boundary condition (line-level)

Structures (ext/standard/var_unserializer.re, generated .c line numbers):
- `php_unserialize_data`: `{last, first_dtor, last_dtor, allowed_classes,
  ref_props, cur_depth, max_depth, incomplete_classes_only, entries}` where
  `entries` is the EMBEDDED first `var_entries` (VAR_ENTRIES_MAX=1018 zval*).
- `var_entries {used_slots, next, data[1018]}` = 8160-byte heap block when
  chained; `var_dtor_entries {used_slots, next, data[255]}` (16-byte zvals).

Broken invariant — three source facts compose:

1. var_destroy (.c:242, .re ~230) frees the chained entries blocks FIRST:
   `var_hash = entries.next; while (var_hash) { next=var_hash->next;
   efree_size(var_hash); ... }` — after this loop `d->last` points at FREED
   memory whenever total pushes > 1018.
2. The dtor-slot walk that follows runs user code UNBRACKETED: for each
   slot, `i_zval_ptr_dtor(zv)` (.c:319) — when the slot holds the LAST ref
   of an object, its `__destruct` executes with `BG(serialize_lock)==0`.
   (The delayed `__wakeup`/`__unserialize` calls above it ARE bracketed;
   the slot free is not.)
3. `php_var_unserialize_destroy` (.c:91) runs `var_destroy` + `efree(d)`
   BEFORE decrementing `BG(unserialize).level` — so during the whole walk
   `level==1 && data==d` and any re-entrant `unserialize()` takes the
   REUSE branch of `php_var_unserialize_init` (.c:66: `else { d =
   BG(unserialize).data; ++level; }`) and pushes into the dying context.

The first re-entrant decoded value then executes `var_push` (.c:143:
`var_hash->data[var_hash->used_slots++] = rval`) with
`var_hash = (*var_hashx)->last` = freed block → **UAF read (used_slots) +
write (data[used_slots]) into the freed 8160-byte chunk**; `R:n` payloads
instead take `var_access` (.c:231) which walks the freed `.next` chain and
returns `data[id]` = fully attacker-controlled 8 bytes if the chunk was
reclaimed.

**How an object becomes slot-owned (last ref = dtor slot):**
- (a) duplicate-key/property overwrite: `var_push_dtor_value` (.c:513/.re
  ~506-516, 658-701) takes OWNERSHIP of the overwritten value
  (`ZVAL_COPY_VALUE`, hash slot NULLed, no addref) — vd1/vd1b/vd2/vd3 use
  a plain duplicate array key. Works with decode SUCCESS (no error path).
- (b) `__wakeup` flag slot (.c:898): trailing decode error frees the tree
  pre-destroy; the WAKEUP-flagged slot is the last ref; wakeup runs
  bracketed, then the unbracketed slot free fires `__destruct` — vd4.

**Boundary (empirical sweep, vd_sweep.log):** flat `a:N:{...}` with the
dup-key pair at the end: clean at N=1017, UAF at N=1018 (total var_push
count = 1 + N = 1019 > VAR_ENTRIES_MAX=1018). The Wiz "n=1015" is this
same edge under their push accounting. Every payload element (non-`R:`)
pushes — including integers.

## M2 — receipts

ASAN (asan2, `USE_ZEND_ALLOC=0 ASAN_OPTIONS=detect_leaks=0`):
- vd1_asan.log, vd1b_asan.log (success-path, no decode error),
  vd4_asan.log (wakeup-slot variant):
  `AddressSanitizer: heap-use-after-free READ of size 8` — 0 bytes inside
  the freed 8160-byte region; stack: `var_destroy:319 → i_zval_ptr_dtor →
  zend_objects_destroy_object → __destruct → zif_unserialize →
  php_var_unserialize:906`. SUMMARY:
  heap-use-after-free var_unserializer.c:906 in php_var_unserialize.
- plain2 + glibc (`USE_ZEND_ALLOC=0`): **SIGSEGV, core dumped** (rc=139) —
  freed chunk's first qword is glibc's unsorted-bin fd → `data[fd]` wild
  write. Same SEGV on 8.5.11 and distro 8.1.2 (vd_versions.log).
- plain2 default ZendMM (FPM/mod_php real-world config): SURVIVES
  silently — hardware-watchpoint receipt (vd_watch.gdb run log in
  VD_STATUS section below): `var_push:143` writes `data[3]` =
  0x7ffff54be020 into the freed block, used_slots 3→4, full re-entrant
  backtrace captured. No detector fires — deterministic silent heap
  corruption.

## M3 — root cause (which invariant breaks)

Not slot accounting and not the block chain per se: the **ownership
lifecycle of the shared context** is the flaw. `var_destroy` frees the
entries chain and then executes unbracketed user code (slot destructors),
while the context-global reuse guard (`BG(unserialize).level==1` +
`data==d`) still ROUTES re-entrant unserialize() calls into the dying
context. Any push/access from that re-entrant call operates on freed
chain blocks. The nested destroy itself is balanced (level 2 → no
var_destroy, no efee) — the UAF is confined to the freed entries blocks
(and, after reclaim, whatever live object reoccupies the chunk).

Corollary: a bailout (OOM/timeout) inside the re-entrant call leaves
`level==2`; the outer destroy then efrees `d` and decrements to 1, so
`BG(unserialize).data` = freed 8208-byte php_unserialize_data → the NEXT
unserialize() in the request reuses a FULLY freed context (the
CVE-2026-109618 "fire" state, now reachable in-request). Not needed for
the receipts; documented as escalation.

## M4 — controlled corruption (receipts)

- vd2_readchain.php (plain, default ZendMM): re-entrant `R:1021;`
  resolves THROUGH the freed block and var_dumps `int(5)` — data-dependent
  read-after-free, silent, deterministic.
- vd3_reclaim.php (plain, default ZendMM): destructor first reclaims the
  freed 8160-byte chunk with `str_repeat('B', LEN)` (LEN ≤ 8159 → same
  ZendMM page bin), then re-entrant `R:1020;` → `var_access` reads
  `used_slots` from the string's gc word (huge → walk stops at reclaimed
  block) and `data[1]` from string payload bytes → forged `zval*` =
  0x4242424242424242 → `Z_TYPE_P` deref. gdb receipt (vd3_fault.gdb):
  `=> cmpb $0xa,0x8(%rax)` with `rax=0x4242424242424242` — deref of a
  fully attacker-chosen address, ASLR-independent. With a valid pointer
  instead, the R: rule's `ZVAL_COPY`/`ZVAL_NEW_REF` turn this into
  zval-copy-from-arbitrary-address (read) and a 16-byte write primitive.
- Length sweep vd3_sweep.log: LEN 8000-8159 → SIGSEGV every time; LEN
  ≥8165 → no reclaim (clean) — bin edge between 8184 and 8190 byte allocs.

## Files (poc_matrix/)

- vd1_dupkey.php / vd1b_dupkey_ok.php — minimal dup-key PoCs (error path /
  success path)
- vd2_readchain.php — freed-chain R: read proof
- vd3_reclaim.php + vd3_sweep.sh/.log + vd3_segv.gdb / vd3_fault.gdb —
  controlled-deref receipts
- vd4_wakeup.php — __wakeup-slot variant (ASAN receipt vd4_asan.log)
- vd_sweep.sh / vd_sweep.log — boundary sweep (clean ≤1017, fire ≥1018)
- vd_versions.sh / vd_versions.log — 8.5.12 / 8.5.11 / 8.1.2 SEGV matrix
- vd_watch.gdb — silent ZendMM write receipt
- vd_trace.gdb — lifecycle tracer (INIT/DESTROY/var_destroy chains)
- vd1_asan.log, vd1b_asan.log, vd1b_plain.log, vd1b_plain_glibc.log,
  vd1b_8511.log, vd1b_812.log, vd4_asan.log

## Fix direction (for the eventual report)

Bracket the slot destruction too (`BG(serialize_lock)++` around the
`i_zval_ptr_dtor(zv)` in the walk), or invalidate the reuse guard before
freeing anything in `php_var_unserialize_destroy` (set
`BG(unserialize).data=NULL` + level such that re-entrant INIT allocates a
fresh context for the duration of `var_destroy`). Serialize side needs the
mirror-image review (see below).

## BONUS — serialize-side analog (suspect c): REPRODUCED (vd6)

Same class on the encode side, mirrored through the HashTable instead of
the entries chain:

- `php_add_var_hash` (var.c:753-801) PINS serialized objects in the
  context ht (`zend_hash_index_add_new(key+1, var); Z_ADDREF_P(var)`)
  when they don't meet the skip condition (rc>1, or __sleep/__serialize,
  etc.).
- `php_var_serialize_destroy` (var.c:1426) runs `zend_hash_destroy(&d->ht)`
  (dtor = ZVAL_PTR_DTOR) while `BG(serialize).level==1` and
  `data==d` → context reuse still admitted.
- Trigger (vd6_carrier.php): serialize `[$p1, $carrier]` where P1 holds
  the same D object in two props (rc 2 at walk → pinned, rc 3) and
  Carrier::__sleep NULLS P1's props (object props → NO COW, unlike the
  $GLOBALS write in vd5 which detached a copy and left the original
  alive on the VM arg stack). After __sleep, D's last ref is the pin.
- At `zend_hash_destroy`, the D-pin bucket release fires D::__destruct
  INSIDE the destroy loop → re-entrant serialize() takes the REUSE
  branch (level==1) → its inserts land in the SAME ht the destroy loop
  is iterating. With ≥6 nested distinct objects (each rc 2 → pinned,
  2 buckets each; 4 pre-existing + 2N ≥ nTableSize=16) the insert
  RESIZES arData → erealloc frees the old block mid-iteration → the
  destroy loop keeps iterating the FREED arData.
- Receipt (vd6_asan.log): `AddressSanitizer: heap-use-after-free READ`
  in `i_zval_ptr_dtor ← zval_ptr_dtor ← zend_hash_destroy
  (zend_hash.c:1985) ← php_var_serialize_destroy (var.c:1429) ←
  zif_serialize` — 265 bytes inside the freed 640-byte old-arData
  region. Boundary sweep (vd6_sweep.log): clean at N=5, fires at N=6.
- 8.5.11 and distro 8.1.2 under glibc: re-entry occurs (hits=1) but
  survives silently — the freed old arData stays readable, so the
  destroy loop reads garbage type bytes without crashing; ASAN is the
  detector. (The unserialize side crashes hard on glibc instead,
  because the freed chunk's first qword is the unsorted-bin fd used as
  a slot index.)
- vd5*.php document the failed approaches: vd5b (stray local ref —
  destructor never fired), vd5c (destructor fired but at VM arg cleanup,
  AFTER the destroy, because $GLOBALS writes COW-detach; backtrace
  receipt: zend_vm_stack_free_args), vd5d (resize forced but COW
  prevented the mid-destroy release).
