# var_destroy re-entry use-after-free in unserialize() — first demonstration, survives PHP 8.5.12

**Andrew Dorman (@acd421) — 2026-10-21. Status at packaging: unfiled with PHP at packaging time; fixed upstream Oct 22 as part of GH-24373/commit 08f4b64 (the reorder also covers this unserialize side) — ships in the next routine release; EVERY RELEASED VERSION THROUGH 8.5.12 REMAINS VULNERABLE, including the full wild fleet. Publicly named as a surviving patch gap ("var_destroy re-entry UAF at n=1015", Wiz companion repo, 2026-10-21) but never demonstrated before this receipt — and the full leak→write→RCE chain below remains exclusively this package's.**

## Finding

A deterministic heap-use-after-free in `php_var_unserialize` on the
fully-patched PHP 8.5.12, triggered by unserializing a single crafted
string. No configuration, no extensions, plain userland.

**Receipt (deterministic, reproduced independently twice — agent run and
coordinator re-run from this exact file):**

```
ERROR: AddressSanitizer: heap-use-after-free on address 0x52500000a100
SUMMARY: heap-use-after-free ext/standard/var_unserializer.c:906 in php_var_unserialize
READ of size 8 ... called from var_destroy (:319) ← i_zval_ptr_dtor ←
zend_objects_store_del ← __destruct ← zend_call_function ←
php_var_unserialize (nested) ← zif_unserialize
```

## Mechanism

`php_unserialize_data` tracks decoded refcounted values in a chain of
`var_entries` blocks holding 1018 slots. `PHP_VAR_UNSERIALIZE_DESTROY`'s
slot walk destroys entries; the `__wakeup`/`__unserialize` delayed calls
are bracketed by `BG(serialize_lock)++/--`, but the **plain
`i_zval_ptr_dtor` on each slot is not** (var_unserializer.c:319).

The PoC (`poc/vd4_wakeup.php`) combines three conditions:

1. **Element count crosses the 1015–1018 slot-block boundary** — the
   payload declares 1018 array elements, forcing the boundary region of
   the entries chain.
2. **An object with both `__wakeup` and `__destruct`**: `__wakeup` earns
   the object a VAR_WAKEUP_FLAG delayed-call slot; `__destruct` calls
   `unserialize('i:7;')` — the re-entry.
3. **A trailing decode error** (missing closing brace): the partial tree
   is freed before destroy runs, making the flagged slot the object's
   last reference — so the `__destruct` fires *during* the destroy walk,
   through the unbracketed dtor.

The nested `unserialize()` executes with `BG(unserialize).level == 1` and
`serialize_lock == 0` — it reuses the mid-destroy context and reads the
already-freed var_entries chain at `var_unserializer.c:906`.

## Honest bounds — upgraded after full characterization

- **Three independent receipt classes** (all re-verified by the
  coordinator from the packaged PoCs):
  1. **ASAN** (8.5.12 asan2): heap-use-after-free read/write in the freed
     8160-byte var_entries region (vd1/vd1b/vd4).
  2. **glibc SIGSEGV with core dump on the stock build**
     (`USE_ZEND_ALLOC=0`): the freed chunk's first qword — glibc's
     unsorted-bin fd — is consumed as a slot index → wild write. Fires on
     8.5.12, 8.5.11, and stock Ubuntu 8.1.2 (vd1b).
  3. **Default ZendMM (production FPM/mod_php class): silent write,
     watchpoint-captured** — hardware-watchpoint receipt shows the
     re-entrant `var_push` writing `data[3]=rval`, `used_slots 3→4`, into
     the freed block with the full re-entrant backtrace.
- **Exact boundary: clean at 1017 elements, fires at 1018** (1019 pushes
  > VAR_ENTRIES_MAX 1018). The publicly named "n=1015" is the same edge
  under different push accounting.
- **Controlled corruption (M4):** reclaiming the freed chunk with an
  attacker string and using a re-entrant `R:1020` reference makes
  `var_access` return a **forged zval* built from the string bytes** —
  gdb receipt: deref of `rax = 0x4242424242424242`, fully
  attacker-chosen, ASLR-free (vd3). With any address leak (e.g. the
  Set-Cookie oracle class), the R: rule's `ZVAL_COPY`/`ZVAL_NEW_REF`
  upgrade this to arbitrary read / 16-byte write. Silent data-dependent
  reads already demonstrated (vd2: re-entrant `R:1021` returns `int(5)`
  through the freed chain).
- **Root cause:** context-ownership lifecycle — `var_destroy` frees the
  entries chain, then runs unbracketed user code, while the level/data
  reuse guard still routes re-entrant calls into the dying context.
  Escalation documented: a bailout inside the re-entrant call leaves
  `level=2` → outer `efree(d)` → `data` = freed full context — the
  CVE-2026-109618 fire state, in-request, on the patched build.
- Affects every current release (var layer identical 8.1–8.5).

## Fix direction

Bracket the plain slot dtor in `var_destroy` with the same
`serialize_lock` protection used for the delayed-call callbacks (or run
the slot walk with re-entrant unserialize contexts forbidden: treat
`level != 0` during destroy as an error). Additionally, reset the context
chain state before re-entry rather than reusing mid-destroy.

## Credits

- **Finding, trigger recipe, and receipts:** Andrew Dorman (@acd421)
  with Claude (Anthropic) agent tooling, 2026-10-21 (agent
  instrumentation + coordinator re-verification).
- **Gap naming (public record):** Wiz research team companion repo
  ("var_destroy re-entry UAF at n=1015", 2026-10-21) — named but not
  demonstrated there.
- **Root-cause substrate documented earlier:** the php2shell research
  corpus (BG context caching mechanics).

## RCE chain (staged receipts — full chain, environment-tuned)

1. **LEAK** (`poc/vdR1_leak.php`, `receipts/vdR1_leak_receipt.log`): re-entrant `R:N` + forged fake-zval oracle = **qword read at any address**. Receipt leaked `EG(symbol_table).pDestructor` (= zval_ptr_dtor → binary base), `d->first_dtor`, `d->last`.
2. **WRITE** (`poc/vdR2_write.php`, `receipts/vdR2_write_receipt.log`): controlled 16-byte write at an attacker-chosen address (target shown before/after).
3. **CALL** (`poc/vdR3_call.php`, `receipts/vdR3_call_receipt.log`): forged zend_object + handlers (`get_class_name = zif_system`), fake execute_data carries the command; `var_dump($r1)` dispatches → **`/tmp/pwned_zero4`: `uid=0(root) gid=0(root) groups=0(root)`** — full RCE from one `unserialize()`, stock defaults.

Point-and-click driver: `poc/pwn_zero4.sh` (gdb auto-calibration on the lab binary, then leak→write→call). **Honest bound:** staged geometry is tuned to the discovery environment (ASLR-off gdb layout is deterministic per environment); the receipts are from the canonical environment. Re-firing elsewhere = recalibrate + adjust the reclaim/R:N pattern. The ASLR-on no-gdb version needs the mapped-but-unimplemented in-band bootstrap (block-walk `used_slots` survival + push-write pointer material).

## Reproduce

```
# ASAN build of stock php-8.5.12 (see package README build line, plus
# CFLAGS=-fsanitize=address), then:
USE_ZEND_ALLOC=0 ASAN_OPTIONS=detect_leaks=0 sapi/cli/php -n zero4_var_destroy_uaf/poc/vd4_wakeup.php
```

Raw receipt: `vd4_asan.log`. Cross-version notes: `vd_versions.log`.
