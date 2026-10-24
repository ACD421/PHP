# What PHP's 2026-10-21 patch actually fixed — verified defense map of 8.5.12

**Andrew Dorman (@acd421) — 2026-10-21. Companion analysis to zero1/zero2: the mirror-image finding — where the patch genuinely holds, with gdb receipts for every closed path.**

## The patch

`3584a98` "Avoid state corruption via bailout" (arnaud-lb, iluuu1994,
bukka, ndossche) — 8.2.35/8.3.36/8.4.27/8.5.12. Fixes
GHSA-w8hw-w9fx-j79w (CVE-2026-109618) + GHSA-6wmf-4rv5-p3rp
(CVE-2026-109619). Reporters credited: lcfr-hax, sagitzadik-wiz,
tomash-areion, amyb-oai. Root cause known to the Foundation since 2024
(Calif audit Jul 30; Ryan A unconditional RCE Aug 11; OpenAI same day;
Wiz Aug 24).

## Three defense layers (source + gdb verified)

1. **OOM no longer longjmps mid-context.** Engine-wide UnwindExit /
   fallible-alloc rework (`array_finit`, `RETURN_OOM()`, `EG(delayed_oom)`,
   `ZEND_HAS_OOM()`); soft OOM surfaces at the next VM safe point; hard
   OOM `_exit()`s. Multipart hardening closes the reach-any-config tricks
   (no-content-length post_max_size bypass, unbounded per-part headers,
   empty uploads not counting).
2. **State reset before the pre-RINIT consumer.** New
   `php_basic_early_rinit()` (main.c:1939, before `php_hash_environment`
   at :1976) memsets `BG(serialize)`/`BG(unserialize)` + clears
   `serialize_lock` every request — the cross-request orphan through the
   rfc1867 window is dead.
3. **Consumer hardening.** The rfc1867 decode runs
   `incomplete_classes_only` (no autoload / unserialize_callback_func /
   __wakeup pre-RINIT — "no user code may run").

## Verified closed (p1–p9 receipt matrix, plain+ASAN builds, gdb-traced)

- Timeout in a pure C serialize/unserialize walk: **graceful** — destroy
  runs, the fatal is delayed to the next VM opcode (gdb trace: balanced
  INIT/DESTROY pairs, fatal printed after; 12M-object decode receipt).
- Bailout inside the `serialize_lock` brackets (`__sleep`, `__wakeup`,
  `__unserialize`, `unserialize_callback_func` — timeout/E_USER_ERROR):
  the lock leaks to ≥1 which then **disables context caching for the rest
  of the request** — a tripwire that makes dangling-context reuse
  structurally impossible in-request.
- require-failure inside those callbacks: an exception in 8.5 (returns
  through C, brackets run — no corruption).
- `__wakeup` exceptions during the delayed destroy walk: handled
  (delayed_call_failed path).
- `__destruct` re-entry into a mid-destroy context (1020-object dtor
  storm): stayed balanced.
- Double fatals (fatal in shutdown function after a first fatal,
  fatal_error_backtraces store-over-store): clean on both plain and ASAN.
- The allocator backstop: `ZEND_MM_HEAP_PROTECTION` per-slot shadow keys
  (64-bit random per heap) turn same-bin double-frees into alloc-time
  panics (see zero2) — crash, not silent aliasing, on stock builds.

## What survives (see zero1/zero2)

The session serialize-format logic layer (zero1: mismatch + key injection
+ wipe) and the GC/garbage-buffer ownership layer (zero2: the GH-24050
regression family) — neither is a bailout-path bug, so the patch's three
layers do not touch them.

## Why this map matters

It bounds the threat honestly: the October class is closed where the
patch aimed, and open exactly where it didn't look — format/ownership
logic, not memory-bailout mechanics. Defenders triaging today should
prioritize: (1) serialize_handler uniformity audits, (2) upload_progress
disablement, (3) extension get_gc ownership review, (4) XML-parser input
surfaces until the GC regression patch lands.

## Credits

Patch analysis, gdb verification matrix, and receipts: Andrew Dorman
(@acd421) with Claude (Anthropic) agent tooling, 2026-10-21. Patch author
team and original reporters as credited above. Wiz companion repo for the
surviving-gap names this map corroborates.
