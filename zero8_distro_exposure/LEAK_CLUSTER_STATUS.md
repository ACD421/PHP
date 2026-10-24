# LEAK_CLUSTER_STATUS.md — the PS_* session-state cluster on fully-patched PHP 8.5.12

**2026-10-23/24. Lane: LC (session-state cluster only; no overlap with vd-boot /
ser-rce2 / fresh-code / wipe2 / mongo-hunter).**

## Executive verdict

**The dangling session-state family is CLOSED on 8.5.12.** Every producer class
that could previously bail out of the rfc1867 window mid-open (leaking the
flocked fd, PS(id), PS(session_status)=active, PS(http_session_vars),
PS(rfc1867_progress)) either no longer bails (flag-based OOM/timeout), is
routed through `MULTIPART_EVENT_END` cleanup (every parser early-exit), or
dies the process (hard OOM `_exit(137)`, hard timeout `_exit(124)`). Every
next-request consumer reads PS_* state only AFTER a reset that runs before it
(`MULTIPART_EVENT_START → php_rinit_session_globals()` for multipart,
session RINIT for everything else, `php_basic_early_rinit` memset for the
var-layer contexts). **The Wiz Set-Cookie heap-leak oracle does not
resurrect: PS(id) is NULLed before any cookie-emitting reader, and every
Set-Cookie observed in the matrix carried a fresh random 32-hex id.**

The same probes **DO fire on Ubuntu jammy 8.1.2-1ubuntu2.27** (jammy never
received the 2026-10 patch — changelog 2.27 stops at unrelated CVEs), and
that run also surfaced one **new artifact of the unpatched cluster: a
UAF-read in the INI layer** (stale-active blocks the per-dir ini restore →
`session.save_path` reads freed-and-reused request memory — observed holding
`"_SESSION"` and `"upload_progress_"`).

## 1. What the patch actually resets (8.5.12 source map)

| State | Reset point | Runs before any consumer? |
|---|---|---|
| BG(serialize)/BG(unserialize)/serialize_lock | `php_basic_early_rinit()` basic_functions.c:492, called main.c:1939 BEFORE `php_hash_environment()` (:1976) | yes (request start) |
| PS(id), PS(session_status), PS(mod_data), PS(http_session_vars), PS(in_save_handler), PS(session_vars), PS(in_rfc1867_update) | `php_rinit_session_globals()` session.c:111 — called at `MULTIPART_EVENT_START` (session.c:3232, "This runs before RINIT, so we need to clear these early") and at session RINIT (:2888) | yes: EVENT_START is the first event of every multipart parse; RINIT covers non-multipart; both precede every reader |
| PS(rfc1867_progress) | EVENT_START overwrites the pointer (`ecalloc` + store) without dereferencing the old value | yes (pointer never read pre-overwrite) |
| PS(send_cookie) | NOT in the reset list — but only read in `php_session_start`/`php_session_reset_id` with a PS(id) that is always NULL-or-live at that point | inert |
| flock'd sess fd | `php_session_save_current_state` always ends in `s_close` (even after write failure, session.c:~571); EVENT_END calls `php_rshutdown_session_globals` → `s_close`; decode-catch → `php_session_destroy` → close | yes — no producer can skip the close anymore (see §3) |

Notable hardening beyond the memsets: **`incomplete_classes_only` applies to
BOTH directions** (`php_session_unserialize_init` AND
`php_session_serialize_init`, session.c:958-975) and does a *full
no-class-lookup* decode (var_unserializer.c:1499 "Do not look the class up at
all") — so no `__sleep`/`__serialize`/`Serializable::unserialize`/`__wakeup`
call can occur inside the window, even for built-in classes (DOMNode::__sleep
is real C code but unreachable: every class becomes `__PHP_Incomplete_Class`,
incomplete objects re-serialize verbatim via `php_var_serialize_incomplete_raw`).

## 2. Why every bailout producer is dead on 8.5.12 (source + receipts)

- **Memory-limit OOM (the original CVE-109618 arm).** `zend_mm_check_limit`
  (zend_alloc.c:533): soft-limit exceed on an infallible alloc queues a
  *delayed* OOM (`EG(delayed_oom)=PENDING`, `vm_interrupt=1`) and the
  allocation SUCCEEDS up to the hard limit (2x memory_limit,
  zend_alloc.c:3130). The delayed error only becomes a bailout at a check
  site — `zend_call_function` (zend_execute_API.c:835/1083), VM interrupt
  points, or `sapi_handle_post` (SAPI.c:169, AFTER the parse) — and
  `zend_handle_delayed_oom` ends `if (!execute_data) zend_bailout();`.
  Inside the rfc1867 window there is no VM and no call frame, and with
  all-incomplete classes there are no `zend_call_function` sites at all →
  **no bailout inside the flock window is possible**. RECEIPT (matrix
  oom_parser/oom_window): `Fatal error: Allowed memory size of 8388608 bytes
  exhausted ... in Unknown on line 0`, worker ALIVE, all probes clean. Hard
  limit: `Hard memory limit ... _exit(137)` (matrix hardoom_window: worker
  death, no state).
- **max_execution_time / max_input_time (the timer producer).** The non-ZMET
  handler (zend_execute_API.c:1508, build has `#undef
  ZEND_MAX_EXECUTION_TIMERS`) only sets `timed_out`/`vm_interrupt` and arms
  the hard kill; `zend_timeout()` E_ERROR fires only at VM interrupt points.
  Pre-VM expiry + >2s further CPU → `_exit(124)`. RECEIPTS: timer VM-side =
  clean `Maximum execution time of 2 seconds exceeded in arm_target.php on
  line 1`, session intact, probes clean (timeout_clean); timer in-window =
  **`Fatal error: Maximum execution time of 2+2 seconds exceeded
  (terminated) in Unknown on line 0` + server DEAD** (timeout_burn) — process
  death, not a bailout, no state can leak.
- **Decode failures / handler mismatch.** `php_session_decode`'s
  `zend_catch` → `php_session_cancel_decode` → `php_session_destroy` →
  `php_rshutdown_session_globals` (closes fd) + `php_rinit_session_globals`
  (resets all PS_*). Matrix mismatch case: clean, sess file destroyed (known
  T1/T4 family), no stale state.
- **Invalid-key reject (T4).** E_WARNING + NULL return → `s_write("")` +
  `s_close`. Matrix badkey: wipe, no stale state.
- **flock/open/read/write failures.** All abort paths call
  `php_session_abort()` → `s_close` + status reset; `save_current_state`
  always reaches `s_close` even after write FAILURE (warning only). Matrix
  badpath (ENOTDIR) and write_fail (permission as `nobody`): clean.
- **Parser aborts (client cut, cancel_upload, post_max_size, soft-OOM
  gates).** Every early exit is `goto fileupload_done`, which ALWAYS fires
  `MULTIPART_EVENT_END` (rfc1867.c:1432) → cleanup + `php_rshutdown_session_globals`
  + progress free + `zend_delete_global_variable("_SESSION")`. Matrix abort +
  planted_cancel: clean.
- **User code.** Impossible pre-RINIT (see §1). `request_parse_body()`
  permutation: callback early-returns while `PG(modules_activated)` — matrix
  workers4 PART 2: rfc1867 phase + userland re-parse in one request, victim
  data intact (`keep|s:6:"keepme";`), probes clean.

## 3. Producer × consumer matrix (8.5.12, php -S single process = deterministic
same-process affinity; every case = fresh server)

| # | Producer | Arm result | Hang probe | ini-warn oracle | Set-Cookie | fd count | Verdict |
|---|---|---|---|---|---|---|---|
| 0 | timer control (met=2 busy loop) | 500 E_ERROR @2.0s | n/a | — | — | — | timer armed ✓ |
| 1 | baseline (no producer) | 200 | SERVED 4ms | NONE | fresh hex | stable | CLEAN |
| 2 | OOM in parser (24x262144B names, ml=8M) | OOM fatal, ALIVE | SERVED 5ms | NONE | none | stable | CLEAN |
| 3 | OOM in window (6M sess, ml=8M) | OOM fatal, ALIVE | SERVED 4ms | NONE | fresh hex (see §5) | stable | CLEAN |
| 4 | hard OOM window (12M, ml=8M) | hard-limit kill, DEAD | — | — | — | — | process death |
| 5 | timer in window (50M sess, met=2, burn) | `2+2 seconds exceeded (terminated)`, DEAD | — | — | — | — | process death |
| 6 | timer in VM (50M sess, met=2, busy) | E_ERROR @VM, ALIVE | SERVED 190ms | NONE* | fresh hex | stable | CLEAN |
| 7 | badkey (`\|` in progress key) | invalid-key wipe | SERVED 6ms | NONE | none | stable | CLEAN (wipe=T4) |
| 8 | handler mismatch (php_serialize fmt / php) | decode-fail destroy | SERVED 4ms | NONE | none | stable | CLEAN (T1 family) |
| 9 | save_path open failure (ENOTDIR) | abort warnings | SERVED 6ms | NONE | none | stable | CLEAN |
| 10 | sess-file open failure (perm, as nobody) | abort warnings | SERVED 6ms | NONE | none | stable | CLEAN |
| 11 | client abort mid-body | EVENT_END cleanup | SERVED 4ms | NONE | none | stable | CLEAN |
| 12 | planted cancel_upload=true | callback FAILURE → EVENT_END | SERVED 4ms | NONE | none | stable | CLEAN |
| 13 | OOM arm + OOM window, PHP_CLI_SERVER_WORKERS=4 | both fatals, all 4 children alive | 12/12 SERVED (5-20ms) | NONE | fresh hex ×3 | sess_fds=0 on all 4 | CLEAN |
| 14 | request_parse_body() re-parse | 200, victim data intact | — | NONE | fresh hex | stable | CLEAN |

\* case 6's first probe showed "Failed to decode session object" — traced to
my own probe flipping `session.serialize_handler` before `session_start`
(the T1 mismatch mechanic, self-inflicted); probe fixed to a decode-neutral
`session.save_path` ini-change, after which all probes read NONE.

Consumers explicitly probed after every arm: same-sid multipart progress
upload (flock self-deadlock oracle — never hung), fd accounting (never grew;
workers4: 0 sess fds on all children), ini-change warning (never fired),
Set-Cookie content (always fresh 32-hex), session file inventory.

## 4. Positive control: the SAME probes on unpatched Ubuntu 8.1.2-1ubuntu2.27
(Apache 2.4.52 prefork mod_php, MaxRequestWorkers 1)

Arm: 4 parts x 1,500,000B filenames, memory_limit=8M (the pre-patch shape).

- **Pre-RINIT OOM fatal, child survives:**
  `PHP Fatal error: Allowed memory size of 8388608 bytes exhausted (tried to
  allocate 1503232 bytes) in Unknown on line 0` — 3/3 runs.
- **Stale-status ini-warning oracle FIRES (did not fire once on 8.5.12):**
  `PHP Warning: Unknown: Session ini settings cannot be changed when a
  session is active in Unknown on line 0` — twice per run, at the *next*
  requests' per-dir INI apply (per-dir apply runs before
  `zend_activate_modules`, so it observes the previous request's stale
  `PS(session_status)`).
- **fd leak:** sess fd left open across requests (persistent; 2 fds in the
  php_admin_value run, `open sess fds: 1` in the PHPRC runs). flock held
  across the bailout instant confirmed in strace (`openat(sess)=10;
  flock(10, LOCK_EX); ...` with zero `close(10)`), though in these tunings
  the fd is closed again during request shutdown before the next request —
  the deterministic self-deadlock receipt remains the WEAPON_NOTES one
  (`second flock ERESTARTSYS`).
- **NEW ARTIFACT — INI-layer UAF read:** the stale-active status blocks the
  per-dir INI restore; the next request's `session.save_path` then reads
  freed-and-reused request memory. Observed values: `"_SESSION"` (run 1) and
  `"upload_progress_"` (run 2 — the rfc1867 prefix string reused into the
  freed entry):
  `PHP Warning: Unknown: open(upload_progress_/sess_lcsid..., O_RDWR)
  failed` / `Failed to read session data: files (path: upload_progress_)` /
  `Failed to write session data ... (upload_progress_)`.
  Same stale-state family, consumer in the INI machinery — worth one line in
  any re-file of the 8.1 exposure. (On 8.5.12 the 109619 sweep's
  "INI-diagnostics-before-RINIT" layer plus the resets close this.)

Implication: every unauthenticated arm that worked pre-patch still works on
jammy 8.1.2-1ubuntu2.27 (the last jammy-security build): worker-surviving
pre-RINIT fatals, attacker tree persisted to the sess file, stale status,
leaked fds, corrupted save_path. The cluster — including the full
CVE-2026-109618/19 chains — is alive on that distro build and dead on
8.5.12.

## 5. Behavior notes (no security impact, documented for completeness)

- **Pre-RINIT Set-Cookie with a fresh sid:** after a mid-request session
  destroy (decode failure under memory pressure inside the window), the
  EVENT_END cleanup's `php_session_initialize` sees `PS(id)=NULL`, creates a
  cryptographically random sid, and `php_session_reset_id` sends the cookie
  *during the rfc1867 window* (session.c:1631). Observed in matrix cases 3/4
  and workers4 arm 2: `Set-Cookie: PHPSESSID=d89fecfb...; path=/` plus a new
  6-byte session file. Value always fresh/random — no dangling memory, no
  oracle. (The victim's original session was already destroyed by the decode
  failure — the known wipe family.)
- **Writes are `pwrite64`-based** (invisible under naive write-only strace
  filters — cost me a detour): each update window is
  `open → flock(LOCK_EX) → pread(whole file) → decode → insert →
  pwrite(rewritten tree) → close` (lock released by close; no LOCK_UN calls
  at all on 8.5.12 files handler in this flow).

## 6. Deliverables / file index (this folder)

- `lc_lab.sh` + `lc_probe.php` + `lc_arm.py` — full matrix (§3)
- `lc_focus.sh`, `lc_focus2.sh`, `lc_decode_test.sh`, `lc_bisect.sh` — timer
  window + strace flock accounting + decode-bisect (the "poisoning" was the
  probe's own serialize_handler flip: T1 mechanic, self-inflicted, closed)
- `lc_apache.sh` .. `lc_apache4.sh` — 8.1.2 positive control (§4)
- `lc_workers.sh` — PHP_CLI_SERVER_WORKERS=4 + request_parse_body (§3 #13/14)
- `lc_collect.sh` — artifact collector
- Receipts: `receipts_8512/lc_session_state/` (matrix_full_run.log,
  apache812_ap2_error.log [ini-UAF + stale-status oracle],
  apache812_ap2_trace.log [flock-then-no-close], apache_locks_arm/,
  apache_oom_arm/, workers4/, timer_focus/, lab_logs/, focus2_logs/)

## 7. Bottom line for the weapon program

- 8.5.12: no cross-request stale state from the rfc1867 session window —
  rigorous closure with receipts for every producer x consumer permutation
  we could construct, plus source-level reasons each remaining class cannot
  reach a bailout inside the window (no call sites; all-incomplete classes;
  EVENT_END funneling; always-close flush).
- The Wiz chain-B consumer (dangling `PS(http_session_vars)` reclaimed by a
  31-byte string → forged `zend_reference` → pDestructor) cannot be armed on
  8.5.12: no producer leaves the zval dangling across requests, and the
  next-request reset drops it with `ZVAL_UNDEF` (no dtor, no re-walk).
- The live exposure is the unpatched-distro lane (jammy 8.1.2-1ubuntu2.27
  and any 8.2<8.2.35 / 8.3<8.3.36 / 8.4<8.4.27 / 8.5<8.5.12 deployment),
  where the original arm receipts still reproduce and the INI-layer UAF
  artifact adds a new consumer.
