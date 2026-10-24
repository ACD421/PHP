# SLOW BLEED — the quantified case that every size-based PHP mitigation is aimed at a dead target

Andrew Dorman (@acd421) — 2026-10-23. Lane deliverable for the doctrine:
"they mitigate with memory_limit raises and body-size shrinking — a slow
bleed wins." Every number below is a logged run from this session (receipts
in `sb_receipts/`, harnesses `sb_*.sh/py/php` in this directory). Builds:
php-8.5.12 (`plain2`), 08f4b64-fixed tree = 8.5.13 preview (`plain3fix` /
`fixedasan`), Ubuntu jammy Apache 2.4.52 + mod_php 8.1.2-1ubuntu2.27
(never received the Oct 2026 patch — cross-lane intel, item 11), fresh
out-of-tree 8.5.12 FPM build (`/tmp/php8512_build/sb_fpm`).

## 0. The doctrine, stated

A size-based mitigation can only stop an attack whose cost is a function
of payload size. The php2shell arsenal's cost functions are:

| Primitive | Wire cost | Victim cost driver |
|---|---|---|
| C: empty-object worker kill (fc_c_dom_prop / HashContext) | **23 B raw / 41 B on the wire** | process lifetime, not bytes |
| php -S pool exhaustion | 1–5 × 23 B | worker-pool cardinality |
| FPM respawn churn | 23 B per request | fork+init per request, forever |
| fb1 context leak (8.5.13 preview) | 10 KB | ownership bug, 24 KB/request flat |
| flock-hold drip | 2 MB once + trickle | lock + decode of attacker-sized session |
| duplicate-header amplification (jammy only) | 6 B per header | 303 B allocated per 6 B line |
| no-CD part flood | 26 B per part | parser CPU, uncapped |

Not one of those has a byte threshold to clamp. The receipts below make
that inarguable, then quantify the bleed each sustains.

## 1. The matrix — mitigation x primitive defeat

✅ = mitigation defeats the primitive, ❌ = primitive sails through,
⚠ = mitigation only rescales the primitive.

| Mitigation (what defenders turn) | worker-kill churn (1a) | php -S pool death (1a) | fb1 leak (1b) | flock-hold (1c) | dup-header amp (M2) | no-CD part flood (M2) |
|---|---|---|---|---|---|---|
| `memory_limit` raise | ❌ 2048M: identical kills (E/C receipts) | ❌ | ❌ slope 24,266 B/req at 2048M = slope at 128M | ❌ 2 MB decodes never approach any limit | ⚠ caps the alloc spike AT the limit: 128M default still buys 128 MB from ~2.6 MB wire (jammy) | ❌ CPU-bound |
| `post_max_size` shrink | ❌ 23 B payload passes any limit > 23 B | ❌ | ❌ 10 KB payload | ⚠ only caps the fat-key size (512 KB key works fine, mechanism intact) | ⚠ caps dup count at limit/6 B — still ~50x amplification inside any limit (jammy) | ⚠ caps part count; CPU per max-size body stays ~0.5 s |
| `upload_max_filesize` / `max_file_uploads` | ❌ | ❌ | ❌ | ❌ the attack uses the PROGRESS field, not an upload | ❌ no files involved | ❌ no files involved |
| `max_input_vars` | ❌ 1 variable | ❌ | ❌ | ❌ 1 variable | ❌ | ❌ parts carry no Content-Disposition, never registered — invisible |
| `max_multipart_body_parts` | ❌ 1 part | ❌ | ❌ | ❌ 1 part | ❌ 1 part | ❌ **BYPASS**: the counter only decrements when a part has a Content-Disposition header; no-CD parts are uncounted (receipted: 5000 no-CD parts under limit=200, no cap, no warning) |
| `pm.max_requests` recycling (ops answer to churn) | ❌ respawn already happens per request; recycling changes nothing for the attacker | n/a | ⚠ resets per worker, but 24 KB x 500–1000 req/cycle = 12–24 MB/cycle/worker keeps bleeding in cycles | ❌ | ❌ | ❌ |
| The real fixes | release branches must pick up the master C: guard (b50b30c/4bf700e — never merged to any release branch) | same | fix the fb1 ownership lifecycle (bailout abandons contexts) | disable `session.upload_progress` / sid hygiene | **jammy needs the Oct 2026 patch** (8.5.12 already has it) | cap ALL parsed parts, not CD-parts |

The class the size knobs DO stop (control receipt, run F): a 42 MB
unserialize body against `memory_limit=32M` → 20/20 graceful
"Allowed memory size exhausted" bailouts, **zero** worker deaths, pool
intact. That is the target the defenders' knobs were built for — and it is
dead target practice.

## 2. MISSION 1a — worker-churn bleed (quantified)

### 2.1 php -S (PHP_CLI_SERVER_WORKERS=4) — the house of cards

Architecture receipts (source, `sapi/cli/php_cli_server.c`): workers are
forked **once** at startup; the master never respawns (waitpid only runs
in the dtor at shutdown); the master **also serves requests**; children
install PDEATHSIG(SIGTERM) — master death cascades to the whole pool.

- Benign control N=10,000: 68.4 req/s, 10,000/10,000 OK, 5 stable server
  pids, master RSS drift +552 KB. Same-size control (`O:8:"stdClass":0:{}`)
  N=10,000: 60.9 req/s, identical profile. (`sb_churn_A/B.log`)
- Crasher N=100: 100/100 kills; pool 4→0 in 0.6 s; **zero respawns**;
  after death the zombie master keeps the listening socket open — clients
  get RSTs, not refusals (service looks hung). (`sb_churn_C.log`)
- Kill-to-death over 5 independent runs: **1, 5, 3, 1, 4** crasher
  requests to permanent total service death. One request suffices when the
  master wins the accept race (bash receipt: master SIGSEGV, all children
  PDEATHSIG'd). (`sb_churn2_run{1..5}.log`)
- Degradation: 8-thread benign throughput 312 req/s (5 servers) falling
  to 0 as the pool dies; ~130 req/s on the last surviving server.
- Mitigation theater (`memory_limit=2048M post_max_size=64M
  max_input_vars=10000`): identical kill, 20/20. (`sb_churn_E.log`)

### 2.2 FPM (fresh 8.5.12 build, pm dynamic, 4 children, Apache mod_proxy_fcgi)

- Benign N=1,000: 43.8–82.1 req/s, 1000/1000 OK, master RSS drift 0.
- Crasher N=100: **34.1 req/s sustained kill rate**, 100/100 SIGSEGV +
  respawn ("exited on signal 11" x100 in the FPM log), service alive.
- Crasher N=1,000: 25.2 req/s sustained, cumulative 1,100 SIGSEGVs,
  397 distinct child-pid pool states in 40 s (churn visual),
  master RSS drift 0. (`sb_fpm85_B*.log`, `sb_fpm85.error.log`)
- **N=10,000: 29.9 req/s sustained for 334.5 s = 10,000 SIGSEGV
  respawns, one per request, pool never empty (min 1 child alive), FPM
  master RSS drift 4 KB, service serving normally after the run** (new
  worker pid receipt). (`sb_fpm85_D.log`, `sb_fpm10k.error.log`)
- Mitigation theater on FPM (memory_limit=2048M, post_max_size=64M,
  max_input_vars=10000): 100/100 kills, 100 respawns — identical.
  (`sb_fpm85_C.log`)
- Jammy 8.1.2 FPM (apt php-fpm8.1, HashContext-serialize crasher, 23 B):
  benign 29.0 req/s → crasher 1,000: 28.1 req/s sustained, 1,000
  respawns, master RSS drift 0, alive after. (`sb_fpm81_B.log`)

Doctrine number: **one unauthenticated connection sustains ~30 kills per
second for as long as it cares to**, at 41 bytes per kill. From the
outside the service is "up" (benign requests interleave at near-baseline
rates); each kill costs the operator a fork+module-init+core-capture and
returns a 500 to whoever shared the victim.

## 3. MISSION 1b — leak-rate bleed on the NEXT-release code

fb1 shape (bailout mid destroy-walk abandons serialize/unserialize
contexts) as an HTTP victim (cache-decode app shape; single-request LSan
receipt was 25,244 B / 22 allocs on the fixed tree).

- plain3fix (8.5.12+08f4b64 = 8.5.13 preview) + `USE_ZEND_ALLOC=0`,
  persistent php -S worker, fb1 x 1,000: RSS 16,260 → 40,708 KB
  (**+23.88 MB**), **linear slope 24,254 B/request** (fit over 50
  samples; curve dead-linear: 19,068 KB @ 80 req → 40,236 KB @ 980 req),
  78.5 req/s, 1000/1000 bailouts. (`sb_leak_L1*`)
- Same-size valid-payload control x 1,000: drift 0.94 MB, slope 206
  B/request — **118x smaller**. (`sb_leak_L2*`)
- `memory_limit=2048M`: slope 24,266 B/request — identical. (`sb_leak_L3*`)
- fixedasan + `USE_ZEND_ALLOC=0` + LSan, fb1 x 200, SIGINT shutdown:
  **total at exit 4,710,632 bytes in 2,597 allocations = 23,553
  B/request**; largest block: 2,031,000 B / 200 objects (one 10,155 B
  context per request). Control x 200: zero LSan findings.
  (`sb_leak_L4/L5`, leak reports in `sb_leak_L4_asan_fb1.server.log`)

Honest scope: under default ZendMM the request-scoped heap reset hides
cross-request accumulation (the earlier plateau receipt); the linear bleed
is live on system-malloc SAPI shapes (`USE_ZEND_ALLOC=0`, malloc-backed
builds). The bug ships in 8.5.13-preview unless the ownership lifecycle
is fixed — 24 KB/request is 24 GB per million requests.

## 4. MISSION 1c — flock-hold bleed (jammy Apache + mod_php 8.1.2)

Mechanism (source-verified): `ps_files_open` takes `flock(LOCK_EX)` at
session open and holds it until close; every rfc1867 upload-progress
update runs open+read+**decode**+encode+**write**+close — the whole cycle
under LOCK_EX. `update_step` = declared Content-Length/100; min_freq
throttles to 1/s stock, 0/s for progress-bar apps.

- Baseline (empty victim session): legit `session_start` p50 0.0 ms /
  p99 0.1 ms / max 0.1 ms (n=2,361). (`sb_flock_details.csv`)
- **Stock-ini shape** (drip carries a 2,048 KB
  `PHP_SESSION_UPLOAD_PROGRESS` value → the session key becomes
  `upload_progress_AAA...` 2 MB; session file balloons to 2,097,479 B at
  FILE_START; every update re-decodes+re-encodes 2 MB under LOCK_EX):
  legit session_start during the drip **p50 2.6–5.4 ms, p95 5.8–8.0 ms,
  p99 7.0–11.5 ms, max 16.3–28.1 ms — 50–280x baseline**. The drip never
  needs to complete: at 8–131 KB/s the request is still alive server-side
  after the window (file stays fat); stock cleanup=1 deletes the key only
  at MULTIPART_EVENT_END, which the attacker simply never lets fire.
  (`sb_flock_summary.log` fatdrip rows, PA section)
- **cleanup=0 apps** (progress-bar config; per-dir
  `session.upload_progress.cleanup=off`): one FULL 2,048 KB-key upload →
  session file 2,097,496 B **persists** (stable at +0.2/+1/+2 s; 512 KB
  variant receipts 524,630 B). Permanent self-DoS: every future victim
  request pays the decode — poisoned_persist p50 2.6 ms / max 8.3 ms vs
  0.1 ms baseline. Then a TINY drip (8-byte key, declared 64 KB →
  655 B update step) re-seizes the lock per update on the poisoned sid:
  p50 4.0–5.5 ms, p99 10.1–11.6 ms, max 21.5 ms across 2K–131K Bps.
  Poison **stacks**: a second 512 KB-key upload on the same sid →
  keys=2, key_bytes=2,621,472, session_start 3.11 ms — every victim
  request decodes ALL injected keys. (`sb_flock_summary.log` PB rows,
  `sb_flock_filestates.log`, `sb_flock_dbg.sh` receipts)
- Attack cost: one connection, ~2 MB one-time (or 512 KB), then trickle
  bandwidth. Every victim request on that sid is now a 2 MB
  decode+encode+write on the session file, serialized behind the lock
  against every other request on that sid.

## 5. MISSION 2 — does the multipart hardening survive? VERDICT

8.5.12's `rfc1867.c` carries the hardened part-header parse
(`php_mime_should_save_hdr`: only Content-Disposition/Content-Type saved;
duplicates ignored via `php_mime_get_hdr_value`). Measured on php -S with
`memory_get_peak_usage` at script top (parse-time high-water mark):

**The Wiz duplicate-small-header class is DEAD on 8.5.12** (all deltas vs
the 451,784 B baseline / 532,664 B 1000-part control):
- xdups 1x20,000 (160 KB wire of 6-byte "X-A: b" lines): **zero**
  allocation growth.
- xdups 1000x20: byte-identical to the no-dup control.
- cddups (exact-duplicate Content-Disposition) 1x20,000: zero.
- cdfuzz (case/space/colon variants) 1x20,000: zero — variant lines are
  simply not saved.

**The same class is LIVE on jammy 8.1.2** (unpatched fleet; baseline
419,704 B) — the A/B receipt that proves the harness detects the class
when present:
- xdups 1x20,000: peak_int 6,469,904 (**+6.05 MB from 160 KB wire = 38x**;
  ~303 B allocated per 6-byte header — the "~314 B/header" class).
- **xdups 1x150,000: wire 1,200,076 B → peak_int 45,989,904 = +45.6 MB
  (38x net), deterministic across two runs** — the "1 MB → 46 MB" Wiz
  headline reproduced on the stock jammy binary. (`sb_amp_all.log`,
  `sb_amp2` run)
- cddups 1x20,000: +6.37 MB (7.6x); cdfuzz 1x20,000: +5.09 MB (6x).

**Cap threshold receipt (8.5.12)**: `max_multipart_body_parts` default
**-1 = UNLIMITED** (verified live: 20,000 parts pass). With =200:
CD-carrying parts cap at exactly 200 with "PHP Request Startup: Multipart
body parts limit exceeded" + parse abort (199/200 OK, 5,000 aborted).

**Bypass receipt (8.5.12 AND 8.1.2)**: the body-parts counter decrements
only inside the Content-Disposition branch — parts with no CD header are
**uncounted**: 5,000 no-CD parts under limit=200 → no cap, no warning,
never registered (invisible to max_input_vars/max_file_uploads too).
26 B/part wire → pure parser pressure: 20,000 parts = 520 KB wire, 36 ms
CPU; a post_max_size-sized body (8 MB) = ~320 K parts ≈ 0.55 s of parser
spin per request, repeatable at line rate. A part-count pressure primitive
no size/count knob bounds.

**Not bypassable**: continuation-line flooding is linear (1–2.2x wire,
realloc doubling) on both versions; chunked TE on php -S is dechunked and
the post_max_size pre-check fires on the effective length ("POST
Content-Length of 4194378 bytes exceeds the limit of 2097152") — no
chunked bypass.

**Size-indifference completion**: on the patched build, the tiny-body
pressure primitive that survives is the no-CD part flood (uncapped,
uncounted, CPU-bound) — it is immune to every size knob because its cost
per wire byte is parser work, and its per-request ceiling is post_max_size
itself, the very knob defenders raise for legitimate uploads.

## 6. ESCALATION — the kill window is the insertion window

The worker-churn receipt is not just DoS. When the lock-holding worker
dies, the kernel drops every flock it held; between death and the next
`flock(LOCK_EX)` the session file is unlocked and writable. Jammy lab
(`sb_killwin*`, `sb_gap_probe.py`, `sb_lockkill.php`):

- **R1 (lock-hold baseline)**: a competitor's `session_start` blocks for
  the holder's entire window — 3,298,933 us receipt against a 4 s holder.
- **R2 (crash-drops-the-flock)**: holder SIGSEGVs (HashContext crasher,
  dies between session_start and write_close); a blocked competitor
  acquired the lock **0.1 ms after** the kill request completed — the
  window belongs to whoever flocks next, and the server's respawn is
  irrelevant to it.
- **R3 (insertion)**: during the window a second connection wrote
  attacker bytes into the victim session through the app's own write
  route, uncontended (acquisition 7–41 us vs 3.3 s blocked): file receipt
  `injected_by_attacker|s:11:"PWN-1767487";ts|d:...`.
- **R4 (torn-write product)**: a partial-pwrite state (death mid-write of
  a 16 MB session; operator-simulated file state, the death vector itself
  being the receipted crasher / the jammy hook's decode-during-update)
  → **every torn fraction from 2% to 98% produces
  "session_start(): Failed to decode session object. Session has been
  destroyed" + FILE DELETION** — an unauthenticated session-destroy on
  the victim (T4 class), 5/5 fractions. (`sb_killwin` receipts)

Chain shape on jammy (original arms live there): flock-leg poison → hook
decode-during-update fires gadget destructors → crasher gadget dies the
worker INSIDE the lock/write cycle → flock drops, file torn/unlocked →
second connection inserts / respawned worker reads the torn file through
the serialize_handler mismatch (zero1's read-side object injection) or
trips the var_destroy re-entry UAF (zero4) — from DoS to RCE through the
death window. Those two lanes own the read-side receipts; this lane
receipts the window.

## 7. Defender reality

Every knob in the matrix above is aimed at an attack class that the
receipts show is already dead (the 42 MB graceful-bailout control), while
the live arsenal pays 23–41 bytes per kill, 24 KB per request of
unreclaimable context, 2 MB once for a permanent session tax, or 303
bytes of allocation per 6-byte header line — none of which has a byte
threshold to clamp, and the one thing that would actually help on the
crashers (the C:-format guard that has sat fixed on master since June
while every release branch through 8.5.12/8.4.27 ships the unconditional
`object_init_ex`) is a two-line semantic fix, not a size limit. On FPM the
operator-visible symptom is a healthy-looking service with a 30/sec
respawn rate and a 500-error drumbeat; on php -S it is five requests to a
zombie listener; on jammy it is a 46 MB allocation spike from a 1.2 MB
body plus every original rfc1867 arm. The honest mitigation set is:
merge the C: guard to release branches, fix the fb1 ownership lifecycle,
patch jammy, disable `session.upload_progress` where it is not needed,
and treat per-request SIGSEGV counts as the alarm — memory_limit and
post_max_size tuning is theater against all of it.

## 8. Files

Harnesses: `sb_env.sh sb_81matrix.sh sb_build_fpm.sh sb_victim.php
sb_victim81.php sb_churn.py sb_churn.sh sb_churn2.sh sb_diag.sh
sb_fpm.sh sb_fpm10k.sh sb_leak_victim.php sb_leak.py sb_leak.sh
sb_flock_read.php sb_flock_up.py sb_flock_probe.py sb_flock.sh
sb_flock_dbg.sh sb_flock_receipts.sh sb_amp_victim.php sb_amp.py
sb_amp.sh sb_amp2.sh sb_lockkill.php sb_ssprobe.php sb_sswrite.php
sb_bigwrite.php sb_gap_probe.py sb_killwin.sh`

Receipts: `sb_receipts/` — `sb_churn_{A,B,C,E,F}.log`,
`sb_churn2_run{1..5}.{log,server.log,sample.csv}`,
`sb_fpm85_{A,B1,B2,C,D}.log` + `.req.csv/.sample.csv/.summary.txt`,
`sb_fpm85.error.log sb_fpm85m.error.log sb_fpm81_{A,B}.log
sb_fpm81.error.log sb_fpm10k.error.log sb_81_crashmatrix.txt`,
`sb_leak_L{1..5}*` (curves, summaries, LSan reports),
`sb_flock_summary.log sb_flock_details.csv sb_flock_filestates.log`
(raw per-request probe rows + derived percentiles),
`sb_amp_all.log sb_amp2_jammy_wizclass.log`, `sb_killwin_probe.txt
sb_killwin_apache_error.log sb_torn_reader_sweep.log`.
