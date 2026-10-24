# SHAPE34 — remote receipts: WP HTTP RCE surface + flock-drop zero4 delivery

Andrew Dorman (@acd421) — 2026-10-24. Missions 3+4 of the remote-receipts
push. Receipts standard: every claim below is a logged run in
`shape34_receipts/`; harnesses are the `shape34_*` files in this directory.
No overlap with shape12.

## MISSION 3 — WordPress HTTP endpoint remote RCE surface (DONE, kill-tier)

The prior zero4 WordPress receipt was `--local` CLI on the container's
8.3.36 binary. The critic's gap: "prove it through WordPress's HTTP API."
Closed:

### What fired (real WordPress, wordpress:latest = vanilla PHP 8.3.36
### Apache/2.4.69 mod_php, real install via HTTP, real DB)

- **M3-1 CORE custom-fields surface — ANALYSIS RECEIPT, negative result
  that matters**: XML-RPC `wp.newPost` custom_fields stores serialized
  attacker text, but `maybe_serialize()` DOUBLE-SERIALIZES any value that
  `is_serialized()` matches (`s:43:"s:37:...";` in the DB receipt) — the
  historic core mitigation; the read side strips one layer only, so core
  meta is NOT a raw unserialize surface and the stored trigger is inert
  through stock wp-admin reads (`wp_fire_stock_zendmm.log` A1/A2/A3,
  DB rows in both fire logs). Core also ships NO destructor-unserialize
  gadget: every `__destruct` in wp-includes + shipped plugins inventoried
  in `wp_core_surface_grep.log` (SimplePie/PHPMailer/WP_HTML_Token/image
  editors are inert; `WP_HTML_Token::__destruct` would be a call_user_func
  gadget but `__wakeup` throws since 6.4.2). This is the honest core map:
  WP core hands unserialize() to OPTIONS/TRANSIENTS/META from the DB, and
  its HTTP write paths all pass through the double-serialize guard.
- **M3-2 PLUGIN-LEVEL SURFACE = the receipted class** (the brief's
  explicit fallback: "even a plugin-level unserialize surface receipt
  proves the class"): lab plugin `shape34_wp_plugin.php` (queue-envelope
  import pattern — the classic plugin-ecosystem shape: an HTTP endpoint
  that unserializes a request field, plus the envelope gadget class whose
  destructor drains jobs by unserializing them) installed through the
  standard plugin mechanism on the real WP install.
- **M3-3 THE KILL RECEIPT (HTTP POST, unauthenticated)** — zero4 trigger
  `a:1020:{...i:9998;O:19:"Shape34_JobEnvelope":0:{}i:9998;i:5;}` (10146
  bytes, the exact weapon trigger) POSTed to
  `/?rest_route=/shape34/v1/import` field `data`:
  - stock ZendMM worker: 200 `result=true` — the silent-corruption class
    (`wp_fire_stock_zendmm.log` B2).
  - **glibc worker (`USE_ZEND_ALLOC=0`, the van85g recipe, `shape34_wp_glibc.sh`):
    `RemoteDisconnected` on the shot + `[core:notice] child pid N exit
    signal Segmentation fault (11)` in the container log —
    `wp_fire_glibc.log` B2 + `wp_kill10.log`: benign control 3/3 clean
    200s, then 10/10 kills, 10 SIGSEGV child lines, ~30ms per kill,
    unauthenticated, from a single `urllib` client.**

## MISSION 4 — flock-drop timing oracle + zero4 session injection (DONE)

Composition per the brief: crash the lock-holder, raw-write the zero4
payload into the session file inside the flock-drop window, the respawned
worker unserializes it on the next request — delivery with NO app
unserialize endpoint; **the session file IS the unserialize surface**.

Lab (`shape34_fpm_lab.sh`): fresh 8.5.12 FPM build behind Apache
mod_proxy_fcgi, ports 18390/18391, workers glibc-heap (`USE_ZEND_ALLOC=0`
must be in the MASTER's exec env — pool `env[]` is too late for MINIT;
`clear_env=no`), `setarch -R` (ASLR off). Victim
`shape34_fpm_victim.php`: gadget class declared before `session_start`,
php session handler, `m=hold&ms=700` holds the flock then fires the 23-byte
`C:11:"HashContext":0:{}` crasher (serialize-of-C:-object = SIGSEGV with
the lock held).

- **P1 holder kill**: 503 + `child exited on signal 11` (died holding
  LOCK_EX) — every run.
- **P2 the window**: raw writer (nonblocking flock spin, releases until it
  has observed the lock HELD >=20 blocked polls, then stays spinning):
  **acquired 82-101 us after the last blocked poll across 6/6 runs**
  (`fpm_chain_run4.log`, `fpm_chain_x5.log`, `fpm_chain_final.log`),
  wrote 18338 bytes of `q|a:1020:{...}` poison, fsynced.
- **P3 poisoned read**: any next request on that sid → `session_start` →
  php-handler decode → unserialize(trigger) → var_destroy re-entry UAF →
  **worker SIGSEGV, 6/6 runs** (FPM kill line #2 each run).
- **Determinism receipt (`jobsweep.log`)**: the no-alloc re-entry
  (`jobs='i:1;'`) is heap-lottery (the earlier silent runs); the
  jobs-property gadget (destructor unserializes the attacker-carried
  `jobs` string) makes the session-decode kill DETERMINISTIC: 16/16
  string sizes 4096-12288 and 4/5 int-array shapes DIE, both no-alloc
  controls SURVIVE. Groom size 8160 used in the chain.

## M4.4 stretch — full RCE via session injection (MAPPED, not fired)

The pure-data full chain (forged zval -> fake zend_object -> handlers =
zif_system) ported from the receipted ZERO4_CARRIER into serialized
session data (`shape34_fpm_full.py`, `shape34_full_cli*.php`,
`shape34_full_cli*_sweep.py`). Two gdb geometry receipts landed
(`shape34_fpm_full_dbg.sh`, `shape34_full_cli_dbg2.sh`):

- var_entries layout on 8.5.12: `used_slots@0, next@8, data@16`; when the
  groom string reclaims the freed block F (page-aligned), the string gc
  word at F+0 becomes `used_slots` (huge) and **R:1020 resolves to
  F+0x38 = groom payload offset 32** (var_access returned 0x7ffff54d5038).
- B-groom reclaim + forged-zval deref receipt (rax=0x4242424242424242
  inside the destructor's unserialize) — full pointer control confirmed
  through the SESSION decode path, ASLR-free.

Not fired end-to-end: the groom landing is script-shape-tuned (dtorprobe
shape landed at F=0x7ffff54d5000; adding one `file_get_contents` shifts it
off; the full_cli shape lands nowhere in the swept chunk), and one shape
dies on an uncommitted VM-stack page in the destructor call frame before
dispatch. Same wall the vd-boot lane documented ("geometry env-tuned");
needs the in-band bootstrap (used_slots-as-pointer materialization) — the
mapped next step. Sweeps: `fpm_full_sweep*.log`, CLI receipts in the
session transcript.

## Honest bounds

- M3 kill tier = worker SIGSEGV (the glibc-heap class), not uid — the
  remote full RCE tier needs per-process addresses (same as every prior
  remote zero4 receipt; `--local`/`--docker` remain the unconditional
  uid receipts).
- The M3 plugin is lab-authored (brief-sanctioned "create an endpoint");
  real-plugin gadget hunting is an open recon lane (grep recipe in
  `wp_core_surface_grep.log`).
- The M4 raw write runs where the session dir is writable (lab attacker
  vantage); the prior sb R3 receipt covers the app-route write variant.
- M4.4 = mapped + geometry receipts, no fire (above).

## Files

Harnesses: `shape34_wp_plugin.php shape34_wp_install.py shape34_wp_fire.py
shape34_wp_kill10.py shape34_wp_glibc.sh shape34_fpm_victim.php
shape34_fpm_lab.sh shape34_fpm_chain.py shape34_fpm_full.py
shape34_full_cli.php shape34_full_cli2.php shape34_full_cli_sweep.py
shape34_full_cli2_sweep.py shape34_fpm_full_dbg.sh
shape34_full_cli_dbg2.sh shape34_jobsweep.php shape34_jobsweep_run.sh
shape34_bisect.php shape34_bisect_run.sh shape34_abtest.php
shape34_dtorprobe.php shape34_crashsmoke.php`

Receipts: `shape34_receipts/` — `wp_fire_stock_zendmm.log
wp_fire_glibc.log wp_kill10.log wp_glibc_setup.log wp_core_surface_grep.log
fpm_lab_up.log fpm_chain_run{1..4}.log fpm_chain_x5.log fpm_chain_final.log
jobsweep.log trigger_bisect_glibc.log fpm_full_sweep{1,2}.log`

Rerun: `shape34_wp_glibc.sh && python3 shape34_wp_kill10.py` (M3);
`bash shape34_fpm_lab.sh start && python3 shape34_fpm_chain.py` (M4).
Stop the lab: `bash shape34_fpm_lab.sh stop` (exact ports 18390/18391).
