# php2shell-zeros

Security research package: unpatched vulnerabilities in PHP (through 8.5.12), NativePHP Mobile, and Windows PHP builds. Every finding has turnkey repro scripts and raw receipts. Author: Andrew Dorman (@acd421).

## Quick start

```
# The one-shot weapon (recon -> option list -> fire):
python3 weapons/php2shell.py --target http://host/
python3 weapons/php2shell.py --local --php /path/to/php --all

# The standalone ripper (unconditional RCE, no config):
python3 weapons/pwn_unserialize.py --local --php /path --chain zero4 --cmd 'id'

# Full arsenal verification (one command, all receipts):
bash RUN_ALL_ZEROS.sh

# Live reverse shell (one command):
bash REVSHHELL_E2E.sh
```

## Vulnerability inventory

See `CVE_COUNT.txt` for the full inventory with CVSS scores, affected versions, and fixed status.

## Where to find everything

### Weapons (`weapons/`)
- `php2shell.py` — THE weapon: recon engine, 7 chain modules, target/local/docker modes
- `pwn_unserialize.py` — standalone var-layer UAF ripper (zero4/zero5 chains)
- `WEAPONS.md` — usage guide + all live-fire receipts + honest bounds
- `receipts/` — 20+ receipt logs (the weapon's own stdout from every target)
- `lab/` — victim setups (WordPress, vanilla Docker, jammy, Laravel)

### PHP core vulnerabilities
- `zero1_session_gaps/` — serialize_handler mismatch + key injection RCE + session-wipe
  - `repro/` — self-contained PoC scripts (fin_8512.sh, ap_lab.sh, mm_cli_8512.sh)
  - `receipts/` — uid=0 receipts, hexdumps, reverse shell session
  - `shape10/` — crossfire escalation: php_binary injection, wipe-to-inject, cross-tenant takeover
- `zero2_gc_regression/` — GC double-free (the bug shipped INSIDE the October patch)
  - `poc/` — trigger PoCs (v_*.php), remote kill (r1_*), gdb analysis
  - `receipts/` — tcache aborts, ASAN, control experiment
- `zero3_patch_teardown/` — verified analysis of what the patch actually fixed
- `zero4_var_destroy_uaf/` — var_destroy re-entry UAF (unserialize side)
  - `poc/` — all triggers (vd1b, vd4, vdR1-3 leak/write/call chain, pwn_zero4.sh)
  - `receipts/` — ASAN, glibc SIGSEGV, controlled deref (rax=0x4242...)
  - `shape12/` — C: format second entry (RCE via C: instead of O:, 5/5 stable)
  - `shape34/` — WordPress HTTP remote kills (10/10) + flock-drop delivery (6/6)
- `zero5_serialize_reentry/` — serialize-side mirror UAF
  - `poc/` — vd6 carrier, pwn_zero5.sh wrapper
  - `receipts/` — ASAN, full RCE chain (self-reclaim -> zif_system)
- `zero7_cformat/` — C: format internal-class crashers (141 classes, 5 crashers)
  - `shape5/` — enum-autoload boundary crossing (new UAF surface on 8.5.12)
- `zero8_distro_exposure/` — Ubuntu jammy never got the patch (fleet exposure)
- `zero9_windows_sessions/` — Windows O_NOFOLLOW=0 hardlink RCE (unprivileged)
  - `wp4/` — full RCE receipts on stock Windows builds
- `zero10_slow_bleed/` — slow-bleed doctrine (124 receipts proving all size mitigations defeated)

### Filings (`filings/`)
- `SEC_PHP_FILING_1_mismatch.md` — serialize_handler mismatch report
- `SEC_PHP_FILING_2_keyinjection.md` — upload-progress key injection + session-wipe report

### Other
- `CVE_COUNT.txt` — full vulnerability inventory with CVSS, versions, status
- `index.html` — advisory page (self-contained, embeds the zip)
- `REVSHHELL_E2E.sh` — one-command live reverse shell
- `RUN_ALL_ZEROS.sh` — one-command arsenal verification

## Build (for repros)

```
curl -sLO https://www.php.net/distributions/php-8.5.12.tar.gz && tar xzf php-8.5.12.tar.gz
mkdir b && cd b
../php-8.5.12/configure --disable-all --enable-session --enable-xml \
  --enable-libxml --with-libxml --enable-dom --enable-simplexml \
  --enable-cli --with-readline=/usr
make -j$(nproc)
```

## Credits

- Findings: Andrew Dorman (@acd421)
- var_destroy UAF prior art: dinosn (May 2026)
- serialize class: janhelke (GH-24373)
- GC regression: evankford (GH-24488)
- Original CVE research: Calif, OpenAI, Wiz (CVE-2026-109618/109619)
- Patch team: arnaud-lb, iluuu1994, bukka, ndossche

## License

Security research. All testing on own infrastructure. No unauthorized access.
