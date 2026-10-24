# php2shell-zeros — surviving-bug package against PHP 2026-10-21 security releases

Publication-ready findings against **fully-patched PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35**, NativePHP Mobile, and Windows PHP builds, with turnkey repro scripts and raw receipts. Author: Andrew Dorman (@acd421), 2026-10-21.

| # | Folder | Class | Receipt level |
|---|--------|-------|---------------|
| 1 | `zero1_session_gaps/` | session serialize_handler mismatch + upload-progress key injection → unauth object injection → **RCE** + **unauth session-wipe** on default installs | Full RCE, 5 independent receipts + negative control |
| 2 | `zero2_gc_regression/` | GC double-free of SimpleXMLElement properties table (regression shipped *inside* the patch) | Double-free proven + remote kill + **controlled indirect call** via GC composition |
| 3 | `zero3_patch_teardown/` | Verified analysis of what the patch actually fixed | gdb-verified closure of every bailout path |
| 4 | `zero4_var_destroy_uaf/` | **var_destroy re-entry UAF in unserialize** | ASAN UAF, glibc SIGSEGV, full RCE chain (`uid=0`), C: format second entry (5/5), WordPress HTTP kills (10/10) |
| 5 | `zero5_serialize_reentry/` | **php_var_serialize_destroy re-entry UAF** | ASAN heap-use-after-free + full RCE chain (`uid=0` via plain `serialize()`) |
| 6 | `zero6_nativephp/` | NativePHP bridge: ungated API + File.Copy + AsyncTask unserialize | Full RCE through bridge (`uid=0`, in-band bootstrap, stripped-binary symbols) |
| 7 | `zero7_cformat/` | C: format internal-class instantiation (141 classes, 5 crashers) + **enum-autoload boundary UAF** | SIGSEGV on stock builds, 3v4l.org, 8.5.13 preview |
| 8 | `zero8_distro_exposure/` | Ubuntu jammy never got the patch (entire 22.04 LTS fleet exposed) | All original arms fire + `save_path` INI-UAF |
| 9 | `zero9_windows_sessions/` | Windows PHP `O_NOFOLLOW` = 0 → unprivileged hardlink RCE | `WP4_RCE_OK` on stock builds, zero privilege |
| 10 | `zero10_slow_bleed/` | Slow-bleed doctrine (all size mitigations defeated) | 124 receipts, TOCTOU kill-window |
| — | `weapons/` | **php2shell.py** (recon → options → fire, 7 chains) + **pwn_unserialize.py** | Live-fire receipts: WordPress, Docker, jammy, 8.5.12, public URL, 3v4l.org |

## Build (once, for repros)

```
curl -sLO https://www.php.net/distributions/php-8.5.12.tar.gz && tar xzf php-8.5.12.tar.gz
mkdir b && cd b
../php-8.5.12/configure --disable-all --enable-session --enable-xml \
  --enable-libxml --with-libxml --enable-dom --enable-simplexml \
  --enable-cli --with-readline=/usr
make -j$(nproc)
```

## Repro quickstart

```
bash zero1_session_gaps/repro/fin_8512.sh     # full RCE on 8.5.12 (self-contained lab)
bash RUN_ALL_ZEROS.sh                          # entire arsenal, one command
python3 weapons/php2shell.py --local --php ./sapi/cli/php --all  # fire every viable chain
```

## Full credit map

- **Findings, receipts, write-ups:** Andrew Dorman (@acd421)
- **var_destroy UAF prior art:** dinosn (May 2026)
- **serialize re-entry class:** janhelke (GH-24373)
- **GC regression:** evankford (GH-24488)
- **Gap naming (public record):** Wiz research team
- **Original CVE-2026-109618/19 research:** Calif, OpenAI, Wiz, lcfr-hax, tomash-areion
- **Patch team:** arnaud-lb, iluuu1994, bukka, ndossche

## Raw receipts

Every zero folder contains its receipts. Weapons receipts in `weapons/receipts/`. Every claim is backed by a logged run.

## Disclosure status

Unfiled with php-src at publication time. The choice is the author's.
