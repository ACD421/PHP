# php2shell-zeros — surviving-bug package against PHP 2026-10-21 security releases

Two publication-ready findings against **fully-patched PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35** (today's releases), with turnkey repro scripts and raw receipts. Author: Andrew Dorman (@acd421), 2026-10-21.

| # | Folder | Class | Receipt level |
|---|--------|-------|---------------|
| 1 | `zero1_session_gaps/` | session serialize_handler mismatch + upload-progress key injection → unauth object injection → **RCE** (`uid=` over HTTP, incl. stock-ini race and on-build 8.5.12 chain) + **unauth session-wipe** on default installs | Full RCE, 5 independent receipts + negative control |
| 2 | `zero2_gc_regression/` | GC double-free of SimpleXMLElement properties table (regression shipped *inside* the patch) — remote kill, allocator-wall analysis | Double-free proven (gdb/ASAN/glibc/core) + remote kill; RCE escalation in progress |
| 4 | `zero4_var_destroy_uaf/` | **var_destroy re-entry UAF in unserialize** (first demonstration of the Wiz-named n=1015 gap) | 3 receipt classes: ASAN UAF, glibc SIGSEGV w/ core on stock builds (8.5.12/8.5.11/8.1.2), watchpoint-captured silent write on production ZendMM + attacker-chosen zval* deref (0x4242424242424242, ASLR-free) |
| 5 | `zero5_serialize_reentry/` | **php_var_serialize_destroy re-entry UAF** — the serialize-side mirror, first demonstration, unnamed anywhere | ASAN heap-use-after-free (zend_hash_destroy ← php_var_serialize_destroy); boundary clean@5/fire@6 nested objects |

## Build (once, for repros)

```
# php-8.5.12 from release tarball (any standard toolchain; WSL Ubuntu 22.04 used for receipts)
curl -sLO https://www.php.net/distributions/php-8.5.12.tar.gz && tar xzf php-8.5.12.tar.gz
mkdir b && cd b
../php-8.5.12/configure --disable-all --enable-session --enable-xml \
  --enable-libxml --with-libxml --enable-dom --enable-simplexml \
  --enable-cli --with-readline=/usr
make -j$(nproc)
# binary at ./sapi/cli/php  (receipts used /tmp/php8512_build/plain2/sapi/cli/php)
```

zero1 Apache receipts additionally used Ubuntu 22.04's Apache 2.4.52 +
mod_php 8.1.2-1ubuntu2.27 (all security backports — also fully patched for
the CVE class; the gaps survive there too).

## Repro quickstart

```
bash zero1_session_gaps/repro/fin_8512.sh     # A0 object-injection + A5 full RCE on 8.5.12 (self-contained lab)
bash zero1_session_gaps/repro/mm_cli_8512.sh  # mismatch matrix incl. closed variant (correctness control)
bash zero1_session_gaps/repro/ap_lab.sh       # Apache T-series: T1/T2/T3 (stock-ini race)/T4 wipe/B2 + controls
bash zero2_gc_regression/poc/p12b_churn.sh    # zend_mm_heap corrupted (php -a shape)
```

## Full credit map

- **zero1 findings + receipts + write-up:** Andrew Dorman (@acd421) with Claude (Anthropic) agent tooling.
- **zero1 gap naming (public record):** Wiz research team's disclosure companion repo (surviving-gap list, 2026-10-21).
- **zero1 race technique shape:** public same-day research against 8.5.11 (author requested no credit); its "patched in 8.5.12" claim corrected herein with receipts.
- **zero1 legacy technique class:** public PHP security research since the mid-2010s (OWASP PHP Object Injection).
- **zero2 base regression:** evankford (php-src #24488, PR #24494; verified by devnexen).
- **zero2 weaponization analysis + receipts:** Andrew Dorman (@acd421) with Claude (Anthropic) agent tooling.
- **zero2 public corroboration:** Elise (@elise@katze.sh) same-day ASAN receipt.
- **Original CVE-2026-109618/19 research** (context for the patch): Calif (Ryan A), OpenAI, Wiz, lcfr-hax, tomash-areion, et al. — per GHSA-w8hw-w9fx-j79w / GHSA-6wmf-4rv5-p3rp.
- **Regression source:** GH-24050 fix wave by arnaud-lb, iluuu1994, bukka, ndossche (PHP security team).

## Raw receipts

`zero1_session_gaps/receipts/*.log`, `zero2_gc_regression/poc/p22_ground.log` (+ run logs in zero2 receipts). Every claim in the write-ups is backed by a logged run from 2026-10-21.

## Disclosure status at packaging

Both findings unfiled with php-src at package time. Decide file-first (sec@php.net / GitHub security advisory, credit to @acd421) vs publish-first before wide release — the choice is the author's.
