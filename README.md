# php2shell-zeros

Publication-ready security research: unpatched vulnerabilities in PHP, NativePHP Mobile, and Windows PHP builds. Turnkey repro scripts, raw receipts, weaponized exploit chains.

**Author:** Andrew Dorman (@acd421)
**Date:** 2026-10-21

---

## Vulnerability Inventory

| # | Finding | CVSS | Attack Vector | Status | Folder |
|:-:|---------|:----:|--------------|:------:|--------|
| 1 | var_destroy re-entry UAF (unserialize) | **9.8** | Remote via any `unserialize()` surface | 🔴 Not fixed | `zero4/` |
| 2 | serialize-side mirror UAF | **9.8** | Remote via any `serialize()` surface | 🔴 Not fixed | `zero5/` |
| 3 | Enum-autoload boundary-crossing UAF | **8.1** | Remote via session decode (E: format) | 🔴 Not fixed | `zero7/shape5/` |
| 4 | Session serialize_handler mismatch RCE | **8.1** | Remote (config-dependent, CVE-2026-115560) | 🔴 Not fixed | `zero1/` |
| 5 | php_binary format-confusion injection | **8.1** | Remote (third delivery format) | 🔴 Not fixed | `zero1/shape10/` |
| 6 | Windows `O_NOFOLLOW`=0 hardlink RCE | **7.7** | Local (shared hosting, no privilege needed) | 🔴 Not fixed | `zero9/` |
| 7 | NativePHP bridge ungated API RCE | **9.8** | Remote (every NativePHP mobile app) | 🔴 Not fixed | `zero6/` |
| 8 | GC double-free → controlled indirect call | **7.5** | Remote crash + attacker-chosen call target | 🔴 Not fixed | `zero2/` |
| 9 | C: format internal-class crasher | **7.5** | Remote DoS (141 classes, 5 crashers) | 🔴 Not fixed | `zero7/` |
| 10 | Session-wipe on default installs | **7.5** | Remote unauth DoS (0-byte write) | 🔴 Not fixed | `zero1/` |
| 11 | Slow-bleed TOCTOU / flock-drop window | **7.5** | Remote DoS + RCE insertion window | 🔴 Not fixed | `zero10/` |
| 12 | Jammy fleet: Ubuntu 22.04 never patched | — | Entire LTS fleet exposed to all above | 🔴 Not fixed | `zero8/` |

**CVSS 3.1 computed from formula, not estimated.** Full details: `CVE_COUNT.txt`

---

## Weapons

| Weapon | What it does |
|--------|-------------|
| `php2shell.py` | Recon → option list → fire. 7 chain modules. Target / local / Docker modes. |
| `pwn_unserialize.py` | Standalone var-layer UAF ripper. One command → `uid=0`. |
| `pwn_zero4_live.php` | ASLR-on, in-band bootstrap. No gdb, no setarch. Heap leak → forge → `zif_system`. |

```
python3 weapons/php2shell.py --target http://host/
python3 weapons/pwn_unserialize.py --local --php /path --chain zero4 --cmd 'id'
bash RUN_ALL_ZEROS.sh
```

---

## Live-Fire Receipts

| Target | Chain | Receipt |
|--------|-------|---------|
| WordPress on PHP 8.3.36 (real app, vanilla) | zero4 | `uid=0(root)` |
| php:8.5.11 Docker (official, stripped) | zero4 + zero5 | `uid=0(root)` ×2 |
| Ubuntu jammy 8.1.2 (never-patched LTS) | zero4 | `uid=0(root)` |
| PHP 8.5.12 (fully patched) | zero4 + zero5 | `uid=0(root)` ×2 |
| WordPress HTTP endpoint | zero4 trigger | 10/10 kills, unauth POST |
| FPM flock-drop injection | zero4 delivery | 6/6 kills, no unserialize surface |
| Public Cloudflare URL | sessgap | Live interactive reverse shell |
| 3v4l.org (live third-party) | C: crasher | SIGSEGV |
| Windows 8.5.12 + 8.1.34 (stock) | zero9 hardlink | `WP4_RCE_OK` unprivileged |
| NativePHP bridge (framework lab) | zero6 full chain | `uid=0` via in-band bootstrap |

---

## Build

```
curl -sLO https://www.php.net/distributions/php-8.5.12.tar.gz && tar xzf php-8.5.12.tar.gz
mkdir b && cd b && ../php-8.5.12/configure \
  --disable-all --enable-session --enable-xml --enable-libxml --with-libxml \
  --enable-dom --enable-simplexml --enable-cli --with-readline=/usr
make -j$(nproc)
```

---

## Credits

**First defensive report on the surviving flaws:** [Red Eye Security — CVD](https://threat-intelligence.redeyesecurity.com/blog/php2shell-part-two-surviving-php-flaws-2026)

| Contribution | Credited to | How our work differs |
|-------------|-------------|---------------------|
| All findings, receipts, weapons, write-ups | Andrew Dorman (@acd421) | — |
| var_destroy UAF (zero4) | dinosn ([May 2026](https://github.com/dinosn/php-8.5.5-var_destroy-uaf)) | dinosn published crash + RCE first; we independently re-derived, then weaponized on vanilla stripped binaries, added the C: format entry path, WordPress HTTP kills, and flock-drop delivery |
| Serialize re-entry (zero5) | janhelke ([GH-24373](https://github.com/php/php-src/issues/24373)) | janhelke reported the crash; we built the first escalation from crash to full RCE (self-reclaim → forged object → `zif_system`) |
| GC regression (zero2) | evankford ([GH-24488](https://github.com/php/php-src/issues/24488)) | evankford found the bug; we receipted the remote kill, the allocator-wall analysis, and the GC composition to controlled indirect call |
| Surviving-gap naming | Wiz research team | Wiz named the gaps publicly without demonstration; we provided the first receipts |
| Original CVE-2026-109618/19 | Calif, OpenAI, Wiz, lcfr-hax, tomash-areion | Those are the patched bugs; our package covers what survived the patch |
| Patch team | arnaud-lb, iluuu1994, bukka, ndossche | — |

**Session injection technique class**: prior research ([Exploit-DB #50157](https://www.exploit-db.com/docs/50157), 2021) demonstrated session-file poisoning via LFI (file inclusion). Our approach is different: we use serialize_handler format confusion to make PHP itself unserialize the injected payload — no LFI, no file inclusion, different delivery vector and different primitive. The php_binary variant, session-wipe, cross-tenant takeover, and stock-ini race are novel to this package.

---

## Disclosure

Unfiled at publication time. The choice is the author's.
