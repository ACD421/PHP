# php2shell-zeros

Publication-ready security research: unpatched vulnerabilities in PHP, NativePHP Mobile, and Windows PHP builds. Turnkey repro scripts, raw receipts, weaponized exploit chains.

**Author:** Andrew Dorman (@acd421)
**Date:** 2026-10-21

---

## Vulnerability Inventory

| # | Finding | CVSS | Attack Vector | Status | Folder |
|:-:|---------|:----:|--------------|:------:|--------|
| 1 | var_destroy re-entry UAF | **9.8** | Remote via `unserialize()` — WordPress, Docker, public URL | 🔴 Not fixed | `zero4/` |
| 2 | serialize-side mirror UAF | **9.8** | Remote via `serialize()` | 🔴 Not fixed | `zero5/` |
| 3 | Enum-autoload E: UAF | **9.8** | Remote via session decode | 🔴 Not fixed | `zero7/shape5/` |
| 4 | NativePHP bridge RCE | **9.8** | Remote via bridge API | 🔴 Not fixed | `zero6/` |
| 5 | Session serialize_handler RCE | **8.1** | Remote (config-dependent, CVE-2026-115560) | 🔴 Not fixed | `zero1/` |
| 6 | php_binary format injection | **8.1** | Remote (third delivery format) | 🔴 Not fixed | `zero1/shape10/` |
| 7 | Windows `O_NOFOLLOW`=0 RCE | **7.7** | Local (no privilege needed) | 🔴 Not fixed | `zero9/` |
| 8 | GC double-free → controlled call | **7.5** | Remote crash + attacker-chosen call | 🔴 Not fixed | `zero2/` |
| 9 | C: format crasher | **7.5** | Remote DoS (141 classes) | 🔴 Not fixed | `zero7/` |
| 10 | Session-wipe | **7.5** | Remote unauth DoS | 🔴 Not fixed | `zero1/` |
| 11 | Slow-bleed TOCTOU | **7.5** | Remote DoS + RCE insertion window | 🔴 Not fixed | `zero10/` |
| 12 | Jammy fleet composition | — | Ubuntu 22.04 LTS — all above, chained | 🔴 Not fixed | `zero8/` |

**CVSS 3.1 computed from formula.** Full details: `CVE_COUNT.txt`

---

## Weapons

| Weapon | What it does |
|--------|-------------|
| `php2shell.py` | Recon → option list → fire. 7 chain modules. Target / local / Docker. |
| `pwn_unserialize.py` | Standalone var-layer UAF ripper. One command → `uid=0`. |
| `pwn_zero4_live.php` | ASLR-on, in-band bootstrap. No gdb. Heap leak → forge → `zif_system`. |
| `shape12_gen.py` | Payload generator: `--format O\|C` — both entry formats. |

```
python3 weapons/php2shell.py --target http://host/
python3 weapons/pwn_unserialize.py --local --php /path --chain zero4 --cmd 'id'
bash RUN_ALL_ZEROS.sh
```

---

## Live-Fire Receipts

| Target | Chain | Receipt |
|--------|-------|---------|
| **Public Cloudflare URL** (WordPress, php:8.5.11) | zero4 full chain | **`uid=33(www-data)` via HTTP** |
| WordPress on PHP 8.3.36 (real app, vanilla) | zero4 + zero5 | `uid=0(root)` ×2 |
| php:8.5.11 Docker (official, stripped) | zero4 + zero5 | `uid=0(root)` ×2 |
| Ubuntu jammy 8.1.2 (never-patched LTS) | jammy composition | **`uid=0(root)` all 4 stages** |
| PHP 8.5.12 (fully patched) | zero4 + zero5 | `uid=0(root)` ×2 |
| WordPress HTTP endpoint | zero4 trigger | 10/10 kills, unauth POST |
| FPM flock-drop injection | zero4 delivery | 6/6 kills, no unserialize surface |
| 3v4l.org (live third-party) | C: crasher | SIGSEGV |
| Windows 8.5.12 + 8.1.34 (stock) | zero9 hardlink | `WP4_RCE_OK` zero privilege |
| NativePHP bridge lab | zero6 full chain | `uid=0` via in-band bootstrap |
| Enum E: session decode | zero7/shape5 | 4/4 `uid=0`, distinct ASLR each shot |

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
| All findings, receipts, weapons | Andrew Dorman (@acd421) | — |
| var_destroy UAF (zero4) | dinosn ([May 2026](https://github.com/dinosn/php-8.5.5-var_destroy-uaf)) | They published first; we weaponized on vanilla stripped binaries, added C: entry, WordPress HTTP, flock-drop, public URL chain |
| Serialize re-entry (zero5) | janhelke ([GH-24373](https://github.com/php/php-src/issues/24373)) | They reported the crash; we built the first escalation to full RCE |
| GC regression (zero2) | evankford ([GH-24488](https://github.com/php/php-src/issues/24488)) | They found the bug; we receipted remote kill + controlled indirect call |
| Gap naming | Wiz research team | They named gaps without demonstration; we provided the first receipts |
| CVE-2026-109618/19 | Calif, OpenAI, Wiz, lcfr-hax, tomash-areion | Those are the patched bugs; ours covers what survived |
| Patch team | arnaud-lb, iluuu1994, bukka, ndossche | — |

**Session injection technique class**: prior research ([Exploit-DB #50157](https://www.exploit-db.com/docs/50157)) used LFI to include the session file. We use serialize_handler format confusion — no LFI, different delivery vector. The php_binary variant, session-wipe, cross-tenant takeover, and stock-ini race are novel to this package.

---

## Disclosure

Unfiled at publication time. The choice is the author's.
