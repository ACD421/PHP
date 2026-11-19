# php2shell-zeros

Publication-ready security research: unpatched vulnerabilities in PHP, NativePHP Mobile, and Windows PHP builds. Turnkey repro scripts, raw receipts, weaponized exploit chains.

**Authors:** [@acd421](https://x.com/acd421) · [@J4ck3LSyN](https://x.com/J4ck3LSyN) · [@ArchKnight23](https://x.com/Archknight23)
**Date:** 2026-10-24

> **First defensive report on the surviving flaws:**
> **[Red Eye Security — Coordinated Vulnerability Disclosure](https://threat-intelligence.redeyesecurity.com/blog/php2shell-part-two-surviving-php-flaws-2026)**
> They broke the story first.

---

## Vulnerability Inventory

| # | Finding | CVSS | Attack Vector | Status | Folder |
|:-:|---------|:----:|--------------|:------:|--------|
| 1 | var_destroy re-entry UAF | **9.8** | Remote via `unserialize()` — O:, C:, E: enum autoload, session decode (flock-drop) | 🟢 Fixed | `zero4/` |
| 2 | serialize-side mirror UAF | **9.8** | Remote via `serialize()` | 🟢 Fixed | `zero5/` |
| 3 | Enum-autoload E: UAF | **9.8** | Remote via session decode | 🟢 Fixed | `zero7/shape5/` |
| 4 | NativePHP bridge RCE | **9.8** | Remote via bridge API | 🟢 Patched | `zero6/` |
| 5 | Session serialize_handler RCE | **8.1** | Remote (config-dependent, CVE-2026-115560) | 🟢 Fixed | `zero1/` |
| 6 | php_binary format injection | **8.1** | Remote (third delivery format) | 🟢 Fixed | `zero1/shape10/` |
| 7 | Windows `O_NOFOLLOW`=0 RCE | **7.7** | Local (no privilege needed) | 🔴 Not fixed | `zero9/` |
| 8 | GC double-free → controlled call | **7.5** | Remote crash + attacker-chosen call | 🟢 Fixed | `zero2/` |
| 9 | C: format crasher | **7.5** | Remote DoS (141 classes) | 🔴 Not fixed | `zero7/` |
| 10 | Session-wipe | **7.5** | Remote unauth DoS | 🔴 Not fixed | `zero1/` |
| 11 | Slow-bleed TOCTOU | **7.5** | Remote DoS + RCE insertion window | 🟡 Partial | `zero10/` |
| 12 | Jammy fleet composition | — | Ubuntu 22.04 LTS — all above, chained | 🔴 Not fixed | `zero8/` |

**CVSS 3.1 computed from formula.** Full details: `CVE_COUNT.txt`

**NativePHP (zero6):** reported via RedEye CVD; fixed 2026-10-25 in `nativephp/mobile 4.6.1` + `nativephp/mobile-file 1.0.3`. Advisories (6 credited to acd421): `GHSA-9884-fw9c-mq85`, `GHSA-7927-vv5p-fv4f`, `GHSA-3w4w-cchh-qvrw`, `GHSA-83jv-8h7x-287p`, `GHSA-9g37-88p8-75j2`, `GHSA-76px-r497-93p9`.

**As of PHP 8.5.13** (also 8.4.28, 8.3.37, 8.2.36; advisories 2026-11-19, 8:05 AM America/Chicago). [Changelog](https://www.php.net/ChangeLog-8.php#8.5.13). [GH-24373](https://github.com/php/php-src/issues/24373) and [GH-24488](https://github.com/php/php-src/issues/24488) are in the `php-8.5.13` tag; the published changelog omits those NEWS lines. The post-08f4b64 teardown / lock-strand leftover (`CVE_COUNT`) is still unpatched in that tag. CVE-2026-129182 is a follow-on to the October PHP2Shell backtrace fix (CVE-2026-109619), already treated as closed in 8.5.12 — not counted as a new match here.

- 1 / 2: [GH-24373](https://github.com/php/php-src/issues/24373) / [08f4b64](https://github.com/php/php-src/commit/08f4b64e0ae69e51ca95b54717dc74405ba5f0f9). Row 1 entries, all closed at this tag by 08f4b64 (context NULLed before `var_destroy`, independent of format or sink): direct `unserialize()` of `O:` (WordPress HTTP, Docker, public URL); `C:` custom-serialization second entry (shape12, 5/5 uid=0); session decode with no app unserialize sink, including flock-drop (shape34, 6/6). `E:` enum-autoload as an entry into the same destroy-walk UAF (finish/mission 2; also row 3) is closed by 08f4b64 (repo `fixedasan` receipt) and additionally locked by [b4a63ec](https://github.com/php/php-src/commit/b4a63ecd709ba6452be84c2842b475d8384f82c6). Row 1 also likely [GH-24433](https://github.com/php/php-src/issues/24433) / [2b99297](https://github.com/php/php-src/commit/2b99297b76457100e1688e49697bb0e6a5124327) (vd4 / incomplete records). The `C:` empty-object crashers remain row 9 (still open); they are not a leftover of this UAF.
- 3: enum-autoload context lock [b4a63ec](https://github.com/php/php-src/commit/b4a63ecd709ba6452be84c2842b475d8384f82c6).
- 5 / 6: [CVE-2026-115560](https://github.com/php/php-src/security/advisories/GHSA-658j-r8rw-q6mx) / [522afb6](https://github.com/php/php-src/commit/522afb690fd0c8a23f0b0bbe3d9ee1564599d59c) (row 6 is the shape10 php_binary path).
- 7: still broken — `O_NOFOLLOW` is still `#define`d to 0 under `PHP_WIN32`; uid check still `#ifndef PHP_WIN32`.
- 8: [GH-24488](https://github.com/php/php-src/issues/24488) / [5bd92da](https://github.com/php/php-src/commit/5bd92da0abd34fe141938ac44d137eea060bbd0c); upstream [f963484](https://github.com/php/php-src/commit/f9634847258a8c3ed6c12bb79104eba60bb631ea).
- 9 / 10 / 12: still broken (row 9: FC-1 empty-object crashers; row 12: Ubuntu jammy packaging, not php-src).
- 11: likely partial — [CVE-2026-126714](https://github.com/php/php-src/security/advisories/GHSA-fm2m-fjf5-v3cp) / [2139e7e](https://github.com/php/php-src/commit/2139e7e6ceb03eca00bda03bb7da57da6cb33cf8); DoS leftovers still broken (C:-format worker kill, flock-hold lockout, no-Content-Disposition part-counter bypass).

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
| All findings, receipts, weapons | [@acd421](https://x.com/acd421), [@J4ck3LSyN](https://x.com/J4ck3LSyN), [@ArchKnight23](https://x.com/Archknight23) | — |
| var_destroy UAF (zero4) | dinosn ([May 2026](https://github.com/dinosn/php-8.5.5-var_destroy-uaf)) | They published first; we weaponized on vanilla stripped binaries, added C: entry, WordPress HTTP, flock-drop, public URL chain |
| Serialize re-entry (zero5) | janhelke ([GH-24373](https://github.com/php/php-src/issues/24373)) | They reported the crash; we built the first escalation to full RCE |
| GC regression (zero2) | evankford ([GH-24488](https://github.com/php/php-src/issues/24488)) | They found the bug; we receipted remote kill + controlled indirect call |
| Gap naming | Wiz research team | They named gaps without demonstration; we provided the first receipts |
| CVE-2026-109618/19 | Calif, OpenAI, Wiz, lcfr-hax, tomash-areion | Those are the patched bugs; ours covers what survived |
| Patch team | arnaud-lb, iluuu1994, bukka, ndossche | — |

**Session injection technique class**: prior research ([Exploit-DB #50157](https://www.exploit-db.com/docs/50157)) used LFI to include the session file. We use serialize_handler format confusion — no LFI, different delivery vector. The php_binary variant, session-wipe, cross-tenant takeover, and stock-ini race are novel to this package.

---

## Disclosure

Findings were emailed to security@php.net on Oct 24, 2026 at 12:57 AM CDT (America/Chicago) after public release, pointing at this repo. PHP did reply: a two-week thread (Oct 24–Nov 5) with Ilija Tovilo, Jakub Zelenka (bukka), Stanislav Malyshev, and Elizabeth Barron. The published 8.5.13 advisory for CVE-2026-115560 credits ZEST / Dvir Sasson, not this report.

Ilija Tovilo (Oct 24):

> Yes, the PoC is based on your report that was responsibly reported by somebody else, likely based on your finding. And yes, they will get the credit for it when the CVE is published, because that's how it works. You don't publish findings on X and expect credit.

> Reporting on X does not count as a report. ... We accept reports via security@ and GHSA, nothing else.

Jakub Zelenka (Nov 5):

> We give credit to anyone who reports the security issues and does not disclose it before the advisory is published. We require 90 days embargo which was broken here. Also it has to be done through the GitHub advisory because that's where we collect it (you were not the first one who found it btw so your report is just a duplicate but if you didn't disclose it, we would still give you a credit).

Jakub also wrote that the published `security-classification.rst` is "completely outdated and incorrect," that "The current rules are not actually written anywhere properly," and that the stub PR (php-src #25146) "does not yet mention this new crediting rule and some other bits."

## PHP Group CNA — policy vs practice

Record from the Oct 24–Nov 5 security@ thread and a Nov 5 Root complaint to Kevin Harwood (INL / MITRE Top-Level Root), requesting review under CNA Operational Rules 1.2.3.1, 3.2.6.1, 3.2.6.2 and the CVE Program Code of Conduct. This does not claim rule 5.2.4 forces finder credit. As of Nov 19, 2026, no reply from INL, MITRE, or cve.org has been received.

1. **Inaccurate published guidance.** The published php-src `security-classification.rst` promises "When published, you will be credited as a contributor." Jakub Zelenka admitted that document is "completely outdated and incorrect" and that "The current rules are not actually written anywhere properly." CNA rules 3.2.6.1 / 3.2.6.2 require accurate published guidance.

2. **Retroactive attribution rule.** Policy commit de06991 / PR #40 ("Irresponsible disclosure will result in the report not being attributed to you") was added around Nov 2, 2026, and applied to work disclosed Oct 24.

3. **Admitted PoC lineage, then credit denial.** Ilija Tovilo admitted the CVE-2026-115560 PoC was "based on your finding," but credit on the Nov 19 advisory went to the formal-channel refiler (ZEST / Dvir Sasson). The CVE Record Format separates finder from reporter; rule 5.2.4 makes description credit optional, so a lineage admission does not automatically assign finder credit to the refiler.

4. **Embargo and intake terms not in the published policy.** A "90 days embargo" and "GHSA-only" intake were asserted, though the published policy accepts security@php.net and post-fix disclosure.

5. **Code of Conduct.** Derogatory language in CNA correspondence. Ilija Tovilo (Oct 24):

> Just because Calif fucked up doesn't mean you should too.

The dispute was dismissed as "ego stroking" by Stas Malyshev.

6. **Uneven precedent.** Another party's lane was credited after a leak, while the admitted PoC source was denied.
