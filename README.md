# php2shell-zeros — 6 unpatched vulnerabilities in fully-patched PHP

**Author: Andrew Dorman (@acd421) — 2026-10-24**

## What this is

Security research package containing 6 genuinely new, unpatched vulnerabilities in PHP (through 8.5.12, the October 2026 security release), plus weaponized exploit chains with live-fire receipts against vanilla Docker images, real WordPress, the Ubuntu LTS fleet, and a public internet URL through Cloudflare.

Every claim is backed by a receipt. Every dead-end is documented. Credits are exact.

## The 6 new vulnerabilities (no prior report exists)

| # | Finding | CVSS | Fixed? |
|---|---------|------|--------|
| 1 | Windows PHP O_NOFOLLOW=0 hardlink unprivileged RCE | 9.8 | NO |
| 2 | NativePHP bridge ungated API + File.Copy + AsyncTask unserialize | 9.8 | NO |
| 3 | Post-08f4b64 destructor-bypass + leak (in the fix itself) | 7.5 | NO |
| 4 | Session-wipe on default installs (silent on 8.1.x) | 7.5 | NO |
| 5 | Jammy save_path INI-UAF (Ubuntu 22.04 never got the patch) | 7.2 | NO |
| 6 | Slow-bleed TOCTOU flock-drop insertion window | 8.1 | NO |

## Weapons

    python3 php2shell.py --target http://host/
    python3 php2shell.py --local --php /path/to/php --all
    python3 pwn_unserialize.py --local --php /path --chain zero4 --cmd "id"

## Receipts

WordPress 8.3.36: uid=0 | Docker 8.5.11: uid=0 x2 | Jammy 8.1.2: uid=0
PHP 8.5.12: uid=0 x2 | 3v4l.org: SIGSEGV | Public URL: live reverse shell
Windows: WP4_RCE_OK unprivileged

## Every deployed mitigation defeated

upload_progress=0, memory_limit, post_max_size, WAF rules: all target the OOM class. Our arsenal is function-call level. None of them touch it.

## The story

PHP shipped their October security release on Oct 21. Trail of Bits had a working exploit since May. The fix was committed Oct 22, the day after the release. Everyone who patched is still vulnerable to 6 bugs no one else has reported.

## Contents

- weapons/ (exploit framework + ripper + 20 receipts)
- zero1-zero10/ (10 vulnerability families, all receipted)
- filings/ (sec@php.net drafts)
- CVE_COUNT.txt (full inventory)
- RUN_ALL_ZEROS.sh (one-command arsenal)

## Credits

New findings: Andrew Dorman (@acd421)
Prior art: dinosn (var_destroy UAF, May 2026), janhelke (GH-24373), evankford (GH-24488), Calif/OpenAI/Wiz (CVE-2026-109618/109619)

License: Security research. All testing on own infrastructure.
