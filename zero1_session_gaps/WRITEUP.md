# Unauthenticated RCE and session-wipe on fully-patched PHP via surviving session-handling gaps (CVE-2026-109618/19 patch class)

**Andrew Dorman (@acd421) — 2026-10-21**
**Status: works on PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (today's fully-patched releases). Unfiled with the PHP project at time of writing.**

## Abstract

The October 21, 2026 PHP security releases (fixing CVE-2026-109618 / CVE-2026-109619) closed the memory-corruption class but left two session-handling gaps open on every patched branch. Neither requires memory corruption; both are pure logic bugs, ASAN-clean, and both were verified end-to-end today with unauthenticated `uid=` receipts over HTTP — including one chain against the freshly built php-8.5.12 itself and one against a stock-ini Apache/mod_php stack with **no configuration prerequisites** beyond defaults. A third primitive, an unauthenticated session-wipe, works against completely default installs.

1. **serialize_handler read/write mismatch → attacker-chosen object injection.** Any deployment where the session write path and read path use different serialize handlers (per-dir `php_value`, per-vhost ini, `.htaccess`, or app-level `ini_set()` between routes) lets an attacker land a fully-controlled serialized object at a value position the `php` decoder unserializes. PHP 8.5's "Session has been destroyed" hardening does not prevent execution: the destruction itself invokes the attacker object's `__destruct()` (receipt includes a fatal-error stack trace showing the attacker class destructor invoked from inside `session_start()`), and `__wakeup()` fires during construction. The pure-`php`-handler pipe-in-key write variant IS closed on patched builds (verified, both 8.1.2-1ubuntu2.27 and 8.5.12) — the mismatch variants are not.
2. **session.upload_progress key injection → pre-script object injection.** The rfc1867 hook writes `upload_progress_` + the raw `PHP_SESSION_UPLOAD_PROGRESS` multipart field value into the session file **verbatim, before any script runs** (ext/session/session.c:3265-3269 on php-8.5.12 — `smart_str_appendl(&progress->key, *data->value, value_len)`, no filtering). When the write side runs `php_serialize` (the "modern" per-dir/vhost configuration), the poisoned key is persisted inside `serialize($_SESSION)` and any `php`-handler read unserializes it as an object. Against **stock ini** (cleanup=1, strict_mode=1), the slow-upload concurrent-read race defeats the cleanup. This corrects the public record: same-day research asserting this class is "patched in 8.5.12" tested only the closed pure-`php` variant.
3. **Unauthenticated session-wipe (default installs).** Even when the invalid-key check rejects the write, the open-then-reject sequence truncates the victim's session file to 0 bytes with a single unauthenticated multipart POST.

## Root cause (php-8.5.12 source)

- `php_session_rfc1867_callback` (ext/session/session.c:3265-3269): the upload-progress key is `prefix + raw field value`. No grammar validation on the value.
- `PS_SERIALIZER_DECODE_FUNC(php)` (session.c:1136+): splits on the first `|`, unserializes the remainder — any format confusion puts attacker bytes at an unserialize position.
- `PS_SERIALIZER_ENCODE_FUNC(php)` (~session.c:1093): rejects keys containing `|` at write time (the 8.5 hardening) — but this only guards the pure-`php` write path, not `php_serialize` writes, and the reject-truncate sequence is the wipe primitive.
- On decode failure: `php_session_cancel_decode()` → `php_session_destroy()` → object destruction → attacker `__destruct()` executes.

## Receipts (all from 2026-10-21 runs, raw logs in receipts/)

```
[A5 RCE receipt on 8.5.12] -> uid=0(root) gid=0(root) groups=0(root)     # php-8.5.12 build, key injection + gadget
[T1 RCE receipt] -> uid=0(root) ...   # app ini_set mismatch -> gadget webshell (Apache 8.1.2 stack)
[T2 RCE receipt] -> uid=0(root) ...   # per-dir php_value php_serialize upload dir
[T3 RCE receipt] -> uid=0(root) ...   # ALL-STOCK session ini, slow-upload race, read #1
[B2 RCE receipt] -> uid=0(root) ...   # no-POP variant: save_path in docroot, session file executed
[PASS] A0 ... object(EvilObj)#1 ...   # attacker object retained in $_SESSION + __wakeup/__destruct markers
[T4] victim session file -> 0 bytes   # unauth session-wipe, default ini
[C1] negative control: no mismatch -> key stays inert string, no object, no shell
```

Session-file hexdumps (receipts_A3_upload_8512.log) show the poisoned key persisted verbatim by the 8.5.12 rfc1867 hook. ASAN build runs clean — pure logic bug, orthogonal to the CVE-2026-109618/19 memory class.

## Reproduce

Build (once): see package README (php-8.5.12 tarball, standard configure with session+simplexml).

- `bash repro/fin_8512.sh` — A0 (object-injection receipt, CLI) + A5 (full RCE over HTTP on 8.5.12). Self-contained; stand up its own php -S lab, prints PASS lines and the `uid=` receipt.
- `bash repro/mm_cli_8512.sh` — mismatch matrix on 8.5.12 + 8.1.2 including the closed variant.
- `bash repro/ap_lab.sh` — the Apache/mod_php T-series (T1/T2/T3/T4/B2 + controls). Requires the Ubuntu Apache+mod_php stack.
- Client used for upload racing: `repro/up_client.py`.

## Victim requirements (minimum)

- Finding 1: differing serialize handlers between write and read paths + any attacker-controlled string persisted into `$_SESSION`.
- Finding 2: `session.upload_progress.enabled=1` (default) + `php_serialize` write side (per-dir/vhost ini — the recommended "modern" configuration) + a `php` read path; with stock cleanup, the slow-upload race applies.
- Finding 3: defaults only.
- RCE escalation needs one gadget class in the application (any destructor with a side effect — file write demonstrated) or a save_path/docroot overlap. Real applications universally carry suitable destructor classes.

## Fix recommendation

1. Validate the upload-progress key against a strict grammar (e.g. `[A-Za-z0-9_-]{1,128}`) before it ever reaches the session, or reject the write entirely on invalid input without opening/truncating the file.
2. In `PS_SERIALIZER_DECODE_FUNC(php)`, refuse to unserialize any value that did not parse under a strict `key|serialized-value` grammar — do not construct objects from cross-format content before validating the whole file.
3. Do not truncate/destroy the session file before a successful encode of the replacement content.

## Credits

- **Findings, 8.5.12 survival receipts, stock-ini race, on-build RCE, session-wipe primitive, controls, and write-up:** Andrew Dorman (@acd421), with Claude (Anthropic) agent tooling, 2026-10-21.
- **Gap naming (public record that these survive the patch):** the Wiz research team's coordinated-disclosure companion repo (2026-10-21) listed "serialize-handler mismatch" and "upload-progress key injection" as surviving gaps without demonstration.
- **Race technique shape (drip-fed upload + concurrent read):** public same-day research against 8.5.11; the public record's "patched in 8.5.12" conclusion is corrected here with receipts (the pure-`php`-handler variant is closed; the `php_serialize` write side and stock-ini race are not).
- **Legacy technique class** (session injection via upload progress / serialize_handler confusion): documented in public PHP security research since the mid-2010s (OWASP PHP Object Injection). This write-up's contribution is the demonstration that the class survives the 2026-10-21 security releases in specific, reproducible shapes.
- **Context — the original CVE research** that today's patch shipped for: Calif (Ryan A), OpenAI, Wiz, lcfr-hax, tomash-areion, et al. (per GHSA-w8hw-w9fx-j79w / GHSA-6wmf-4rv5-p3rp credits).

## Disclosure timeline

- 2026-10-21 ~21:50 UTC: gaps verified on 8.5.12 with RCE receipts (this package).
- Unfiled with php-src at publication time. php-src #24488 (unrelated GC regression, see zero2) filed same-day by evankford.

## Finding C pass-2 characterization (2026-10-23: rigorous closure + addenda)

376 ASAN shots, 3,517-request randomized chaos bomb, 541-wipe/1.2M-decode
race, 108-crossfire matrix, disk-full and abort paths — ZERO memory
corruption: the reject path is DoS-only, closed with receipts
(wp2/WIPE2_STATUS.md). Mechanism receipted: the wipe is a deliberate
empty write — encode NULL -> php_session_save_current_state (session.c:543)
writes ZSTR_EMPTY_ALLOC() -> ps_files_write ftruncate(0) (strace receipt).
Behavioral addenda:
1. SILENT on Ubuntu 8.1.x — reject never logs a warning (200 Apache runs,
   100% wipe, 0% warnings): error-log detection impossible; 8.5.x warns.
2. DELETE escalation — handler mismatch or pre-corrupted victim session
   turns the same touch into an UNLINK.
3. ABORT-IMMUNE — the wipe commits at FILE_START; connection kill never
   rolls it back.
4. FULL-DISK-IMMUNE — 0-byte writes only; the wipe succeeds where
   legitimate session writes ENOSPC.
