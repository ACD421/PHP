# Security filing: session.upload_progress key injection (unauthenticated, pre-script, survives 8.5.12 when write side is php_serialize) + unauthenticated session-wipe on default installs

**To:** security@php.net
**From:** Andrew Dorman <acd421>
**Date:** 2026-10-21
**Disclosure:** coordinated; note the same-day public record is partially
incorrect on this class ("patched in 8.5.12" — only the pure-`php`-handler
variant is closed; receipts below).

## Summary — Finding A (key injection → object injection → RCE)

The rfc1867 upload-progress handler stores `upload_progress_` + the raw
value of the multipart field `PHP_SESSION_UPLOAD_PROGRESS` as a
`$_SESSION` KEY, before any script runs, and persists it to the session
file at request startup. In php-8.5.12 (release source):
ext/session/session.c:3265-3269 —
`smart_str_append(&progress->key, PS(rfc1867_prefix)); smart_str_appendl(&progress->key, *data->value, value_len);`
— no grammar validation on the value.

When the session write side runs `php_serialize` (the recommended
per-dir/per-vhost configuration) the poisoned key is persisted inside
`serialize($_SESSION)` verbatim; any request whose read side uses the
`php` handler unserializes the embedded payload as an ATTACKER-CHOSEN
OBJECT. The application stores zero attacker-controlled session data —
the only attacker input is the multipart field value.

Stock-ini variant (cleanup=1, strict_mode=1): the slow-upload
concurrent-read race defeats cleanup — receipt shows injection landing on
read attempt #1 with all-default session ini. Full RCE receipts
(`uid=0(root)` over HTTP) on 8.5.12 and on Apache/mod_php 8.1.2-1ubuntu2.27.

## Summary — Finding B (unauthenticated session-wipe, DEFAULT installs)

With the default `php` write handler, the poisoned-key write is rejected
("Data contains invalid key") — but the open-then-reject sequence
TRUNCATES the victim's session file to 0 bytes. One unauthenticated
multipart POST wipes any victim session (logout/CSRF-state destruction;
receipt: victim session `pref|s:6:"keepme";` → 0 bytes).

## Affected

All current releases (8.2.35+). A: `session.upload_progress.enabled=1`
(default) + `php_serialize` write side + any `php` read path.
B: default installs, no configuration.

## Repro

`zero1_session_gaps/repro/ap_lab.sh` (T2 = A with per-dir php_value;
T3 = A with ALL-STOCK ini via race; T4 = B) and `fin_8512.sh` (A5 = A on
8.5.12 built-in server → webshell → uid receipt). Self-contained; logs in
`receipts/`. Session-file hexdump receipt (8.5.12, php_serialize write
side): `a:1:{s:145:"upload_progress_inj|O:14:"DeferredWriter":2:{...}`
— the pipe+object payload persisted verbatim by the patched build.

## Suggested fix

1. Validate the upload-progress key value against a strict grammar
   (e.g. `[A-Za-z0-9_-]{1,64}`) at session.c:3265 BEFORE constructing the
   key; reject the whole progress entry on violation.
2. Never truncate/destroy the existing session file when rejecting an
   invalid write (fixes B independently of A).

## Credit / prior art

Surviving-gap status named by the Wiz companion repo (2026-10-21);
same-day public research demonstrated the 8.5.11 include-race shape and
asserted 8.5.12 closure — corrected here with receipts (pure-`php`
write-side pipe keys ARE rejected; the `php_serialize` write side and the
stock-ini race are open). Legacy technique class public since the
mid-2010s. The 8.5.12 survival receipts, stock-ini race, session-wipe
primitive, object-injection escalation, and controls here are my
independent work (agent-assisted), 2026-10-21.
