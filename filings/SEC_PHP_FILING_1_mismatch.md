# Security filing: session serialize_handler read/write mismatch → attacker-controlled object injection → RCE (survives 8.5.12/8.4.27/8.3.36/8.2.35)

**To:** security@php.net
**From:** Andrew Dorman <acd421>
**Date:** 2026-10-21
**Disclosure:** coordinated — no public release of this filing's details before your advisory, at your discretion given same-day ecosystem publication of related class names.

## Summary

When a PHP deployment's session WRITE path and READ path use different
`session.serialize_handler` values (per-dir `php_value`, per-vhost ini,
`.htaccess`, or app-level `ini_set()` between routes), an attacker who can
cause any attacker-controlled string to be persisted into `$_SESSION` gets
a fully attacker-chosen PHP object constructed and executed on the READ
path: `__wakeup()` fires during construction and `__destruct()` fires
during the decode-failure teardown. Verified end-to-end with unauthenticated
RCE receipts (`uid=` over HTTP) on PHP 8.5.12 (built from the release
tarball today) and on Ubuntu's fully-patched 8.1.2-1ubuntu2.27 under
Apache/mod_php.

The 8.5 write-side key validation ("Failed to write session data. Data
contains invalid key") does not mitigate this: the payload travels as a
session VALUE (not key) under the `php_serialize` encoder, and the `php`
decoder (PS_SERIALIZER_DECODE_FUNC(php)) unserializes everything after the
first `|` it finds. The decode then fails on trailing wrapper bytes,
`php_session_cancel_decode()` → `php_session_destroy()` — and the
destruction itself invokes the attacker object's `__destruct()` with
attacker-chosen properties. A fatal-error stack trace receipt shows the
attacker class destructor invoked from inside `session_start()`.

## Affected

All current releases: 8.2.35, 8.3.36, 8.4.27, 8.5.12 (and all earlier).
Requires: differing handlers between write and read paths + any
attacker-controlled string persisted raw into `$_SESSION` (user prefs,
form echo, tokens...). Escalation to RCE needs one application gadget
class with a side-effectful destructor (demonstrated: file-write gadget
→ webshell → `uid=0(root)`).

## Repro (CLI, no server needed)

```
# WRITE route: ini_set('session.serialize_handler','php_serialize');
#   $_SESSION['userpref'] = 'inj|O:7:"EvilObj":2:{s:3:"cmd";s:5:"BINWR";s:4:"note";s:5:"pwned";}';
# READ route: default php handler, class EvilObj defined with
#   __wakeup/__destruct writing marker files.
# Result: both marker files created; var_dump shows the object with
# attacker properties; hexdump of sess_ file shows payload at a value
# position inside serialize($_SESSION).
```
Full self-contained script + Apache RCE receipts:
`zero1_session_gaps/repro/mm_cli_8512.sh`, `fin_8512.sh`, `ap_lab.sh`
(T1/T2/T3 include stock-inini race variants), logs in `receipts/`.

## Suggested fix

`PS_SERIALIZER_DECODE_FUNC(php)` must not construct objects from content
that did not parse under a strict `key|serialized-value` grammar: validate
the complete record structure before invoking `php_var_unserialize()`,
and do not destroy the session (executing attacker destructors) when the
failure is a format confusion between encoder formats — clear the data
without object construction.

## Credit / prior art

Technique class public since the mid-2010s; the surviving-gap status on
patched releases named publicly by the Wiz research team's disclosure
companion repo (2026-10-21). The 8.5.12 receipts, the decode-failure-
executes-`__destruct` behavior, stock-ini race delivery, and the RCE
chains here are my independent work (agent-assisted), 2026-10-21.
