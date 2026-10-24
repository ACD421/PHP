# NativePHP Mobile 0-day Hunt — STATUS

Date: 2026-10-23 | Lane: nativephp (no overlap with php-core/mongo lanes)
Artifacts: RECON.md (source map), lab/ (harness + attack driver + orchestrator), receipts/ (5 logs)

---

## THE BUNDLED-VERSION VERDICT (decision-grade)

NativePHP Mobile ships prebuilt PHP from `bin.nativephp.com` (release 4.1.0 manifest, updated 2026-10-23):
- **PHP 8.4.27** (default) and **PHP 8.3.36** (optional) — both contain the October-2026 security
  patch (3584a98) that fixed CVE-2026-109618/109619. NativePHP patched fast.
- **BUT the var_destroy re-entry UAF (Wiz's n≈1015 gap, CWE-416) is UNPATCHED in 8.5.12 and
  therefore in 8.4.27/8.3.36.** Pure-`unserialize()` trigger, no session/multipart/ini needed.
  Lab-proven below through the NativePHP delivery surface on fully-patched 8.5.12 — the same
  var.c/var_unserializer.c code the shipped binaries carry. Older installs (4.0.0 = php8.4.24,
  pre-patch) are vulnerable to BOTH chain families.
- Runtime shape: ZTS embedded in-app, no web server, no sockets (JNI/scheme-handler only).

## WHAT FIRED (receipts in receipts/)

Lab = faithful mini-clone of the framework surface (NativeCallController, FileFunctions raw-path
copy, AsyncFunctions.Dispatch arbitrary-id, AsyncTaskRunner raw unserialize, asset handler,
event controller) driven purely over HTTP — the same requests a page in the app's webview makes.

1. **[PASS] VD UAF via full framework delivery** (nativephp_vd_asan.log):
   HTTP upload (app file-save) → `POST /_native/api/call File.Copy` (raw paths) → spool poison →
   `POST /_native/api/call AsyncTask.Dispatch` → runner lane `unserialize()` → **ASAN
   heap-use-after-free**, canonical stack: `var_destroy:319 → i_zval_ptr_dtor → destructor →
   re-entrant unserialize → var_unserializer.c:906 READ on freed 8160-byte block`. On
   fully-patched 8.5.12.
2. **[PASS] Manifest crash via pure HTTP delivery** (nativephp_vd_glibc.log): runner dies
   mid-unserialize, exit=139 (SIGSEGV, glibc heap wild write).
3. **[PASS] Attacker-chosen pointer control via full HTTP delivery** (nativephp_vd_controlled_ptr.log):
   staged spool payload → SIGSEGV in `php_var_unserialize_internal` with
   **rax = 0x4242424242424242** — full forged-zval* control, ASLR-free (vd3-class CONTROLLED
   receipt, delivered through the bridge, not a local script).
4. **[PASS] Standalone critical #1 — arbitrary sandbox file exfiltration** (nativephp_exfil.log):
   `File.Copy` any sandbox file → `public/` → `GET /_assets/...` returns it. No memory bug needed.
5. **[PASS] Standalone critical #2 — event forgery** (nativephp_eventforgery.log):
   `POST /_native/api/events` fires `PaymentCompleted` with attacker-chosen orderId/amount —
   `new $eventClass(...$payload)` with class_exists gate only (arbitrary-object-instantiation
   gadget surface on top).

## WHAT'S DEAD (checked, negative)

- Original rfc1867/pre-RINIT CVEs: patched in shipped binaries + embed SAPI parses multipart
  in PHP userspace, in-memory (no tmp files) — no rfc1867 lane at all.
- Cross-app localhost socket (Android): no socket; all requests go through JNI interception.
- GlobalEventTransport signature forgery: APP_KEY is per-install SecureRandom in
  Keystore/Keychain (AppKeyStore.kt), purpose-prefixed HMAC, hash_equals — solid gate.
- Binary-manifest tampering: Ed25519-signed manifests + SHA-256-pinned zips at install.
- Direct remote attacker-bytes-into-unserialize with zero app-side premise: every sink
  (GlobalEventTransport, NativeCallbacks cache, AsyncTask spool) is key/cache/disk-gated.
  The delivery needs the File.Copy bridge hole (webview-content premise) + any app file-save.

## THE FRAMEWORK 0-DAYS (source-proven, mobile-air @ main)

1. **CRITICAL — Ungated bridge + raw-path File.Move/File.Copy.** `POST /_native/api/call`
   (no middleware, no CSRF, no auth; cross-origin form-POST = simple request = no preflight)
   reaches every registered bridge function. `FileFunctions.kt`/`.swift` take raw filesystem
   paths with zero validation. Any content in the app's webview (remote iframe — loads in-app
   by design on both platforms; any embedded remote webview; XSS; adb webview debug —
   `WebContentsDebuggingEnabled(true)` in release builds) = arbitrary sandbox file move/copy
   = exfiltration (copy to public/ + /_assets read-back), state corruption/DoS, and poisoning
   of every unserialize sink.
2. **CRITICAL — Poisonable unserialize lane.** `AsyncTaskRunner::runTask` unserializes
   `storage/framework/async/payload/{id}.task` raw (no allowed_classes; only closures inside
   are signed — task class + args are not), and `AsyncTask.Dispatch` is a bridge function
   taking an arbitrary id. File.Copy + Dispatch = attacker bytes into `unserialize()` on the
   bundled PHP → VD UAF (receipts 1-3 above) → RCE. Envelope also carries the task class name
   → classic phpGGC Laravel POP chains apply wherever the app has a destructor gadget.
3. **HIGH — `POST /_native/api/events` event forgery.** `new $eventClass(...$payload)` +
   `event()` fires any app event with attacker args (PaymentCompleted, TokenGenerated,
   UpdateInstalled, scanner/camera results) — logic-level auth bypass in every app trusting
   these; arbitrary-object-instantiation gadget surface besides.
4. **MEDIUM — `AndroidPOST` JS interface** exposed to every frame incl. remote iframes
   (addJavascriptInterface): `storeCsrfToken` poisons the native CSRF token;
   `beginBody/appendBody/commitBody` inject arbitrary POST bodies onto the app's own
   subsequent requests (request forgery).
5. **INFO — iOS scheme handler serves php://127.0.0.1 to any page/frame in the webview**
   (their own form-stash comment confirms other-origin requests reach it; only preflightable
   custom headers are blocked). Android equivalent via shouldInterceptRequest.

## FULL-RCE CHAIN STATE

Leak→write→call (vdR1/R2/R3 → zif_system → uid receipt) did NOT re-fire in today's lab
environment — the same layout-lottery failure hits the ORIGINAL pwn_zero4.sh wrapper on this
box (leak oracle returns 0x0; D→CHUNK offset and reclaim coverage drifted with the
environment). This is the known open gap on our side (in-band bootstrap mapped, not
implemented), NOT a NativePHP defense. The full chain is receipted in poc_matrix/
(vdR1/2/3 receipts, pwn_zero4 original PASS). What IS receipted here end-to-end through the
NativePHP surface: UAF trigger (ASAN), memory-corruption crash (SIGSEGV), and full
forged-pointer control (rax=0x4242…) — i.e., the framework delivers the primitives; chain
completion is our env-tuning problem.

## PREMISE STRENGTH (what an app needs for each bug)

- File.Copy exfil + event forgery (bug 1+3): attacker content in ANY webview the app shows.
  Framework enables remote iframes in-app by design; embedded `<webview>` of remote URLs is a
  first-class feature; release webview debugging is on.
- RCE (bug 1+2): the above + ANY app feature that persists user bytes to a file (uploads,
  imports, exports, media saves) + an app destructor gadget for the VD trigger (or any
  phpGGC Laravel POP gadget for the non-memory-corruption path — no gadget needed for
  crash/DoS).

## NEXT MOVES (if Andrew wants to push)

1. Report to NativePHP (security@nativephp.com / their SECURITY.md): bugs 1-4 are
   framework-level, fixable (path allowlist in File.*; sign/auth the async spool envelope or
   key it to a dispatch nonce; restrict /_native/api/* to same-origin webview requests with a
   native-issued token; drop addJavascriptInterface exposure to subframes).
2. The "zero" for the PHP-core lane stands regardless: any NativePHP app with the premise =
   unpatchable-by-them memory-corruption RCE until PHP fixes var_destroy re-entry (their
   bundled 8.4.27/8.3.36 inherit it).
3. Optional deepening: map the EDGE `<webview>` element URL policy (web-ui/mobile-ui repos)
   to nail the "remote content loads in-app" premise framework-wide; audit mobile-ota plugin
   (private repo) for update-signature gaps.

## FILES

- RECON.md — full source map, sinks, gates, architecture
- lab/harness.php — NativePHP-shaped app (NativeCallController/File/AsyncTask clones)
- lab/runner.php, lab/runner_rce.php — AsyncTaskRunner clones (plain + staged RCE gadget)
- lab/attack.py — HTTP attack driver (chain/exfil/events/calib/rce modes)
- lab/run_lab.sh — 4-pass receipt orchestrator
- receipts/nativephp_vd_asan.log, nativephp_vd_glibc.log, nativephp_vd_controlled_ptr.log,
  nativephp_exfil.log, nativephp_eventforgery.log
