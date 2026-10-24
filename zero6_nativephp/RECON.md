# NativePHP Mobile — 0-day Recon (Phase 1)

Date: 2026-10-23 | Operator: acd421 | Scope: NativePHP for Mobile (nativephp.com, Laravel-ecosystem)
Repos cloned: `nativephp/mobile-air` (core, tags 3.3.4 → 4.6.0, main ahead of 4.6.0), `nativephp/laravel`, `nativephp/web-ui` (browser dev renderer)

---

## 1. BUNDLED PHP VERSION — THE VERDICT (decision-grade)

Binaries pinned in `src/Support/PhpBinaries.php` (`VERSION = '4.1.0'` at time of clone; main has moved past 4.6.0), fetched from `https://bin.nativephp.com/{branch}/{release}.json` (Ed25519-signed manifests, SHA-256 per zip).

**Live manifest `https://bin.nativephp.com/main/4.1.0.json` (updated 2026-10-23) ships TWO PHP lines:**
- **PHP 8.4.27** (default) — `ios/android/macos-4.1.0-php8.4.27{,-icu}.zip`
- **PHP 8.3.36** (optional pin) — `ios/android/macos-4.1.0-php8.3.36{,-icu}.zip`

**Both 8.4.27 and 8.3.36 CONTAIN the October-2026 security patch (3584a98, fixed our CVE-2026-109618/109619 upstream in 8.2.35/8.3.36/8.4.27/8.5.12).** NativePHP bumped binaries on/before 2026-10-23 — they are patched against the two embargoed CVEs.

**BUT the VD re-entry UAF (var_destroy re-entry at n≈1015-1018, the Wiz-named gap, CWE-416) is UNPATCHED in 8.5.12 and therefore unpatched in 8.4.27/8.3.36.** Our receipts (poc_matrix/vd1b, vd4, pwn_zero4 wrapper) fire it with pure `unserialize()` of crafted data — no session, no multipart, no ini. **Any NativePHP mobile app that gets attacker-shaped bytes into `unserialize()` = memory-corruption RCE on current binaries.** Older installs (4.0.0 = php8.4.24, pre-patch) are vulnerable to BOTH chain families.

Runtime shape: ZTS (thread == TSRM context), embedded SAPI in-app process, no web server, no sockets. iOS = `php://127.0.0.1` WKURLSchemeHandler; Android = `http(s)://127.0.0.1` shouldInterceptRequest interception. **No localhost socket on Android** (all through JNI bridge) — the cross-app-socket lane is dead.

---

## 2. ARCHITECTURE (how data flows mobile → PHP)

Two app modes:
- **v4 "SuperNative" (EDGE)**: PHP embedded in-process, single main lane runs a runloop (`nativephp_element_wait_event()`), UI tree binary-rendered by SwiftUI/Compose. Events arrive via a native event queue (JNI: `NativeElementBridge.postNativeEventToQueue` / `sendNativeEvent`).
- **WebView/php-mode (v1-v3 legacy + still shipped)**: app pages served at `php://127.0.0.1` (iOS) / `http://127.0.0.1` (Android) from the embedded Laravel; webview fetches hit the persistent runtime via `BridgeDispatcher` → `RequestFactory::make()` (synthesizes Symfony/Laravel Request: query, parsed body, cookies, server, php://input-equivalent body).
- **Lanes**: main UI lane, per-webview dedicated PHP contexts (WebviewPHPRuntime, own executor thread + TSRM context), async task lane (runner = separate PHP context, work handed over via serialized file on shared disk), queue worker lane (PHPQueueWorker). Cross-lane events = `GlobalEventTransport` (serialize + HMAC-SHA256 with APP_KEY + base64 in JSON, posted under fixed name `__global_event`).

APP_KEY: generated **per-install** (SecureRandom/Keystore on Android, Keychain on iOS — `AppKeyStore.kt`), handed to PHP via env (`DeviceAppKey::apply`). NOT baked into the binary → signature gates are strong against remote attackers.

**Mobile attacker surfaces:** deep links/universal links (DeepLinkRouter → route or `__deeplink` native event), push payloads, QR/scanner, share intents, webview JS (any content loaded in the app's webviews), remote servers the app talks to (mobile-vibe websockets etc. = plugins).

---

## 3. unserialize()/serialize() INVENTORY (framework code)

| Sink | File | Gate | Attacker bytes? |
|---|---|---|---|
| `GlobalEventTransport::receive()` :317 | src/Support/GlobalEventTransport.php | HMAC-SHA256(app key) BEFORE unserialize; comment explicitly says webview JS can call Event.Broadcast | **No** (key is per-device Keystore) — gate is solid |
| `NativeCallbacks::resolve()` :106 | src/Support/NativeCallbacks.php | `unserialize(Cache::pull('native_cb:'.$id.':'.$eventClass))` — cache contents written only by `register()` (serialize of app closures) | Not directly — **but key parts ($id, $eventClass) are attacker-chosen via POST /_native/api/events; cache-poisoning via file-write = in** |
| `AsyncTaskRunner::runTask()` :55 | src/Support/AsyncTaskRunner.php | **raw `unserialize($payload)` of `storage/framework/async/payload/{id}.task` file, no allowed_classes, no signature on envelope** (only closures inside are HMAC-signed; task class+args are NOT) | **Not remotely — needs disk write.** Runner then does `app($class)->handle(...$args)` with envelope-chosen class |
| `AsyncTaskTransport` | writePayload/readPayload | 0700 dir, app-private disk | needs file write |
| Laravel cookies | EncryptCookies | decrypt-or-drop (APP_KEY) | No |
| Laravel session/queue/cache | app-managed | server-side | app-dependent |

**Delivery trigger that IS remote:** bridge function `AsyncTask.Dispatch` (registered, callable from webview JS via `/_native/api/call`) takes an arbitrary `id` string and runs the runner for whatever spool file has that name. `AsyncTask.Complete` takes an arbitrary event FQCN + payload and posts it as a native event.

---

## 4. THE ACTUAL FRAMEWORK HOLES FOUND (source-proven)

### 4a. `/_native/api/call` + `/_native/api/events`: unauthenticated, CSRF-exempt, bridge-shaped routes
`routes/api.php` (loaded via spatie `hasRoute('api')` — no middleware group, no CSRF, no auth):
- `POST /_native/api/call` → `NativeCallController` → `nativephp_call($method, $paramsJson)` gated only by `nativephp_can()` = "is the method registered".
- `POST /_native/api/events` → `DispatchEventFromAppController` → **`new $eventClass(...$payload)` with attacker-chosen class (class_exists check only) + attacker args** → `event($event)` (fires real app listeners — e.g. `Events\Wallet\PaymentCompleted` forgery) → `fireCallback` → `NativeCallbacks::resolve` (cache unserialize above).
- Reachable by **any content in the app's webview**: Android `shouldInterceptRequest` intercepts ALL `127.0.0.1` requests from any origin/frame in the webview; iOS `PHPSchemeHandler` serves `php://127.0.0.1` to any page in the webview (its own form-stash comment: "The custom header keeps other origins out: they can't send it without a CORS preflight" — i.e., other-origin requests DO reach the handler; only preflightable custom headers are blocked). Cross-origin **form-encoded POST = simple request = no preflight = executes** (response unreadable, side effects fire). Nested params work form-encoded (`params[from]=x&params[to]=y`).

### 4b. `File.Move` / `File.Copy`: raw filesystem paths, ZERO validation (both platforms)
`FileFunctions.kt` / `FileFunctions.swift`: `File(from)`, `File(to)` — no sandbox check, no canonicalization, no allowlist. Callable from any webview content via 4a. Consequences:
- **Arbitrary sandbox file read**: copy `database.sqlite` / `.env` / `storage/framework/sessions/*` / logs / async spool into `public/`, then fetch `/_assets/...` (asset handler serves `Documents/app/public/**` with no restriction — iOS: `appPath + "/public/" + relativeAssetPath`).
- **Arbitrary file corruption/DoS** (move DBs mid-write).
- **Poison the unserialize sinks**: copy attacker bytes over `storage/framework/async/payload/{id}.task` → `AsyncTask.Dispatch({id})` → runner `unserialize()` → **our VD chain → RCE**. Same for file-cache entries (`storage/framework/cache/data/{hash}` — hash computable, key `native_cb:{id}:{eventClass}` is attacker-chosen) → `POST /_native/api/events` → `NativeCallbacks::resolve` → `unserialize()`.

### 4c. `AndroidPOST` JS interface exposed to every frame (Android)
`WebViewManager.kt:537` `addJavascriptInterface(JSBridge, "AndroidPOST")` — no origin gating (addJavascriptInterface semantics): any remote iframe in the webview can call `storeCsrfToken` (poison the native-held CSRF token applied to subsequent requests), `beginBody/appendBody/commitBody` (inject arbitrary POST bodies keyed by URL/request-id — forge bodies onto the app's own subsequent requests to PHP).

### 4d. Remote content CAN live in the app webview
- Android: main-frame remote http(s) → system browser; **subframe/iframe remote → loads in-app** (only `isForMainFrame` is gated). `mixedContentMode = ALWAYS_ALLOW`, `allowFileAccess = true`.
- iOS: main-frame remote → `UIApplication.shared.open` (Safari); **non-listed schemes (`data:`, `blob:`, `about:`, anything custom) → `.allow` → loads in-app**.
- The EDGE `<webview>` element (php-mode embedded webviews, `WebviewPHPRuntime`) exists as a framework feature; URL policy per web-ui/mobile-ui (not fully mapped — secondary).
- WebView config: `WebContentsDebuggingEnabled(true)` in RELEASE builds (WebViewManager.kt:99) — adb-accessible webview debug on any retail device = another bridge-in.

### 4e. Event forgery (logic level)
`AsyncTask.Complete` (bridge) + `POST /_native/api/events` let webview content fire ANY registered event class with ANY payload (`PaymentCompleted`, `TokenGenerated`, `UpdateInstalled`, scanner/camera results...) — every app that trusts these events for state transitions is logic-compromised. `new $eventClass(...$args)` = arbitrary-object-instantiation gadget surface on top.

### 4f. What's SOLID (gates that held)
- `GlobalEventTransport` HMAC gate (per-device Keystore key, purpose-prefixed, hash_equals) — remote can't forge signed lanes.
- Binary manifests: Ed25519-signed, SHA-256-pinned (install-time).
- Async spool: 0700 dirs, owner-only files.
- `AppKeyStore` Keystore/Keychain handling.
- Off-host redirects from PHP main-frame → external browser (both platforms) — no main-frame remote in-app via redirect.
- Deep links: file URLs ignored; http(s) universal links internalized to app routes.

---

## 5. SECURITY HISTORY
No published CVEs for NativePHP mobile found in-repo (SECURITY.md = standard GitHub template). The bridge design docs (native-callback-api-design.md, async-task-design.md, event-channel-pointer-refactor.md) show repeated hardening passes around the webview/bridge boundary (signature on cross-lane events, CSRF-token plumbing, form-stash CORS comment) — the authors KNOW webview content is hostile, but the `File.*` raw-path functions + unauthenticated `/_native/api/*` routes shipped anyway.

---

## 6. PHASE 2 PLAN (what fires, what's dead)

**DEAD LANES:**
- Original CVE-2026-109618/19 (rfc1867 pre-RINIT bailout): patched in shipped binaries (8.4.27/8.3.36) + no rfc1867 on the embed SAPI anyway (multipart is parsed in PHP userspace, in-memory — `MultipartParser.php`; no tmp files).
- Cross-app localhost socket (Android): no socket, all JNI.
- GlobalEventTransport signature forgery: per-device Keystore key.
- Direct attacker-bytes-into-unserialize with zero prerequisites: no framework-universal path (all sinks are key/cache/disk-gated).

**THE LIVE CHAIN (framework 0-day, weaponizable with our VD UAF):**
1. Premise (app-level, common): attacker content in the app's webview (remote iframe — loads in-app by design; any embedded webview of remote content; XSS in an app page; adb webview debug on retail builds) — OR any malicious app on a rooted/jr-modified context is not needed; the webview premise alone suffices.
2. Webview JS → simple cross-origin POST `/_native/api/call` (`method=File.Copy`, `params[from|to]`, form-encoded) → arbitrary file copy in sandbox.
3. Attacker bytes on disk (any app file-save feature — uploads are the common case; or cookie/localStorage artifacts on some apps) → copy to `storage/framework/async/payload/{uuid}.task`.
4. POST `/_native/api/call` (`method=AsyncTask.Dispatch`, `params[id]=uuid`) → runner lane does `unserialize()` on our bytes → **VD re-entry UAF (unpatched in 8.4.27) → leak/write/forged-object → zif_system → RCE**.
5. Standalone (no memory bug needed): step 2 alone = full sandbox file exfiltration (copy to public/ + fetch /_assets/) + event forgery (PaymentCompleted etc.) + arbitrary class instantiation — critical on its own for any app whose webview ever touches untrusted content.

**Phase-2 lab:** simulate the surface with their bundled PHP (8.4.x build in WSL) + a minimal harness replicating: NativeCallController route → File.Copy raw → spool → AsyncTaskRunner::runTask unserialize → VD payload. Receipt = command-execution marker file. PoCs adapted from `poc_matrix/` (vd1b/vd4 triggers, pwn_zero4.sh wrapper pattern).
