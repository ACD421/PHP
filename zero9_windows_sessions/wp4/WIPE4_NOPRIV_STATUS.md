# Finding C pass 4 — privilege requirement KILLED: hardlink lane needs NO privilege in ANY Windows context; unpriv RCE receipted in every default deployment shape

Verdict: **the "needs SeCreateSymbolicLink / admin / dev-mode" caveat on the zero9
Windows chain is dead.** NTFS *hard links* carry the same primitives with **zero
privilege and zero access to the target file**: `mklink /H`, PowerShell
`New-Item -ItemType HardLink`, `python os.link`, and **PHP's own `link()` (stock
8.5.12 and 8.1.34 windows.php.net builds, `bool(true)` under a filtered token)** all
plant `sess_<sid>` hard links. End-to-end webshell chains were receipted with the
plant performed (a) under a filtered (non-elevated) token, (b) by a separate
**standard user** (`wp4ten`, created standard, since deleted), and (c) against a
server running as **NT AUTHORITY\SYSTEM** (service context, `WP4_RCE_OK[nt
authority\system]`). The dangling-symlink W6 arbitrary-create shape additionally
works **unprivileged on any Dev-Mode box** via `python os.symlink` (which passes
`SYMLINK_FLAG_ALLOW_UNPRIVILEGED_CREATE`) — receipted with Dev Mode toggled ON and
boundary-tested OFF (WinError 1314). Only PHP's own `symlink()` is useless as a
planter (never requests unprivileged-create; also rejects dangling, `../` and
absolute-form targets even elevated).

**Updated zero9 claim line (replaces the WIPE3 precondition sentence):**

> Precondition: ANY local write access to the session save_path directory. Hardlink
> planting requires **no privilege and no access to the target file** (CreateHardLink
> succeeds against readonly-attribute, write-denied, and RX-only targets; same volume
> only). Symlink planting additionally requires SeCreateSymbolicLink OR Dev Mode
> (python/PowerShell/cmd planters — not PHP `symlink()`). The HTTP trigger remains
> one unauth multipart POST. Applies to every stock Windows PHP build independent of
> patch state (O_NOFOLLOW=#define 0 at mod_files.c:85-90, uid check #ifndef
> PHP_WIN32 at 194-207).

## 1. Write semantics enumerated (which write carries attacker bytes)

Per-update lifecycle (each rfc1867 update = open `sess_<sid>` O_RDWR|O_CREAT →
flock → read → decode → insert `upload_progress_<KEY>` → encode → write → close;
source `php_session_rfc1867_update`/`php_session_initialize`, wp2 strace receipts):

| Write | Trigger | Content | Attacker bytes? | Hardlink effect |
|---|---|---|---|---|
| update write | first + every subsequent rfc1867 update | `orig_vars` + `upload_progress_<KEY>\|a:5:{...}` (pwrite@0, truncate to len) | **YES** (the KEY, pipe-free) | overwrites the target file in place |
| reject write | KEY contains `\|` → php-handler encoder refuses (`memchr(key, PS_DELIMITER)`) → `val == NULL` → **deliberate empty write** | `ftruncate(fd,0)` + `pwrite(fd,"",0,0)` | no | **zeroes the target through the shared inode** (H2) |
| FILE_END cleanup=1 | cleanup removes progress var → re-encode of remaining vars | the target's original decoded session bytes (empty session encodes to NULL → empty write) | no | **restores original bytes** (H3 = W4 parity); kills the shell if original was empty (H8: final 0 bytes) |
| FILE_END cleanup=0 | final forced update retains progress var | `orig_vars` + `upload_progress_<KEY>\|a:5:{...}` | **YES, persists** | the webshell lands and stays (H4/H5) |
| abort mid-upload | streaming SAPI only (php -S buffers bodies) | last committed update write, no FILE_END | YES, persists | pass-2 addendum C, Apache lane |

8.5.12 emits `PHP Warning: PHP Request Startup: Failed to write session data. Data
contains invalid key "upload_progress_A|B"` on every reject (28 in the H-matrix
server log); 8.1.34 is **silent** (0) — wp2 addendum A parity on Windows.

## 2. Hardlink matrix (H-series) — stock 8.5.12 AND 8.1.34, identical results

Server: stock zips, ZTS, `php.exe -S`, ini default handler `php`,
`use_strict_mode=0`, upload_progress default-on; plant = `cmd mklink /H`
(`python os.link` fallback); trigger = one unauth multipart POST with
`PHP_SESSION_UPLOAD_PROGRESS` + attacker sid cookie.

| Shot | Setup | Result (both builds) |
|---|---|---|
| H1 | regular sess file + pipe key (control) | sess wiped to 0 (Finding C parity) |
| H2 | **hardlink** → decodable target (`pref\|s:6:"keepme";`) + pipe key | **TARGET ZEROED** through the shared inode (reject empty-write ftruncate); hardlink name SURVIVES (nlink stays 2 — reject path never unlinks) |
| H3 | hardlink → decodable target + clean key, cleanup=1 | final == original bytes (FILE_END cleanup rewrite = W4 restore parity); link survives |
| H6 | hardlink → no-pipe php target (`<?php echo "REAL";`) + pipe key | decode FAILS (php-handler decoder: no `\|` found → FAILURE) → destroy unlinks **link name only**; target intact, nlink 2→1 (negative receipt, source-predicted) |
| H8 | hardlink → EMPTY target + payload key, cleanup=1 | shell written during updates, **wiped to 0 at FILE_END** (empty re-encode → empty write) — receipts why cleanup=0/abort is required |
| **H4** | **hardlink → docroot/empty.php (0 bytes) + `<?php ... shell_exec($_GET["c"]) ... ?>` key + cleanup=0** | **457-byte webshell written into docroot; `GET /empty.php?c=whoami` → `WP4_RCE_OK[andre]`** |
| **H5** | **hardlink → docroot/sessfmt.php (non-empty decodable) + payload + cleanup=0** | final = `pref\|s:6:"keepme";upload_progress_<?php ... ?>\|a:5:{...}` (475 B) — **original session vars prefix the shell; GET → RCE** |

Receipts: `receipts/{8512,8134}_hardlink_matrix.log`, `{8512,8134}_h4_shell.php`,
`{8512,8134}_h5_shell.php`, per-shot client logs, `{ver}_hardlink_srv.log`.

## 3. Plant capability audit (who can plant, under what token)

Filtered token = `runas /trustlevel:0x20000` (receipted: only
`SeChangeNotifyPrivilege` — no SeCreateSymbolicLink, no admin):

| Tool (filtered token) | hardlink | symlink (existing) | symlink (dangling) |
|---|---|---|---|
| cmd `mklink /H` | **OK** | n/a | n/a |
| PowerShell `New-Item -ItemType HardLink` | **OK** | n/a | n/a |
| python `os.link` | **OK** | n/a | n/a |
| python `os.symlink` (Dev Mode ON) | n/a | **OK** | **OK** |
| python `os.symlink` (Dev Mode OFF) | n/a | **WinError 1314** privilege-not-held | **WinError 1314** |
| **PHP `link()` 8.5.12 / 8.1.34** | **bool(true) / bool(true)** | n/a | n/a |
| **PHP `symlink()`** (Dev Mode ON) | n/a | **false — "Permission denied"** (never requests unprivileged-create) | false — ENOENT (existing-target requirement) |

PHP `symlink()` Windows quirks (elevated probe, stock builds): absolute-path
targets → ENOENT; `../`-form relative targets → ENOENT; dangling → ENOENT; only
same-dir relative existing targets work (and only when privileged). **Conclusion:
PHP-exposed `link()` = remote hardlink plant; PHP `symlink()` is never a planter.**

**CreateHardLink target-access matrix (B-series, filtered token):** hardlink
creation succeeded against (B0) normal, (B1) **readonly-attribute**, (B2)
**ACL deny write-data+append**, and (B3) **RX-only** targets. The plant needs only
write on the save_path directory + same-volume target visibility. The
server-identity O_RDWR-open requirement is the only target-side gate for the
zero/write primitives (no uid check — `#ifndef PHP_WIN32`).

Dev Mode boundary: `AllowDevelopmentWithoutDevLicense` toggled 0x1→0x0→0x1 (state
restored and verified): OFF = symlink planters die with 1314 while hardlinks still
work; ON = dangling symlink plants return.

## 4. Deployment contexts (X-series, full chains)

| Context | Plant | Server identity | Receipt |
|---|---|---|---|
| X1 interactive-admin | filtered token hardlink → docroot/empty.php | andre | 455-B shell, `WP4_RCE_OK[andre]` (`x1_x3_unpriv_chain.log`) |
| X3 Dev-Mode box | filtered token **dangling symlink** via python → docroot/shell9.php (W6 shape) | andre | 455-B shell created at arbitrary path, `WP4_RCE_OK[andre]` |
| X2 service/SYSTEM (XAMPP-service shape) | filtered token hardlink → andre-owned docroot/sys.php | **NT AUTHORITY\SYSTEM** (schtasks) | 460-B shell, **`WP4_RCE_OK[nt authority\system]`** — cross-owner write (SYSTEM writes andre-owned file), plant by another token class |
| X4 multi-tenant co-tenant | **wp4ten** (separate STANDARD user, `mklink /H`, since deleted) into shared save_path (granted (M)) | andre | 455-B shell, `WP4_RCE_OK[andre]` (`x4_tenant_chain.log` + `wp4ten_plant.log`: `rasputin\wp4ten`, `MKLINK_RC=0`) |

`plant_receipts.log` lines were written **by the filtered-token processes
themselves**. X2 closes the WIPE3 "not covered" item "cross-owner zero/write with
a second principal" (writer SYSTEM ≠ owner andre; planter wp4ten ≠ owner andre in
X4). SAPI note: lab vehicle is `php -S` (rfc1867 + mod_files are RINIT/main code,
SAPI-independent, wp3 §2); XAMPP/Apache translation: service = SYSTEM context
(X2), console = interactive admin (X1), streaming SAPI additionally enables the
abort-persistence variant with stock cleanup=1 (pass-2 addendum C).

## 5. Cross-chain composition (vector 4)

The hardlink webshell's only real precondition beyond save_path write is **an
existing empty or session-formatted file at a web-executable path**. Both
already-receipted write primitives in this family supply it on Windows-PHP
targets:

- **zero1 / DeferredWriter** (rfc1867 key injection → `file_put_contents($path,
  $data)` destructor gadget; A5/T1/T2 receipts): writes an empty file (or any
  decodable content) to `docroot/x.php`, then zero9's hardlink write turns it into
  the shell — same runtime, same request surface, no privilege anywhere.
- **NativePHP Mobile `File.Copy`** (ungated `/_native/api/call` bridge, raw
  paths): copies a 0-byte file into `public/x.php` → same composition on the
  bundled ZTS PHP (any app file-save + webview-content premise per
  nativephp_lane/NATIVEPHP_STATUS.md).
- Conversely, on Dev-Mode boxes zero9's dangling-symlink shape **creates** the
  docroot file itself (X3) — no write primitive needed at all. Older NativePHP
  installs (4.0.0 = php8.4.24, pre-patch) are vulnerable to both chain families
  simultaneously; 4.1.0 binaries still carry the mod_files.c structural gaps.

## 6. Precise constraint set (hardlink lane vs symlink lane)

Weaker than symlinks:
- **Cannot create files** — the target must already exist (no W5/W6
  arbitrary-path create); the webshell needs a pre-existing empty or
  `name|serialized;`-format file at a web-executable path (naturally-present empty
  `.php` guards, or any file-write primitive, §5).
- Same NTFS volume only (save_path ↔ target; single-volume C:\ installs —
  cross-volume CreateHardLink fails by definition, H10 noted, only C: on this box).

Stronger than symlinks:
- **Zero privilege in every context** (B-series), **zero target access**
  (readonly-attr/deny-write/RX-only all plantable), PHP-exposed via stock `link()`.

Unchanged gates (both lanes):
- Target must decode under the active serialize_handler for the read gate — empty
  files and valid `name|serialized;` files decode; anything else (including
  no-pipe php source, H6) decode-fails → destroy unlinks the sess link name only,
  target untouched. Zeroing therefore means "zero any EMPTY or session-format
  file the server identity can open O_RDWR" (other apps' session stores = unauth
  cross-app session wipe).
- Write persistence needs cleanup=0 or upload abort (H8); pipe-free payload key;
  sid charset `[A-Za-z0-9,-]+`.

## 7. Not covered / next

- True stock XAMPP/Apache-mod_php end-to-end on Windows (not installed here;
  contexts requested — service/SYSTEM, interactive admin, Dev Mode — are all
  receipted on the stock php.net builds; abort-persistence on a streaming Windows
  SAPI remains asserted from pass-2 addendum C, not re-receipted).
- Server as a non-SYSTEM second principal writing an andre-owned target (X4 has
  the reverse: andre server, wp4ten plant; X2 has SYSTEM writer).
- `upload_tmp_dir` 0-byte temp files as self-supplied empty targets (name
  predictability) — untested.
- PharData/tar-extract symlink extraction on Windows PHP as a pure-remote planter
  (app-dependent) — untested.

## 8. File map

- `wp4_win_lab.sh` — H-series hardlink matrix driver (both builds)
- `wp4_deploy.sh` — phases B/X1/X3/X2/X4/H10 (`PHASE=<b|x1|x2|x4>` to re-run one)
- `wp4_plant.py` — filtered-token planter (hardlink|symlink via runas trustlevel)
- `wp4_unpriv.bat`, `wp4_access.bat`, `wp4_devmode.bat`, `wp4_sys.bat` — audit /
  access-matrix / dev-mode-boundary / SYSTEM-server helpers
- `receipts/` — all logs quoted above (matrix, access, devmode ON/OFF, unpriv
  audit, plant receipts, per-shot clients, dropped shells)
- `win_lab/{8512,8134,x1,sys8512,x4}/` — lab trees with server logs
