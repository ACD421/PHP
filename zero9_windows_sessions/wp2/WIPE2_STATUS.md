# Finding C pass 2 — invalid-key reject path: memory-corruption hunt CLOSED (DoS-only)

Verdict: **no memory-corruption primitive reachable through the poisoned-key window.**
No OOB / UAF / double-free / leak was produced across the entire envelope below on
ASAN PHP 8.5.12 (`/tmp/php8512_build/asan2/sapi/cli/php`, `USE_ZEND_ALLOC=0`,
`ASAN_OPTIONS=detect_leaks=0:abort_on_error=1`). The lane closes as DoS-only
(unauth session-file wipe / delete), with four behavioral addenda (section 4) that
upgrade Finding C's *detection* and *blast-radius* story without changing its class.

Lab: `wp2/*.sh|py|php` here; artifacts under `/tmp/p2s_c2/` (WSL), durable copies in
`wp2/receipts/`. The ASAN CLI built-in server (`php -S`) drives the full chain —
`wp2_gdb.sh` proves `sapi_handle_post -> rfc1867_post_handler -> php_session_rfc1867_callback
-> php_session_rfc1867_update -> php_session_flush -> php_session_save_current_state
-> ps_srlzr_encode_php` (frame receipt in `receipts/gdb_live_key.log`).

## 1. Root mechanics (source-verified + syscall-receipted)

- Poisoned key = `upload_progress_` + raw POST bytes (any bytes incl. `\x00`, any
  length) inserted as a live `zend_string` HashTable key at session.c:3192
  (`zend_hash_update(sess_var, progress->key.s, &progress->data)`).
- Reject: `PS_SERIALIZER_ENCODE_FUNC(php)` session.c:1090 — `memchr(ZSTR_VAL(key),
  PS_DELIMITER, ZSTR_LEN(key))` per key during `PS_ENCODE_LOOP`; on hit:
  `smart_str_free(&buf)`, E_WARNING, `return NULL`.
- The wipe is a *deliberate* empty write, not open-truncation drift:
  `php_session_save_current_state` session.c:543-551 — `val == NULL` ->
  `PS(mod)->s_write(&PS(mod_data), PS(id), ZSTR_EMPTY_ALLOC(), ...)` ->
  `ps_files_write`: `ZSTR_LEN(val)=0 < st_size` -> `ftruncate(fd,0)` -> `pwrite(fd,"",0,0)`.
- strace receipt (plain 8.5.12, `receipts/strace_reject_path.log`), per rfc1867 update:
  `openat(sess_*, O_RDWR|O_CREAT|O_NOFOLLOW)` -> `flock(LOCK_EX)` -> E_WARNING ->
  `ftruncate(fd,0)` -> `pwrite64(fd,"",0,0)`; subsequent updates pwrite "" only
  (st_size already 0); FILE_END cleanup write emits no warning (empty session encodes
  to NULL without any invalid key).
- gdb live-key receipt (`receipts/gdb_live_key.log`): at the reject,
  `key = 0x7ffff5401300, len=24, bytes = "upload_progress_Abc|O:10"` (pipe at offset
  19), `fail = true`, locals `_ht/_zv/struc` intact — the raw POST bytes are a live
  hash key in the encode walk, exactly as the coordinator's survey stated.
- Structural limit (kills the multi-key angle at the source): MULTIPART_EVENT_FORMDATA
  guard `if (Z_TYPE(progress->sid) && progress->key.s) break;` — once sid+key exist,
  later `PHP_SESSION_UPLOAD_PROGRESS` parts cannot re-key; one request can inject at
  most ONE poisoned key into `$_SESSION`. (sid-after-key ordering, sid-as-form-field,
  and sid-via-GET were all tried; `fm_parts3/10`, `fm_prog_after`, `fm_prog_mid` fuzz
  cases behave identically to single-part.)
- Hash/rehash angle: inserts happen *between* flushes (each update re-decodes then
  inserts); during the encode walk itself no modification occurs (`PS_ENCODE_LOOP`
  ZVAL_COPY guard). No rehash-during-iteration surface exists.

## 2. Exact envelope tested, per surface

### S1 — live poisoned-key window (ASAN, `wp2_fuzz_keys.py` + `wp2_extralong.sh` + `wp2_chaos.py`)
- Content classes (13): pipe-at-end / pipe-at-start / all-pipes / NUL-run+pipe /
  pipe+NUL-run / NUL-pipe-NUL / high-bytes 0x80-0xFF / 0x7F runs / UTF-8 multibyte /
  all 256 byte values / serial-shaped (`inj|O:14:"SplObj":2:{...}`) / %-format-string
  heavy (`%s%n%p` mix) / no-pipe control.
- Lengths (34): 1,2,3,7,8,9,15,16,17,31,32,33,63,64,65,127,128,129,255,256,257,511,
  512,1023,1024,4096,8192,16384,32768,65536,1e6,4MiB,8MiB,16MiB (16MiB key => the
  encode-loop `smart_str_append` allocates then frees a 16MiB buf on reject; clean).
- Structure: 1/3/10 progress fields, progress-after-file, progress-between-files,
  1-10 file parts, 0-byte file part, sid-as-form-field, no-cookie, Content-Length lie.
- Config: cleanup 0/1, freq 1 / -1% / 1000000, min_freq 0/1, prefix default/empty/
  `|x|`/300P+pipe. (Note: `php -d` values are constant-expression-parsed — a `|` in a
  -d value mangles the ini; all values go through a generated php.ini.)
- Modes: full / slow-trickle / abort (CLI server buffers the body, so abort and
  CL-lie never reach the parser — those are Apache-only, see S5) / ENOSPC-abort.
- Chaos bomb: 4 threads x 60s, randomized binary keys (len 1..200000, forced pipe +
  NUL), 3517 requests -> 2764 wipes, 742 keeps (no-pipe keys), 11 other (victim-file
  write races between threads), 0 ASAN, server alive.
- Result: pipe key => warning + 0-byte file, always; no-pipe => intact; zero ASAN,
  zero crashes, zero divergence across all of the above.

### S2 — reject-path file operations (`wp2_strace.sh`, `wp2_diskfull*.sh`, `wp2_readonly.sh`)
- Ordering receipt above.
- Disk-full (256KiB tmpfs): reject with 8KiB free (clean); `upload_tmp_dir` inside the
  full-ish fs with the upload temp file ENOSPCing mid-file — the abort-mid-upload +
  reject combination — FILE_START fires before temp-file creation, so the reject+wipe
  commit even though the upload dies: clean; true session-write ENOSPC (7888B victim,
  8KiB free): `Write wrote less bytes than requested` + `Failed to write session data
  (files)` error path under ASAN — clean, and the partial file is then unlinked by the
  NEXT update's decode-failure (see A3); completely full fs: reject still completes
  (0-byte writes need no space), warning emitted on 8.5.12.
- Broken save_path: nonexistent dir, save_path-is-a-file, `/proc/1`, `/proc/sys/kernel`
  (root cannot bypass procfs EACCES): open-failure path clean. chmod-based readonly
  was defeated by running as root — noted, not a distinct memory surface (initialize
  aborts before any poisoned-key handling).
- php_binary write-side round trip (pipe key, obj victim): no pipe check exists in
  `PS_SERIALIZER_ENCODE_FUNC(php_binary)`; trace shows open -> pread 379 -> ftruncate(0)
  -> pwrite 52 (final file == original victim bytes). Deterministic 10/10.

### S3 — empty/truncated-file decode matrix (`wp2_decode_matrix.sh`, 69 files x 3 handlers)
- php: 0B, `|`, letter, letter+`|`, `|i:1;` (empty key), pair, truncated tail after
  valid pair, truncated value at 4 depths, 0x80/0x81 keys, NUL-in-key, NUL-only key,
  pipe-in-key, 64KiB key, 64KiB key + `|`, object/array values, progress-shaped key,
  two pairs, negative int, s:495250 length lie, int overflow length, partial string,
  b:/N:/R:/r: values.
- php_binary: 0B, namelen 0x00/0x80/0xFF (UNDEF-flag mask), namelen 1 with no name /
  name only, namelen 127 short/name-only/full, 0xFF + 127-byte name + full/short
  value, two entries with truncated 2nd, pipe in name, NUL in name, 0x83 flag byte,
  entry+garbage, namelen 2 partial, nested value.
- php_serialize: 0B, empty/partial arrays at 5 truncation depths, truncated string
  (2 depths), truncated object (2), object w/o closing brace, NUL key, pipe key,
  s:495250 / s:9223372036854775807 length lies, unknown-class object, 4-deep nesting,
  R:1 / R:900 refs, bare N, progress-shaped value.
- Result: all clean; failures take `php_session_cancel_decode` -> "Session has been
  destroyed" exactly as designed. Live production race on top: 541 poison wipes raced
  against 2 concurrent ASAN readers doing 612,370 + 613,304 `session_start` cycles on
  the same sid (438K successful decodes each, rest mid-wipe) — zero ASAN on all three
  processes (`receipts/reader*.log`, `race_srv_err.log`).

### S4 — T4 warning anomaly (angle 4) — RESOLVED
- 8.5.12 CLI: 200x ASAN loop + 200x plain loop -> warn+wipe 400/400, 0 divergence.
  On 8.5.x the warning is an inseparable side effect of the reject (same code block).
- Ubuntu 8.1.2-1ubuntu2.27 (`php -v` 8.1.2-1ubuntu2.27, mod_php libphp8.1.so): the
  invalid-key reject EXISTS but is SILENT — no E_WARNING is ever emitted. CLI probe
  (`wp2_verprobe.sh`): pipe key in $_SESSION -> session file 0 bytes, no warning.
  Apache full+abort loops (100+100): wipe 100%, `invalid key` count 0.
  **The single '[FAIL] T4: no invalid-key warning' in receipts_Apache_lab.log is the
  expected 8.1.2 behavior, not a one-run anomaly** — the original T4 receipt log
  actually records FAIL(no warning)+PASS(wipe) as its outcome. Version window:
  8.1.2-ubuntu silent; 8.5.11 and 8.5.12 warn (exact introduction version between
  8.1 and 8.5 not pinned).
- My own pass-2 "[FAIL] no warning" reproductions (df_pipe, cx_php_v_php_pipe_nc,
  early crossfire runs) were harness port collisions — a stale server held the port,
  the request hit the orphan (same wipe, different log), while the harness grepped the
  new server's empty logs. Fixed with a port-free wait + bind-failure detection; every
  affected case re-run clean. Same class of race (restart + grep timing) is the most
  plausible generator for any similar one-off in the original lab.

### S5 — mixed-handler crossfire (`wp2_crossfire.sh`, 108/108 cases)
3 write/read handlers x 12 victim formats x {pipe, no-pipe, pipe+cleanup=0}:
php / php_serialize / php_binary formats; victims incl. self-referencing object
(`r:1;`), array-of-object, multi-key, pre-poisoned pipe key, `__PHP_Incomplete_Class`
source (unknown class), php-verified valid hex throughout.
- Reader-format mismatch during the rfc1867 touch -> decode failure ->
  `php_session_destroy` -> **victim session file UNLINKED** (deleted, not truncated).
- php_serialize / php_binary write sides accept pipe keys -> poisoned key persists
  (T2 family; no memory surface).
- Objects survive the pre-RINIT incomplete-class round trip cleanly; zero ASAN.
  (3 cases dropped by a port collision in the batch run were completed individually:
  php_binary+binobj+pipe -> round-trips to original bytes (10/10 deterministic);
  php_serialize+binobj+nopipe -> mismatch-unlink; php_binary+binobj+pipe+cleanup=0
  -> poisoned key persists at 412B.)

## 3. Memory-surface conclusions

1. The only attacker-controlled bytes inside the encode walk are the key
   (length-delimited zend_string; memchr is length-bounded; the E_WARNING `%s`
   truncates at NUL by design of vspprintf) and serialized VALUES produced by
   php_var_serialize itself. No raw attacker bytes reach pointer arithmetic.
2. Error paths (encode-NULL write, ENOSPC partial write, open failure, decode
   failure/destroy, temp-file failure mid-upload) are all exercised under ASAN and
   clean. Refcounting across the update loop (Z_TRY_ADDREF + update-steal + END
   SEPARATE_ARRAY of progress->data with the post-bytes_processed pointer) is
   balanced by inspection and by the 3,517-request chaos bomb.
3. Concurrency is process-level (flock per update); in-process there is no shared
   mutable state a second request can race. The file-level race is closed by S3's
   1.2M-decode ASAN race.

## 4. Behavioral addenda that ship with Finding C (non-memory)

- A. SILENT WIPE on 8.1.x: zero log lines on Ubuntu 8.1.2 — error-log detection of
  the wipe primitive is impossible there; on 8.5.x the warning is a reliable detector.
- B. DELETE escalation: if the victim session is in any other handler's format (or
  already corrupt/truncated, e.g. after an ENOSPC partial write), the same unauth
  upload-progress touch UNLINKS the victim session file instead of wiping it.
- C. Abort-immunity: the wipe commits at FILE_START's first update; killing the
  connection mid-upload (or the upload temp file ENOSPCing) never rolls it back.
- D. Full-disk immunity: the wipe path performs only 0-byte writes; it succeeds on a
  completely full filesystem where a legitimate session write would fail.

## 5. Rigor gaps / not covered

- chmod-readonly as non-root (root bypasses permission bits in the lab); covered
  instead via procfs save_path.
- Exact PHP version that introduced the invalid-key E_WARNING (between 8.1.2 and
  8.5.11) — not pinned; empirical window only.
- mod_php-level ASAN (no ASAN Apache build); Apache used for behavioral receipts
  only (abort/abort-warning/8.1 silence).
- DoS-by-hash-collision amplification (zend_inline_hash_func) — out of memory-safety
  scope; no amplification primitive beyond raw key bytes exists.
