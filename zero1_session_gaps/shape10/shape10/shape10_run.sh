#!/bin/bash
# shape10_run.sh — MISSION 10 receipt run: mixed-handler crossfire escalation.
#   pass 1 (plain 8.5.12): all five shapes (a1, a2, b, c, ctl)
#   pass 2 (ASAN 8.5.12):  injection shapes (a1, a2, b) — decode + destroy
#                          teardown of the poisoned files under ASAN
set -u
S10=/mnt/c/Users/andre/Downloads/php2shell-claude/wp2/shape10
REC=/mnt/c/Users/andre/Downloads/php2shell-claude/wp2/receipts

echo "############ shape10 pass 1: plain 8.5.12 — all shapes ############"
python3 "$S10/shape10_attack.py" 2>&1 | tee "$REC/shape10_plain_run.log"
P1=${PIPESTATUS[0]}

echo
echo "############ shape10 pass 2: ASAN 8.5.12 — injection shapes ############"
python3 "$S10/shape10_attack.py" --asan 2>&1 | tee "$REC/shape10_asan_matrix.log"
P2=${PIPESTATUS[0]}

echo
if grep -q "AddressSanitizer" "$REC"/shape10_asan_matrix.log 2>/dev/null; then
  echo "[FAIL] ASAN report in the ASAN pass — inspect shape10_asan_matrix.log"
  exit 1
fi
if [ "$P1" = 0 ] && [ "$P2" = 0 ]; then
  echo "[PASS] shape10: crossfire escalated to weaponizable primitives (all shapes, ASAN-clean)"
else
  echo "[INFO] rc plain=$P1 asan=$P2 — see $REC logs"
fi
