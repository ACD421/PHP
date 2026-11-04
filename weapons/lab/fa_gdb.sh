#!/bin/sh
# fa_gdb.sh — gdb capture of the dance crash (8.3.36 container CLI)
gdb -q -batch \
  -ex 'set pagination off' \
  -ex 'run -n /tmp/fa/fa_probe.php 2' \
  -ex 'bt 18' \
  -ex 'info registers rdi rsi rax rbx' \
  -ex 'x/4i $pc' \
  /usr/local/bin/php 2>&1 | tail -50
