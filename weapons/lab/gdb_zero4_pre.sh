#!/bin/bash
# gdb reclaim check for vdR4_pre.php (prebuilt pattern) on jammy php8.1.2
cd /mnt/c/Users/andre/Downloads/php2shell-zeros/weapons/lab || exit 1
DBG=/tmp/dbgsym81/usr/lib/debug/.build-id/70/4040a392cd0a8b51f18d141caea86e97fa0197.debug
timeout 120 gdb -q -batch \
  -ex 'exec-file /usr/bin/php8.1' \
  -ex "symbol-file $DBG" \
  -x /mnt/c/Users/andre/Downloads/php2shell-zeros/weapons/lab/gdb_zero4_pre.gdb \
  --args /usr/bin/php8.1 -n vdR4_pre.php 0000000000000000 0000000000000000
