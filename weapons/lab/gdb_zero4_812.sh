#!/bin/bash
# gdb discovery for zero4 on jammy php8.1.2 (stripped binary + distro dbgsym)
cd /tmp/pwn_unserialize_4emul8u6 || exit 1
DBG=/tmp/dbgsym81/usr/lib/debug/.build-id/70/4040a392cd0a8b51f18d141caea86e97fa0197.debug
timeout 120 gdb -q -batch \
  -ex 'exec-file /usr/bin/php8.1' \
  -ex "symbol-file $DBG" \
  -x /mnt/c/Users/andre/Downloads/php2shell-zeros/weapons/lab/gdb_zero4_812.gdb \
  --args /usr/bin/php8.1 -n vdR3_call.php 0000000000000000 0000000000000000
