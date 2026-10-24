#!/bin/bash
# gdb the weapon's rendered zero4 carrier (latest workdir) on jammy php8.1.2
D=$(ls -dt /tmp/pwn_unserialize_* | head -1)
echo "DIR=$D"
cd "$D" || exit 1
ls -la
DBG=/tmp/dbgsym81/usr/lib/debug/.build-id/70/4040a392cd0a8b51f18d141caea86e97fa0197.debug
timeout 120 gdb -q -batch \
  -ex 'exec-file /usr/bin/php8.1' \
  -ex "symbol-file $DBG" \
  -x /mnt/c/Users/andre/Downloads/php2shell-zeros/weapons/lab/gdb_zero4_pre.gdb \
  --args /usr/bin/php8.1 -n vdR3_call.php 0000000000000000 0000000000000000 2>&1 \
  | grep -vE 'warning|auto-load|safe-path|gdbinit|info "|add-auto|To enable|To completely|Thread debugging|libthread_db|^$|No such file' \
  | head -25
