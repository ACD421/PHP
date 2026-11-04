#!/bin/bash
# gdb reclaim check for vdR4_pre.php (prebuilt pattern) on jammy php8.1.2
LAB=$(cd "$(dirname "$0")" && pwd)
WEAPONS=$(cd "$LAB/.." && pwd)
REPO=$(cd "$LAB/../.." && pwd)
cd $LAB || exit 1
DBG=/tmp/dbgsym81/usr/lib/debug/.build-id/70/4040a392cd0a8b51f18d141caea86e97fa0197.debug
timeout 120 gdb -q -batch \
  -ex 'exec-file /usr/bin/php8.1' \
  -ex "symbol-file $DBG" \
  -x $LAB/gdb_zero4_pre.gdb \
  --args /usr/bin/php8.1 -n vdR4_pre.php 0000000000000000 0000000000000000
