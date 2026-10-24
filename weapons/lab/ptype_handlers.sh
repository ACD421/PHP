#!/bin/bash
# Extract zend_object_handlers member offsets from DWARF for both builds
echo "=== PHP 8.1.2 jammy (dbgsym) ==="
gdb -q -batch \
  -ex 'exec-file /usr/bin/php8.1' \
  -ex 'symbol-file /tmp/dbgsym81/usr/lib/debug/.build-id/70/4040a392cd0a8b51f18d141caea86e97fa0197.debug' \
  -ex 'ptype /o struct _zend_object_handlers' 2>&1 | grep -E 'offset|/\*' | head -30
echo "=== PHP 8.5.12 plain2 ==="
gdb -q -batch -ex 'ptype /o struct _zend_object_handlers' \
  /tmp/php8512_build/plain2/sapi/cli/php 2>&1 | grep -E 'offset|/\*' | head -30
