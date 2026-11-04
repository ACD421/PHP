#!/bin/bash
# wp2_race.sh - concurrent reader racing the reject-wipe, under ASAN (angle 2/3 cross)
# one ASAN server poisons; one ASAN CLI reader hammers session_start on the same sid
CL=$(cd "$(dirname "$0")" && pwd)
ART=/tmp/p2s_c2/race
SESS=$ART/sess
PORT=18840
SID=racesid0000000000000000000000
PHPBIN=/tmp/php8512_build/asan2/sapi/cli/php

rm -rf "$ART"; mkdir -p "$SESS"
cat > "$ART/php.ini" <<EOF
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
error_reporting = E_ALL
post_max_size = 64M
upload_max_filesize = 64M
memory_limit = 1024M
EOF

cat > "$ART/reader.php" <<'EOF'
<?php
/* concurrent reader: session_start on a file being wiped mid-read */
$n = 0; $decoded = 0; $destroyed = 0; $shortread = 0;
$t0 = microtime(true);
while (microtime(true) - $t0 < 25) {
    $n++;
    session_id($argv[1]);
    $r = @session_start();
    if (isset($_SESSION["pref"])) $decoded++;
    session_write_close();
    unset($_SESSION);
}
echo "reader: iters=$n pref-decoded=$decoded\n";
EOF

pkill -f "127.0.0.1:$PORT" 2>/dev/null; sleep 0.5
printf 'pref|s:6:"keepme";' > "$SESS/sess_$SID"

USE_ZEND_ALLOC=0 ASAN_OPTIONS="detect_leaks=0:abort_on_error=1" \
"$PHPBIN" -c "$ART/php.ini" -S 127.0.0.1:$PORT -t "$CL/docroot" \
  > "$ART/srv_out.log" 2> "$ART/srv_err.log" &
SPID=$!
for i in $(seq 1 100); do curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$PORT/up.php" && break; sleep 0.1; done

# two concurrent readers + poison loop
USE_ZEND_ALLOC=0 ASAN_OPTIONS="detect_leaks=0:abort_on_error=1" \
"$PHPBIN" -c "$ART/php.ini" "$ART/reader.php" "$SID" > "$ART/reader1.log" 2>&1 &
R1=$!
USE_ZEND_ALLOC=0 ASAN_OPTIONS="detect_leaks=0:abort_on_error=1" \
"$PHPBIN" -c "$ART/php.ini" "$ART/reader.php" "$SID" > "$ART/reader2.log" 2>&1 &
R2=$!

END=$((SECONDS + 24))
I=0; WIPES=0; KEEPS=0
while [ $SECONDS -lt $END ]; do
  printf 'pref|s:6:"keepme";' > "$SESS/sess_$SID"
  python3 "$CL/wp2_upclient.py" $PORT full $SID --key 4162637C4F3A3130 --filesize 16384 > /dev/null 2>&1
  I=$((I+1))
  SZ=$(stat -c %s "$SESS/sess_$SID" 2>/dev/null || echo -1)
  [ "$SZ" = "0" ] && WIPES=$((WIPES+1)) || KEEPS=$((KEEPS+1))
done
wait $R1 $R2 2>/dev/null
kill $SPID 2>/dev/null; wait $SPID 2>/dev/null

echo "poison-iters=$I wipes=$WIPES keeps=$KEEPS"
echo "reader1: $(tail -1 "$ART/reader1.log")"
echo "reader2: $(tail -1 "$ART/reader2.log")"
echo "reader1 asan: $(grep -c AddressSanitizer "$ART/reader1.log")  reader2 asan: $(grep -c AddressSanitizer "$ART/reader2.log")"
echo "server asan: $(grep -c AddressSanitizer "$ART/srv_err.log")"
grep -m3 -E "Warning" "$ART/reader1.log" | head -3
echo RACE-DONE
