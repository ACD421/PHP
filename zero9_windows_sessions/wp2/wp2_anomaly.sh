#!/bin/bash
# wp2_anomaly.sh - T4 warning/wipe correlation loop (angle 4)
# N iterations of the exact T4 shape; flags any run where warning and wipe diverge
# usage: wp2_anomaly.sh [N] [php|asan] [PORT]
N="${1:-200}"
WHICH="${2:-asan}"
PORT="${3:-18802}"
CL=$(cd "$(dirname "$0")" && pwd)
ART=/tmp/p2s_c2
DIR=$ART/anomaly
SESS=$DIR/sess
SID=vicsid00000000000000000000000
case "$WHICH" in
  asan) PHPBIN=/tmp/php8512_build/asan2/sapi/cli/php; RUN="USE_ZEND_ALLOC=0 ASAN_OPTIONS=detect_leaks=0:abort_on_error=1" ;;
  *)    PHPBIN=/tmp/php8512_build/plain2/sapi/cli/php; RUN="" ;;
esac

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

pkill -f "127.0.0.1:$PORT" 2>/dev/null; sleep 0.3
eval "$RUN" "$PHPBIN" -c "$DIR/php.ini" -S 127.0.0.1:$PORT -t "$CL/docroot" \
  > "$DIR/server_out.log" 2> "$DIR/server_err.log" &
SPID=$!
for i in $(seq 1 100); do curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$PORT/up.php" && break; sleep 0.1; done

WW=0; WN=0; NW=0; NN=0; DIVERGE=0
CPREV=0
for i in $(seq 1 "$N"); do
  printf 'pref|s:6:"keepme";' > "$SESS/sess_$SID"
  python3 "$CL/wp2_upclient.py" $PORT full $SID --key 4162637C4F3A3130 --filesize 4096 > /dev/null 2>&1
  SA=$(stat -c %s "$SESS/sess_$SID" 2>/dev/null || echo -1)
  C=$(grep -c "invalid key" "$DIR/server_err.log" 2>/dev/null)
  DELTA=$((C - CPREV)); CPREV=$C
  W=0; [ "$DELTA" -gt 0 ] && W=1
  Z=0; [ "$SA" = "0" ] && Z=1
  if [ "$W" = "1" ] && [ "$Z" = "1" ]; then WW=$((WW+1));
  elif [ "$W" = "1" ] && [ "$Z" = "0" ]; then WN=$((WN+1)); DIVERGE=$((DIVERGE+1)); echo "DIVERGE iter=$i warn-but-not-wiped size=$SA";
  elif [ "$W" = "0" ] && [ "$Z" = "1" ]; then NW=$((NW+1)); DIVERGE=$((DIVERGE+1)); echo "DIVERGE iter=$i WIPED-WITHOUT-WARNING";
  else NN=$((NN+1)); DIVERGE=$((DIVERGE+1)); echo "DIVERGE iter=$i neither size=$SA"; fi
  if ! kill -0 $SPID 2>/dev/null; then echo "SERVER DIED at iter=$i"; break; fi
done
kill $SPID 2>/dev/null; wait $SPID 2>/dev/null
echo "RESULT N=$N warn+wipe=$WW warn+nowipe=$WN nowarn+wipe=$NW neither=$NN diverge=$DIVERGE"
echo "asan-in-log: $(grep -c AddressSanitizer "$DIR/server_err.log")"
echo ANOMALY-DONE
