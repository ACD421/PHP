#!/bin/bash
# wp2_shot.sh - one Finding-C experiment against the built-in server (ASAN or plain)
# All knobs via env; results to /tmp/p2s_c2/runs/TAG/
# exit 0 = clean, 42 = ASAN report found, 43 = server crashed/died
TAG="${TAG:-shot}"
PHPBIN="${PHPBIN:-/tmp/php8512_build/asan2/sapi/cli/php}"
PORT="${PORT:-18790}"
SID="${SID:-vicsid00000000000000000000000}"
POISON="${POISON:-417C42}"                 # hex; A|B
POISON_FILE="${POISON_FILE:-}"             # file with hex key (long keys)
MODE="${MODE:-full}"                        # full|abort|slow|headers-only
PARTS="${PARTS:-1}"
PROGRESS_AFTER="${PROGRESS_AFTER:-0}"
PROGRESS_MID="${PROGRESS_MID:-0}"
FILES="${FILES:-1}"
FILESIZE="${FILESIZE:-65536}"
FILEDATA_HEX="${FILEDATA_HEX:-}"
FREQ="${FREQ:-1}"
MINFREQ="${MINFREQ:-0}"
CLEANUP="${CLEANUP:-1}"
PREFIX="${PREFIX:-upload_progress_}"
HANDLER="${HANDLER:-php}"
VICTIM="${VICTIM:-php}"                     # php|php_serialize|php_binary|empty|garbage|missing|custom
VICTIM_HEX="${VICTIM_HEX:-}"
VICTIM_HEX_FILE="${VICTIM_HEX_FILE:-}"
EXTRA_ARGS="${EXTRA_ARGS:-}"                # extra client args
QUERY="${QUERY:-}"
NOCOOKIE="${NOCOOKIE:-0}"
SIDFIELD="${SIDFIELD:-0}"
CHUNK="${CHUNK:-16384}"
DELAY="${DELAY:-0.01}"
ABORTAT="${ABORTAT:-65536}"
SAVEPATH_EXTRA="${SAVEPATH_EXTRA:-}"
SAVEPATH="${SAVEPATH:-}"              # full override for save_path (diskfull/readonly tests)
CLIENT_TIMEOUT="${CLIENT_TIMEOUT:-40}"
CL=$(cd "$(dirname "$0")" && pwd)
ART=/tmp/p2s_c2
DIR="$ART/runs/$TAG"
SESS="$DIR/sess"
SRV_PID=""

mkdir -p "$DIR" "$SESS"
: > "$DIR/shot.log"

cleanup() { [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null; }
trap cleanup EXIT

stop_port() {
  local i
  for i in 1 2 3 4 5 6 7 8; do
    pkill -f "127.0.0.1:$PORT" 2>/dev/null
    sleep 0.15
    if ! ss -ltn 2>/dev/null | grep -q ":$PORT "; then return 0; fi
  done
  pkill -9 -f "127.0.0.1:$PORT" 2>/dev/null
  sleep 0.3
}

start_server() {
  stop_port
  # NB: -d values are parsed as constant expressions in php>=8 ("P|P" -> "0",
  # trailing "|" -> syntax error + all later -d skipped). Use an ini FILE.
  cat > "$DIR/php.ini" <<EOF
session.save_handler = files
session.save_path = "${SAVEPATH:-$SESS$SAVEPATH_EXTRA}"
session.serialize_handler = $HANDLER
session.use_strict_mode = 0
session.upload_progress.enabled = 1
session.upload_progress.prefix = "$PREFIX"
session.upload_progress.freq = $FREQ
session.upload_progress.min_freq = $MINFREQ
session.upload_progress.cleanup = $CLEANUP
session.gc_probability = 0
display_errors = 1
log_errors = 1
error_reporting = E_ALL
post_max_size = 64M
upload_max_filesize = 64M
max_file_uploads = 64
memory_limit = 1024M
upload_tmp_dir = "${UPLOADTMP:-/tmp}"
EOF
  USE_ZEND_ALLOC=0 ASAN_OPTIONS="detect_leaks=0:abort_on_error=1" \
  "$PHPBIN" -c "$DIR/php.ini" \
    -S 127.0.0.1:$PORT -t "$CL/docroot" \
    > "$DIR/server_out.log" 2> "$DIR/server_err.log" &
  SRV_PID=$!
  for i in $(seq 1 100); do
    if grep -q "Failed to listen" "$DIR/server_err.log" 2>/dev/null; then
      echo "PORT-IN-USE" | tee -a "$DIR/shot.log"; return 1
    fi
    if curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$PORT/up.php"; then return 0; fi
    sleep 0.1
  done
  echo "SERVER-START-FAILED" | tee -a "$DIR/shot.log"; return 1
}

victim_content() {
  case "$VICTIM" in
    php)           printf 'pref|s:6:"keepme";' ;;
    php_serialize) printf 'a:1:{s:4:"pref";s:6:"keepme";}' ;;
    php_binary)    printf '\x04\x70\x72\x65\x66\x73\x3a\x36\x3a\x22\x6b\x65\x65\x70\x6d\x65\x22\x3b' ;;
    empty)         : ;;
    garbage)       printf 'GARBAGE_NO_PIPE_HERE_0123456789' ;;
    missing)       rm -f "$SESS/sess_$SID"; return ;;
    custom)        if [ -n "$VICTIM_HEX_FILE" ]; then xxd -r -p < "$VICTIM_HEX_FILE"; else printf "$VICTIM_HEX" | xxd -r -p; fi ;;
  esac
}

# ---- run -----------------------------------------------------------------
start_server || exit 43
SEFF="${SAVEPATH:-$SESS}"
rm -f "$SEFF"/sess_* 2>/dev/null
if [ "$VICTIM" != "missing" ]; then
  victim_content > "$SEFF/sess_$SID" 2>/dev/null
fi
SB=$(stat -c %s "$SEFF/sess_$SID" 2>/dev/null || echo -1)
echo "before=$SB victim=$VICTIM" >> "$DIR/shot.log"

ARGS=""
[ "$PARTS" != "1" ] && ARGS="$ARGS --parts $PARTS"
[ "$PROGRESS_AFTER" = "1" ] && ARGS="$ARGS --progress-after"
[ "$PROGRESS_MID" = "1" ] && ARGS="$ARGS --progress-mid"
[ "$FILES" != "1" ] && ARGS="$ARGS --files $FILES"
[ "$FILESIZE" != "65536" ] && ARGS="$ARGS --filesize $FILESIZE"
[ -n "$FILEDATA_HEX" ] && ARGS="$ARGS --filedata-hex $FILEDATA_HEX"
[ -n "$QUERY" ] && ARGS="$ARGS --query $QUERY"
[ "$NOCOOKIE" = "1" ] && ARGS="$ARGS --no-cookie"
[ "$SIDFIELD" = "1" ] && ARGS="$ARGS --sidfield"
[ "$CHUNK" != "16384" ] && ARGS="$ARGS --chunk $CHUNK"
[ "$DELAY" != "0.01" ] && ARGS="$ARGS --delay $DELAY"
[ "$ABORTAT" != "65536" ] && ARGS="$ARGS --abort-at $ABORTAT"
[ -n "$EXTRA_ARGS" ] && ARGS="$ARGS $EXTRA_ARGS"

KEYARG="--key $POISON"
if [ -n "$POISON_FILE" ]; then
  KEYARG="--key-file $POISON_FILE"
elif [ "${#POISON}" -gt 60000 ]; then
  printf "%s" "$POISON" > "$DIR/poison.hex"
  KEYARG="--key-file $DIR/poison.hex"
fi

timeout "$CLIENT_TIMEOUT" python3 "$CL/wp2_upclient.py" "$PORT" "$MODE" "$SID" $KEYARG --timeout "$CLIENT_TIMEOUT" $ARGS \
  > "$DIR/client.log" 2>&1
CLI_RC=$?
sleep 0.4
SA=$(stat -c %s "$SEFF/sess_$SID" 2>/dev/null || echo -1)
kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null; SRV_PID=""

WARN=0
grep -q "invalid key" "$DIR/server_out.log" "$DIR/server_err.log" 2>/dev/null && WARN=1
ASAN=0
grep -q "AddressSanitizer" "$DIR/server_err.log" 2>/dev/null && ASAN=1
DEAD=0
kill -0 "$SRV_PID" 2>/dev/null || true
if grep -q "Segmentation fault\|SCRIPT DIE\|child exited\|SERVER-START-FAILED" "$DIR/server_err.log" "$DIR/server_out.log" 2>/dev/null; then DEAD=1; fi

echo "TAG=$TAG before=$SB after=$SA warn=$WARN asan=$ASAN rc=$CLI_RC dead=$DEAD" | tee -a "$ART/shots.index"
echo "after=$SA warn=$WARN asan=$ASAN rc=$CLI_RC" >> "$DIR/shot.log"
if [ "$SA" != "-1" ] && [ "$SA" -le 4096 ]; then
  xxd "$SEFF/sess_$SID" 2>/dev/null | head -8 >> "$DIR/shot.log"
fi
[ "$ASAN" = "1" ] && exit 42
[ "$DEAD" = "1" ] && exit 43
exit 0
