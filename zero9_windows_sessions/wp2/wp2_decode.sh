#!/bin/bash
# wp2_decode.sh HANDLER FILEHEX TAG - decode one crafted session file under ASAN CLI
# angle 3: 0-byte / short / truncated files x {php, php_serialize, php_binary}
PHPBIN="${PHPBIN:-/tmp/php8512_build/asan2/sapi/cli/php}"
HANDLER="$1"; FILEHEX="$2"; TAG="$3"
ART=/tmp/p2s_c2
SESS="$ART/dec/$TAG"
mkdir -p "$SESS"
SID="decsid0000000000000000000000"
rm -f "$SESS"/sess_* 2>/dev/null
printf "%s" "$FILEHEX" | xxd -r -p > "$SESS/sess_$SID"
SZ=$(stat -c %s "$SESS/sess_$SID")
OUT=$(USE_ZEND_ALLOC=0 ASAN_OPTIONS="detect_leaks=0:abort_on_error=1" timeout 30 "$PHPBIN" \
  -n -d session.save_handler=files -d session.save_path="$SESS" \
  -d session.serialize_handler="$HANDLER" -d session.use_strict_mode=0 \
  -d session.gc_probability=0 -d display_errors=1 \
  -r 'if (count($argv) < 2) { fwrite(STDERR, "NO-ARGV\n"); } session_id($argv[1] ?? ""); var_dump(session_start()); var_export($_SESSION); echo "\n";' -- "$SID" 2>&1)
RC=$?
ASAN=$(echo "$OUT" | grep -c "AddressSanitizer")
echo "TAG=$TAG handler=$HANDLER size=$SZ rc=$RC asan=$ASAN"
echo "$OUT" | head -20
echo "----"
[ "$ASAN" != "0" ] && echo "$OUT" > "$ART/dec/ASAN_$TAG.txt"
