#!/bin/bash
# wp2_apache.sh - Apache 2.4 prefork + mod_php 8.1.2 lab (angle 4 anomaly loop + abort+reject)
# usage: wp2_apache.sh [loopN] [abportN]
LOOPN="${1:-100}"
ABN="${2:-100}"
PORT=18810
ROOT=/tmp/p2s_c2/ap
URL=http://127.0.0.1:$PORT
MOD=/usr/lib/apache2/modules/libphp8.1.so
CL=$(cd "$(dirname "$0")" && pwd)
SID=apsid000000000000000000000000
PIPEHEX='4162637C4F3A3130'
NOPIPEHEX='416263444546'

pkill -f "Listen 127.0.0.1:$PORT" 2>/dev/null; pkill -f "apache2.*$ROOT" 2>/dev/null; sleep 0.5

rm -rf "$ROOT"; mkdir -p "$ROOT/html" "$ROOT/sess" "$ROOT/logs"
cp "$CL/docroot/up.php" "$ROOT/html/"

cat > "$ROOT/httpd.conf" <<EOF
ServerName localhost
Listen 127.0.0.1:$PORT
PidFile $ROOT/httpd.pid
ErrorLog $ROOT/error.log
CustomLog $ROOT/access.log combined
LogLevel warn
TypesConfig /etc/mime.types
LoadModule mpm_prefork_module /usr/lib/apache2/modules/mod_mpm_prefork.so
LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so
LoadModule dir_module /usr/lib/apache2/modules/mod_dir.so
LoadModule mime_module /usr/lib/apache2/modules/mod_mime.so
LoadModule php_module $MOD
DocumentRoot $ROOT/html
<Directory $ROOT/html>
  Require all granted
  DirectoryIndex up.php
  php_admin_value session.save_path $ROOT/sess
  php_admin_value session.upload_progress.min_freq 0
  php_admin_value session.upload_progress.freq 1
  php_admin_flag display_errors off
  php_admin_flag log_errors on
</Directory>
<FilesMatch \\.php$>
  SetHandler application/x-httpd-php
</FilesMatch>
EOF

apache2 -f "$ROOT/httpd.conf" -k start 2>&1 | head -3
sleep 1
curl -s "$URL/up.php" || { echo APACHE-DEAD; apache2 -f "$ROOT/httpd.conf" -k stop; exit 1; }
echo

# ---------------- anomaly loop: full uploads (the T4 shape) -------------------
WW=0; WN=0; NW=0; NN=0
for i in $(seq 1 "$LOOPN"); do
  printf 'pref|s:6:"keepme";' > "$ROOT/sess/sess_$SID"
  : > "$ROOT/error.log"
  python3 "$CL/wp2_upclient.py" $PORT full $SID --key "$PIPEHEX" --filesize 4096 > /dev/null 2>&1
  SA=$(stat -c %s "$ROOT/sess/sess_$SID" 2>/dev/null || echo -1)
  W=$(grep -c "invalid key" "$ROOT/error.log" 2>/dev/null)
  Z=0; [ "$SA" = "0" ] && Z=1
  WFLAG=0; [ "$W" -gt 0 ] && WFLAG=1
  if [ "$WFLAG" = "1" ] && [ "$Z" = "1" ]; then WW=$((WW+1));
  elif [ "$WFLAG" = "1" ]; then WN=$((WN+1)); echo "DIVERGE-full iter=$i warn-but-size=$SA";
  elif [ "$Z" = "1" ]; then NW=$((NW+1)); echo "DIVERGE-full iter=$i WIPED-WITHOUT-WARNING";
  else NN=$((NN+1)); echo "DIVERGE-full iter=$i neither size=$SA"; fi
done
echo "APACHE-FULL-LOOP: N=$LOOPN warn+wipe=$WW warn+nowipe=$WN nowarn+wipe=$NW neither=$NN"

# ---------------- abort-mid-upload loop with poisoned key ---------------------
WW2=0; WN2=0; NW2=0; NN2=0
for i in $(seq 1 "$ABN"); do
  printf 'pref|s:6:"keepme";' > "$ROOT/sess/sess_$SID"
  : > "$ROOT/error.log"
  python3 "$CL/wp2_upclient.py" $PORT abort $SID --key "$PIPEHEX" --filesize 65536 --abort-at 32768 > /dev/null 2>&1
  sleep 0.25
  SA=$(stat -c %s "$ROOT/sess/sess_$SID" 2>/dev/null || echo -1)
  W=$(grep -c "invalid key" "$ROOT/error.log" 2>/dev/null)
  WFLAG=0; [ "$W" -gt 0 ] && WFLAG=1
  if   [ "$WFLAG" = "1" ] && [ "$SA" = "0" ]; then WW2=$((WW2+1));
  elif [ "$WFLAG" = "1" ]; then WN2=$((WN2+1)); echo "DIVERGE-abort iter=$i warn size=$SA";
  elif [ "$SA" = "0" ]; then NW2=$((NW2+1)); echo "DIVERGE-abort iter=$i WIPED-WITHOUT-WARNING";
  else NN2=$((NN2+1)); echo "DIVERGE-abort iter=$i neither size=$SA"; fi
done
echo "APACHE-ABORT-LOOP: N=$ABN warn+wipe=$WW2 warn+other=$WW2 others=$WN2/$NW2/$NN2"

# ---------------- slow-upload race probe (hook persists key mid-upload) -------
printf 'pref|s:6:"keepme";' > "$ROOT/sess/sess_$SID"
: > "$ROOT/error.log"
python3 "$CL/wp2_upclient.py" $PORT slow $SID --key "$PIPEHEX" --filesize 1048576 --chunk 65536 --delay 0.25 > /dev/null 2>&1
sleep 0.5
echo "APACHE-SLOW: final=$(stat -c %s "$ROOT/sess/sess_$SID" 2>/dev/null || echo -1) warns=$(grep -c 'invalid key' "$ROOT/error.log")"

# ---------------- no-pipe control ---------------------------------------------
printf 'pref|s:6:"keepme";' > "$ROOT/sess/sess_$SID"
: > "$ROOT/error.log"
python3 "$CL/wp2_upclient.py" $PORT full $SID --key "$NOPIPEHEX" --filesize 4096 > /dev/null 2>&1
echo "APACHE-CONTROL-NOPIPE: final=$(stat -c %s "$ROOT/sess/sess_$SID" 2>/dev/null || echo -1) warns=$(grep -c 'invalid key' "$ROOT/error.log")"
head -c 120 "$ROOT/sess/sess_$SID" 2>/dev/null; echo

apache2 -f "$ROOT/httpd.conf" -k stop 2>/dev/null
echo APACHE-DONE
