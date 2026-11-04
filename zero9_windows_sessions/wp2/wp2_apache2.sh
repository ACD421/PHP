#!/bin/bash
# wp2_apache2.sh - isolate the abort-wipe-silently behavior on Apache 8.1.2
PORT=18811
ROOT=/tmp/p2s_c2/ap2
URL=http://127.0.0.1:$PORT
MOD=/usr/lib/apache2/modules/libphp8.1.so
CL=$(cd "$(dirname "$0")" && pwd)
SID=apsid000000000000000000000000
PIPEHEX='4162637C4F3A3130'

pkill -f "Listen 127.0.0.1:$PORT" 2>/dev/null; sleep 0.5
rm -rf "$ROOT"; mkdir -p "$ROOT/html" "$ROOT/sess"
cp "$CL/docroot/up.php" "$ROOT/html/"
cat > "$ROOT/httpd.conf" <<EOF
ServerName localhost
Listen 127.0.0.1:$PORT
PidFile $ROOT/httpd.pid
ErrorLog $ROOT/error.log
LogLevel debug
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
apache2 -f "$ROOT/httpd.conf" -k start; sleep 1
curl -s "$URL/up.php"; echo

echo "=== FULL upload x5 (baseline: warning expected) ==="
for i in 1 2 3 4 5; do
  printf 'pref|s:6:"keepme";' > "$ROOT/sess/sess_$SID"
  : > "$ROOT/error.log"
  python3 "$CL/wp2_upclient.py" $PORT full $SID --key "$PIPEHEX" --filesize 4096 > /dev/null 2>&1
  sleep 0.2
  echo "iter=$i size=$(stat -c %s "$ROOT/sess/sess_$SID" 2>/dev/null) warns=$(grep -c 'invalid key' "$ROOT/error.log") phpwarns=$(grep -ci 'PHP Warning' "$ROOT/error.log")"
done

echo "=== ABORT upload x5 (silently wiped?) ==="
for i in 1 2 3 4 5; do
  printf 'pref|s:6:"keepme";' > "$ROOT/sess/sess_$SID"
  : > "$ROOT/error.log"
  python3 "$CL/wp2_upclient.py" $PORT abort $SID --key "$PIPEHEX" --filesize 65536 --abort-at 32768 > /dev/null 2>&1
  sleep 0.4
  echo "iter=$i size=$(stat -c %s "$ROOT/sess/sess_$SID" 2>/dev/null) warns=$(grep -c 'invalid key' "$ROOT/error.log") phpwarns=$(grep -ci 'PHP Warning' "$ROOT/error.log") connaborts=$(grep -ci 'aborted\|connection' "$ROOT/error.log")"
done

echo "=== one abort error.log dump ==="
printf 'pref|s:6:"keepme";' > "$ROOT/sess/sess_$SID"
: > "$ROOT/error.log"
python3 "$CL/wp2_upclient.py" $PORT abort $SID --key "$PIPEHEX" --filesize 65536 --abort-at 32768 > /dev/null 2>&1
sleep 0.5
grep -iE "php|session|invalid" "$ROOT/error.log" | head -12
echo "(total log lines: $(wc -l < "$ROOT/error.log"))"

apache2 -f "$ROOT/httpd.conf" -k stop 2>/dev/null
echo APACHE2-DONE
