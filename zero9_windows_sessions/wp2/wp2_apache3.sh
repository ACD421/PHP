#!/bin/bash
# wp2_apache3.sh - verify PHP warning logging wiring in the isolated Apache lab
PORT=18812
ROOT=/tmp/p2s_c2/ap3
URL=http://127.0.0.1:$PORT
MOD=/usr/lib/apache2/modules/libphp8.1.so
CL=$(cd "$(dirname "$0")" && pwd)
SID=apsid000000000000000000000000
PIPEHEX='4162637C4F3A3130'

pkill -f "Listen 127.0.0.1:$PORT" 2>/dev/null; sleep 0.5
rm -rf "$ROOT"; mkdir -p "$ROOT/html" "$ROOT/sess"
cp "$CL/docroot/up.php" "$ROOT/html/"
cat > "$ROOT/html/warn.php" <<'EOF'
<?php trigger_error("CONTROL_WARNING_TEST", E_USER_WARNING); echo "warned\n";
EOF
cat > "$ROOT/httpd.conf" <<EOF
ServerName localhost
Listen 127.0.0.1:$PORT
PidFile $ROOT/httpd.pid
ErrorLog $ROOT/error.log
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
  php_admin_value error_log $ROOT/php_error.log
</Directory>
<FilesMatch \\.php$>
  SetHandler application/x-httpd-php
</FilesMatch>
EOF
apache2 -f "$ROOT/httpd.conf" -k start 2>&1 | head -3
sleep 1
echo "--- control: userland warning ---"
curl -s "$URL/warn.php"
sleep 0.3
echo "php_error.log:"; cat "$ROOT/php_error.log" 2>/dev/null | head -3
echo "error.log:"; head -5 "$ROOT/error.log"

echo "--- T4 full upload ---"
printf 'pref|s:6:"keepme";' > "$ROOT/sess/sess_$SID"
: > "$ROOT/php_error.log"
python3 "$CL/wp2_upclient.py" $PORT full $SID --key "$PIPEHEX" --filesize 4096 > /dev/null 2>&1
sleep 0.3
echo "size=$(stat -c %s "$ROOT/sess/sess_$SID" 2>/dev/null)"
echo "php_error.log invalid-key count: $(grep -c 'invalid key' "$ROOT/php_error.log" 2>/dev/null)"
head -3 "$ROOT/php_error.log" 2>/dev/null

echo "--- T4 abort upload ---"
printf 'pref|s:6:"keepme";' > "$ROOT/sess/sess_$SID"
: > "$ROOT/php_error.log"
python3 "$CL/wp2_upclient.py" $PORT abort $SID --key "$PIPEHEX" --filesize 65536 --abort-at 32768 > /dev/null 2>&1
sleep 0.5
echo "size=$(stat -c %s "$ROOT/sess/sess_$SID" 2>/dev/null)"
echo "php_error.log invalid-key count: $(grep -c 'invalid key' "$ROOT/php_error.log" 2>/dev/null)"
head -3 "$ROOT/php_error.log" 2>/dev/null

apache2 -f "$ROOT/httpd.conf" -k stop 2>/dev/null
echo APACHE3-DONE
