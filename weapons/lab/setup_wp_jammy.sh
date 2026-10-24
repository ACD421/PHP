#!/bin/bash
# V-WP-JAMMY: real WordPress latest on the WSL host (Ubuntu 22.04 jammy,
# Apache 2.4.52 prefork + mod_php 8.1.2-1ubuntu2.27 — the unpatched 22.04
# LTS fleet stack). Port 8080. DB: local mariadb.
set -eu
ROOT=/tmp/v_wp
PORT=8080
rm -rf "$ROOT"
mkdir -p "$ROOT" "$ROOT/sess"
chmod 1777 "$ROOT/sess"

# ---- WordPress core
if [ ! -f /tmp/wordpress-latest.tar.gz ]; then
  curl -s --max-time 120 -o /tmp/wordpress-latest.tar.gz https://wordpress.org/latest.tar.gz
fi
tar xzf /tmp/wordpress-latest.tar.gz -C "$ROOT"
WP="$ROOT/wordpress"

# ---- database
sudo -n mysql -e "DROP DATABASE IF EXISTS wp_lab; CREATE DATABASE wp_lab; \
  CREATE USER IF NOT EXISTS 'wp_lab'@'localhost' IDENTIFIED BY 'wp_lab_pw'; \
  GRANT ALL ON wp_lab.* TO 'wp_lab'@'localhost'; FLUSH PRIVILEGES;"

# ---- wp-config.php
cat > "$WP/wp-config.php" <<'EOF'
<?php
define( 'DB_NAME', 'wp_lab' );
define( 'DB_USER', 'wp_lab' );
define( 'DB_PASSWORD', 'wp_lab_pw' );
define( 'DB_HOST', 'localhost' );
define( 'DB_CHARSET', 'utf8mb4' );
define( 'DB_COLLATE', '' );
define( 'AUTH_KEY',         'lab1' );
define( 'SECURE_AUTH_KEY',  'lab2' );
define( 'LOGGED_IN_KEY',    'lab3' );
define( 'NONCE_KEY',        'lab4' );
define( 'AUTH_SALT',        'lab5' );
define( 'SECURE_AUTH_SALT', 'lab6' );
define( 'LOGGED_IN_SALT',   'lab7' );
define( 'NONCE_SALT',       'lab8' );
$table_prefix = 'wp_';
define( 'WP_DEBUG', false );
if ( ! defined( 'ABSPATH' ) ) define( 'ABSPATH', __DIR__ . '/' );
require_once ABSPATH . 'wp-settings.php';
EOF

# ---- apache vhost (mod_php, per-dir session hardening in uploads dir =
#      the realistic per-dir serialize_handler divergence victim shape)
cat > "$ROOT/wp.conf" <<EOF
ServerName localhost
Listen 127.0.0.1:$PORT
PidFile $ROOT/httpd.pid
ErrorLog $ROOT/error.log
LogLevel warn
TypesConfig /etc/mime.types
User www-data
Group www-data
LoadModule mpm_prefork_module /usr/lib/apache2/modules/mod_mpm_prefork.so
LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so
LoadModule dir_module /usr/lib/apache2/modules/mod_dir.so
LoadModule mime_module /usr/lib/apache2/modules/mod_mime.so
LoadModule rewrite_module /usr/lib/apache2/modules/mod_rewrite.so
LoadModule php_module /usr/lib/apache2/modules/libphp8.1.so
DocumentRoot $WP
<Directory $WP>
  Require all granted
  DirectoryIndex index.php index.html
  AllowOverride All
  php_admin_value session.save_path $ROOT/sess
  php_admin_value session.upload_progress.min_freq 0
  php_admin_value memory_limit 256M
  php_admin_value post_max_size 32M
  php_admin_value upload_max_filesize 32M
  php_admin_value max_file_uploads 25
  php_admin_flag display_errors off
</Directory>
# per-dir 'php_serialize' (session-hardening recipe applied to the admin dir —
# a real-world per-dir divergence): the rfc1867 hook's write side for POSTs to
# /wp-admin/* diverges from the global 'php' handler used everywhere else.
<Directory $WP/wp-admin>
  php_admin_value session.serialize_handler php_serialize
</Directory>
<FilesMatch \\.php$>
  SetHandler application/x-httpd-php
</FilesMatch>
EOF

# ---- run installer silently (5-minute install via curl)
sudo -n apache2 -X -f "$ROOT/wp.conf" > "$ROOT/x.log" 2>&1 &
AP_PID=$!
disown
for i in $(seq 1 40); do curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$PORT/" && break; sleep 0.4; done

curl -s -o /dev/null "http://127.0.0.1:$PORT/wp-admin/install.php"
# step 1: language
curl -s -o /dev/null -c /tmp/wp_jar -d "language=&step=1" "http://127.0.0.1:$PORT/wp-admin/install.php?step=1"
# step 2: site + admin user
curl -s -o /dev/null -b /tmp/wp_jar -c /tmp/wp_jar \
  --data-urlencode "weblog_title=Lab WP" \
  --data-urlencode "user_name=admin" \
  --data-urlencode "admin_password=lab-admin-pw-123" \
  --data-urlencode "admin_password2=lab-admin-pw-123" \
  --data-urlencode "pw_weak=1" \
  --data-urlencode "admin_email=admin@lab.local" \
  --data-urlencode "blog_public=1" \
  --data-urlencode "Submit=Install WordPress" \
  --data-urlencode "language=en_US" \
  "http://127.0.0.1:$PORT/wp-admin/install.php?step=2"

echo "--- health:"
curl -s "http://127.0.0.1:$PORT/" | grep -o "<title>.*</title>" | head -1
curl -s -o /dev/null -w "wp-login %{http_code}\n" "http://127.0.0.1:$PORT/wp-login.php"
curl -s -I "http://127.0.0.1:$PORT/" | grep -iE "^(x-powered|x-pingback|server)" | head -3
echo "--- PHP handler check (wp-admin dir vs root):"
echo '<?php echo "H=" . ini_get("session.serialize_handler") . " SAPI=" . php_sapi_name() . " V=" . PHP_VERSION . "\n";' > "$WP/wp-admin/hcheck.php"
curl -s "http://127.0.0.1:$PORT/wp-admin/hcheck.php"
rm -f "$WP/wp-admin/hcheck.php"
echo '<?php echo "H=" . ini_get("session.serialize_handler") . "\n";' > "$WP/hcheck.php"
curl -s "http://127.0.0.1:$PORT/hcheck.php"
rm -f "$WP/hcheck.php"
echo "V-WP-JAMMY up on http://127.0.0.1:$PORT (pid $AP_PID)"
