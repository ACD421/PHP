#!/bin/sh
# fa_wp_setup.sh — install WordPress into van85's docroot (8.5.11 mod_php),
# preserving the weaponsmith lab files under /old. DB = wpdb (p2snet).
set -e
cd /var/www/html
mkdir -p /old
for f in import.php index.php p2s_shell.php postdump.php read.php up.php fa_rce_receipt.txt; do
  [ -e "$f" ] && mv "$f" /old/ || true
done
tar -xzf /tmp/wp.tar.gz -C /tmp
rm -rf /var/www/html/wp-admin /var/www/html/wp-includes
# shellcheck disable=SC2126
cp -r /tmp/wordpress/* /var/www/html/
rm -rf /tmp/wordpress
cat > /var/www/html/wp-config.php <<'CFG'
<?php
define('DB_NAME', 'wordpress');
define('DB_USER', 'wp');
define('DB_PASSWORD', 'wppw');
define('DB_HOST', '172.18.0.2:3306');
define('DB_CHARSET', 'utf8mb4');
define('DB_COLLATE', '');
define('AUTH_KEY',         'fa-lab-key-1');
define('SECURE_AUTH_KEY',  'fa-lab-key-2');
define('LOGGED_IN_KEY',    'fa-lab-key-3');
define('NONCE_KEY',        'fa-lab-key-4');
define('AUTH_SALT',        'fa-lab-salt-1');
define('SECURE_AUTH_SALT', 'fa-lab-salt-2');
define('LOGGED_IN_SALT',   'fa-lab-salt-3');
define('NONCE_SALT',       'fa-lab-salt-4');
$table_prefix = 'fa_';
define('WP_DEBUG', false);
if (!defined('ABSPATH')) define('ABSPATH', __DIR__ . '/');
require_once ABSPATH . 'wp-settings.php';
CFG
mkdir -p /var/www/html/wp-content/plugins/fa-import
cp /tmp/fa/fa_wp_rce.php /var/www/html/wp-content/plugins/fa-import/
cp /tmp/fa/fa_cli_core.php /var/www/html/wp-content/plugins/fa-import/
chown -R www-data:www-data /var/www/html
echo "WP-FILES-READY"
ls /var/www/html | head
