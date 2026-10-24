#!/bin/bash
# V-LAR: real Laravel 10 skeleton (composer, network via pinned hosts).
# Created with distro php8.1-cli; runs on any PHP >= 8.1 (jammy fleet class,
# and the php:8.5.11-fpm docker victim).
set -eu
V=/tmp/v_laravel
rm -rf "$V"
mkdir -p "$V"
cd "$V"
if [ ! -f /usr/local/bin/composer ]; then
  curl -s --max-time 120 -o /usr/local/bin/composer https://getcomposer.org/composer-stable.phar
  chmod +x /usr/local/bin/composer
fi
# Laravel 10.x (PHP 8.1-compatible line)
php8.1 /usr/local/bin/composer create-project laravel/laravel:^10.0 app \
  --no-interaction --prefer-dist --quiet 2>&1 | tail -3
cd "$V/app"
php8.1 artisan --version 2>/dev/null || true
grep -n "serialize_handler" config/session.php || echo "no serialize_handler key in config/session.php"
grep -rn "serialize_handler" vendor/laravel/framework/src/Illuminate/Session/ | head -5 || true
echo "V-LAR skeleton ready at $V/app"
