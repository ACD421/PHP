#!/bin/sh
# fa_ext_setup.sh — build mysqli into the php:8.5.11-apache container
set -e
apt-get update -qq >/dev/null 2>&1 || true
apt-get install -y -qq autoconf build-essential libsqlite3-dev >/dev/null 2>&1 || true
docker-php-ext-install mysqli >/tmp/ext.log 2>&1 && echo "MYSQLI-BUILT" || { tail -20 /tmp/ext.log; exit 1; }
php -m | grep -i mysqli
