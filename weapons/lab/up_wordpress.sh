#!/bin/bash
# Real WordPress deployment on vanilla PHP 8.3.36 (wordpress:latest official
# image = php:8.3-apache base) + mariadb. Docker network p2snet.
set -e
docker network create p2snet 2>/dev/null || true
docker rm -f wpdb wp83 2>/dev/null || true
docker run -d --name wpdb --network p2snet \
  -e MARIADB_ROOT_PASSWORD=rootpw \
  -e MARIADB_DATABASE=wordpress \
  -e MARIADB_USER=wp \
  -e MARIADB_PASSWORD=wppw \
  mariadb:latest >/dev/null
sleep 8
docker run -d --name wp83 --network p2snet \
  --security-opt seccomp=unconfined \
  -p 8083:80 \
  -e WORDPRESS_DB_HOST=wpdb:3306 \
  -e WORDPRESS_DB_USER=wp \
  -e WORDPRESS_DB_PASSWORD=wppw \
  -e WORDPRESS_DB_NAME=wordpress \
  wordpress:latest >/dev/null
for i in $(seq 1 40); do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 http://127.0.0.1:8083/ || true)
  [ "$code" = "200" ] || [ "$code" = "302" ] && break
  sleep 1
done
echo "--- health:"
curl -s -o /dev/null -w "front: %{http_code}\n" http://127.0.0.1:8083/
curl -sI http://127.0.0.1:8083/ | grep -iE "^(x-powered|x-pingback|server)" | head -3
docker exec wp83 php -v | head -1
docker exec wp83 php -i 2>/dev/null | grep -E "^session.serialize_handler|^session.upload_progress.enabled" | head -2
echo "wp83 up: http://127.0.0.1:8083"
