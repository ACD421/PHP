#!/bin/bash
# Vanilla apache victim for the remote session-gap chain:
# php:8.5.11-apache (default-configure mod_php), server write side
# php_serialize (the "hardened write side" config), app read side php (the
# app-level divergence), upload_progress.cleanup=0, a realistic app shape:
#   /var/www/html/up.php    any endpoint receiving file uploads
#   /var/www/html/read.php  session-using page defining the app gadget class
#                           (DeferredWriter = an app destructor that persists
#                           deferred writes — the phpGGC-style premise)
set -e
docker rm -f van85 2>/dev/null || true
docker run -d --name van85 --security-opt seccomp=unconfined \
  -p 8085:80 php:8.5.11-apache >/dev/null
sleep 2
# server ini: write side php_serialize + cleanup=0 (session-hardening recipe)
docker exec van85 sh -c 'cat > /usr/local/etc/php/conf.d/zz-p2s.ini <<EOF
session.serialize_handler = php_serialize
session.upload_progress.cleanup = 0
session.upload_progress.enabled = 1
session.upload_progress.min_freq = 0
session.use_strict_mode = 0
session.save_path = /tmp
EOF'
# victim app
docker exec van85 sh -c 'cat > /var/www/html/up.php <<EOF
<?php header("Content-Type: text/plain"); echo "[up] ok handler=" . ini_get("session.serialize_handler") . "\n";
EOF'
docker exec van85 sh -c 'cat > /var/www/html/read.php <<EOF
<?php
// app shape: a class whose destructor flushes deferred writes (the gadget
// premise — every real app has SOME destructor that acts on attacker data)
class DeferredWriter { public \$path; public \$data;
    public function __destruct() { @file_put_contents(\$this->path, \$this->data); } }
header("Content-Type: text/plain");
ini_set("session.serialize_handler", "php");   // app read-side divergence
session_start();
echo "[read] PHP " . PHP_VERSION . " " . php_sapi_name() . " done\n";
EOF'
docker exec van85 sh -c 'cat > /var/www/html/index.php <<EOF
<?php echo "van85 vanilla victim " . PHP_VERSION . "\n";
EOF'
docker exec van85 apachectl -k restart
sleep 2
echo "--- health:"
curl -s http://127.0.0.1:8085/index.php
curl -s http://127.0.0.1:8085/up.php
curl -sI http://127.0.0.1:8085/read.php | head -1
docker exec van85 php -i 2>/dev/null | grep -E "^session.serialize_handler" | head -1
GW=$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')
echo "GATEWAY=$GW"
