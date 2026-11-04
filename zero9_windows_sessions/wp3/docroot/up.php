<?php
header("Content-Type: text/plain");
echo "[up] ok " . PHP_VERSION . " " . php_sapi_name() . " handler=" . ini_get("session.serialize_handler") . "\n";
