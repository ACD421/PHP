<?php
// exact-bytes unserialize test: take the real session file, split at first |,
// unserialize what the php handler would unserialize.
class DeferredWriter { public $path; public $data;
    public function __destruct() { var_dump("DTOR", $this->path, $this->data); } }
$f = file_get_contents("/tmp/sess_s0000000000000000000000000000000");
echo "file len=", strlen($f), "\n";
$pos = strpos($f, "|");
$key = substr($f, 0, $pos);
$val = substr($f, $pos + 1);
echo "key=[$key]\n";
echo "val=[$val]\n";
$r = unserialize($val);
var_dump("result:", $r);
echo "props: ", var_export(isset($r->path) ? $r->path : "unset", true), "\n";
