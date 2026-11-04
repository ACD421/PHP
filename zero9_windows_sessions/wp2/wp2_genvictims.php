<?php
// wp2_genvictims.php - emit valid victim-session payloads as hex for the crossfire matrix
function out($name, $s) { echo $name . "=" . bin2hex($s) . "\n"; }

class SplObj { public $a = "c"; public $self; }
class Gadget { public $cmd = "x"; }

// php-format: key|serialized-value
$o = new SplObj(); $o->self = $o;           // self-referencing object
out("php_obj",     "obj|" . serialize($o));
out("php_arr_obj", "arr|a:2:{i:0;" . serialize(new SplObj()) . "i:1;i:42;}");
out("php_multi",   "k1|i:1;k2|s:3:\"abc\";obj|" . serialize(new SplObj()));
// php_serialize format: whole array
out("ser_obj",     serialize(["obj" => $o, "x" => 1]));
out("ser_pipekey", serialize(["upload_progress_x|y" => 1]));
// php_binary format: namelen-byte + name + serialized value
function binfmt($k, $v) { return chr(strlen($k)) . $k . $v; }
out("bin_obj",     binfmt("obj", serialize($o)));
out("bin_multi",   binfmt("k1", "i:1;") . binfmt("obj", serialize($o)));
// victim with an object whose class DEFINITELY does not exist anywhere
out("php_noclass", "obj|O:19:\"NoSuchClassAnywhere\":1:{s:1:\"z\";i:1;}");
out("ser_noclass", serialize(["obj" => unserialize('O:19:"NoSuchClassAnywhere":1:{s:1:"z";i:1;}')]));
