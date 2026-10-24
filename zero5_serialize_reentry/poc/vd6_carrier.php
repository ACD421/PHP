<?php
// vd6 (v2): serialize-side re-entry, COW-free + correct refcounting.
// serialize([$p1, $carrier]):
//   walk P1 -> prop d1: D (rc 2) -> PINNED in serialize ht (rc 3); d2: r:2.
//   walk Carrier -> __sleep() nulls P1->d1/d2 (object props, no COW)
//     -> D rc 1 (pin only).
//   encode done -> php_var_serialize_destroy -> zend_hash_destroy(ht):
//     D-pin release -> rc 0 -> D::__destruct INSIDE the destroy loop ->
//     re-entrant serialize() with BG(serialize).level==1 -> context REUSE
//     -> php_add_var_hash INSERTS into the HashTable the destroy loop is
//     iterating; 24 distinct rc-2 objects force arData erealloc
//     mid-iteration.
class D {
    public function __destruct() {
        $GLOBALS['hits']++;
        $a = [];
        for ($i = 0; $i < 24; $i++) { $o = new stdClass; $a[] = $o; $a[] = $o; }
        serialize($a);
        $GLOBALS['trace'] .= 'D';
    }
}
class P1 { public $d1; public $d2; }
class Carrier {
    public function __sleep() {
        $GLOBALS['p1']->d1 = null;
        $GLOBALS['p1']->d2 = null;
        $GLOBALS['trace'] .= 'S';
        return [];
    }
}

$GLOBALS['hits'] = 0; $GLOBALS['trace'] = '';
$d = new D;
$GLOBALS['p1'] = new P1;
$GLOBALS['p1']->d1 = $d;
$GLOBALS['p1']->d2 = $d;          // D rc 2 via props
unset($d);
$s = serialize([$GLOBALS['p1'], new Carrier]);
$GLOBALS['trace'] .= '|';
echo "hits={$GLOBALS['hits']} trace={$GLOBALS['trace']} len=" . strlen($s) . "\n";
echo "SURVIVED\n";
