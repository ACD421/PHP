<?php
/* request_parse_body permutation: this request's body was ALSO parsed by
 * the rfc1867 phase at startup; re-parse it explicitly in userland. */
$w = [];
set_error_handler(function ($n, $s) use (&$w) { $w[] = $s; return true; });
[$post, $files] = request_parse_body();
$started = @session_start();
$cnt = isset($_SESSION) ? count($_SESSION) : -1;
$sid = session_id();
restore_error_handler();
header('Content-Type: text/plain');
echo "RPB_POST=" . count($post) . " FILES=" . count($files) . "\n";
echo "STARTED=" . var_export($started, true) . "\n";
echo "WARN=" . (empty($w) ? "NONE" : implode(" | ", $w)) . "\n";
echo "SID=$sid STATUS=" . session_status() . " CNT=$cnt\n";
