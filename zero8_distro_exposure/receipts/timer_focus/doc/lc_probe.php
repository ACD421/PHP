<?php
/* lc_probe.php - stale-state probe endpoint (php2shell LC lane, PHP 8.5.12)
 * ALL session operations happen BEFORE any output (headers_sent must stay
 * false or every check is masked). Reveals PS_* state leaked across
 * requests by the previous request on this process:
 *  - P2 ini-change warning oracle (stale PS(session_status)=active)
 *  - P3 Set-Cookie oracle (stale/dangling PS(id) + send_cookie)
 *  - session start sanity + foreign-data reflection
 */
$warn = [];
set_error_handler(function ($no, $str) use (&$warn) { $warn[] = $str; return true; });
$r = @ini_set('session.serialize_handler', ini_get('session.serialize_handler') === 'php_serialize' ? 'php' : 'php_serialize');
$started = @session_start();
$sid = session_id();
$status = session_status();
$cnt = isset($_SESSION) ? count($_SESSION) : -1;
$hlist = headers_list();
restore_error_handler();
header('Content-Type: text/plain');
echo "PROBE_START\n";
echo "ini_set_ret=" . var_export($r, true) . "\n";
echo "ini_warn=" . (empty($warn) ? "NONE" : implode(" | ", $warn)) . "\n";
echo "session_start=" . var_export($started, true) . "\n";
echo "sid=" . $sid . "\n";
echo "sid_len=" . strlen($sid) . "\n";
echo "sid_hex=" . (preg_match('/^[0-9a-f]+$/', $sid) ? "yes" : "NO") . "\n";
echo "status_after=" . $status . "\n";
foreach ($hlist as $h) {
    if (stripos($h, 'set-cookie') === 0) echo "HDR: " . $h . "\n";
}
echo "sess_count=" . $cnt . "\n";
echo "PROBE_END\n";
