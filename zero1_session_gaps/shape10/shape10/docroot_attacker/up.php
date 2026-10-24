<?php
/**
 * shape10 attacker-tenant vhost endpoint. Any page that starts a session is
 * an rfc1867 touch target: the session.upload_progress machinery runs
 * BEFORE user code on multipart POSTs carrying PHP_SESSION_UPLOAD_PROGRESS.
 * This tenant's serialize handler (set per-vhost ini by the lab) decides
 * the FORMAT the shared session file gets rewritten in.
 */
error_reporting(E_ALL);
ini_set('display_errors', '1');
session_start();
echo "ATTACKER-VHOST-TOUCH-OK handler=" . ini_get('session.serialize_handler') . "\n";
