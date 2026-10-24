<?php
/**
 * shape10 victim tenant app (vhost B — session.serialize_handler = php).
 *
 * Two roles:
 *   ?login=1  — "legit login": seeds $_SESSION with uid/role (php-format
 *               session file on the SHARED save_path).
 *   default   — the victim's own read: session_start() decodes whatever is
 *               in the shared session file with THIS vhost's handler and
 *               renders auth state + a full $_SESSION census.
 *
 * EvilGadget is the app-side gadget every session-poisoning chain needs (a
 * cache-flusher / deferred-persist / queue-teardown class shape). The
 * markers prove attacker-chosen CLASS + PROPERTY VALUES were instantiated
 * and detonated inside the victim vhost's process:
 *   __wakeup  fires during session decode (php_var_unserialize)
 *   __destruct fires at destroy-teardown (decode-failure destroy) or at the
 *             request's normal shutdown (clean-decode takeover)
 */

error_reporting(E_ALL);
ini_set('display_errors', '1');

class EvilGadget {
    public string $cmd = '';
    public function __wakeup(): void {
        @file_put_contents('/tmp/shape10_wakeup.marker',
            "wakeup fired in " . PHP_SAPI . " cmd=" . $this->cmd . "\n", FILE_APPEND);
    }
    public function __destruct() {
        @file_put_contents('/tmp/shape10_destruct.marker',
            "destruct fired in " . PHP_SAPI . " cmd=" . $this->cmd . "\n", FILE_APPEND);
    }
}

session_start();

if (isset($_GET['login'])) {
    $_SESSION['uid']  = 1337;
    $_SESSION['role'] = 'user';
    session_write_close();
    echo "VICTIM-LOGIN-OK uid=1337 role=user\n";
    return;
}

echo "VICTIM-READ-START\n";
$n = 0;
foreach ($_SESSION as $k => $v) {
    $n++;
    if (is_object($v)) {
        printf("SESSION key=%s type=object class=%s cmd=%s\n",
            bin2hex($k), get_class($v), var_export($v->cmd ?? null, true));
    } else {
        printf("SESSION key=%s type=%s value=%s\n",
            bin2hex($k), gettype($v), var_export($v, true));
    }
}
echo "SESSION-COUNT: $n\n";
printf("AUTH: uid=%s role=%s\n",
    var_export($_SESSION['uid'] ?? null, true),
    var_export($_SESSION['role'] ?? null, true));
echo "VICTIM-READ-END\n";
