<?php
/**
 * AsyncTaskRunner lane clone — what a device spawns when the bridge call
 * `AsyncTask.Dispatch {id}` arrives (nativephp/mobile-air:
 * src/Support/AsyncTaskRunner.php + AsyncTaskTransport::readPayload).
 *
 *   readPayload($id)  → file_get_contents(storage/framework/async/payload/{id}.task)
 *   runTask()         → unserialize($payload)      <-- RAW. No allowed_classes,
 *                                                      no signature on the
 *                                                      envelope (only closures
 *                                                      inside are signed).
 *   invoke($work)     → app($class)->handle(...$args) with envelope-chosen class
 *
 * The class below is the APP-side gadget (every unserialize exploit needs one):
 * a destructor that re-enters the var machinery. On a real app this is any
 * installed class whose __destruct/__wakeup (de)serializes — cache flushers,
 * deferred-persist objects, queued-batch teardown. The framework sink is what
 * delivers attacker bytes to it.
 */

class AppCacheFlusher {
    public function __destruct() { unserialize('i:7;'); }
}

define('LAB_ROOT', __DIR__);
$id = getenv('NATIVEPHP_TASK_ID') ?: ($argv[1] ?? '');

$path = LAB_ROOT . '/storage/framework/async/payload/' . $id . '.task';

if (!is_file($path)) {
    echo "payload missing for $id\n";
    exit(0);
}

$payload = file_get_contents($path);
@unlink($path);

echo "payload_len=" . strlen($payload) . "\n";

/* AsyncTaskRunner::runTask() line 55 — verbatim semantics. */
try {
    $work = unserialize($payload);
    echo "unserialize returned " . var_export($work !== false, true) . "\n";
    echo "SURVIVED\n";
} catch (Throwable $e) {
    echo "runner caught: " . $e->getMessage() . "\n";
}
