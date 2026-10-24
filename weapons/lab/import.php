<?php
// App shape: a queue-import endpoint that unserializes a request field
// (the classic "we pass serialized job envelopes between services" pattern).
// The app defines a cache-flusher helper whose destructor defers work via
// unserialize — the gadget premise for the var-layer trigger.
class AppCacheFlusher {
    public $items = [];
    public function __destruct() {
        // re-enter the unserializer while the outer one is still destroying
        unserialize('i:1;');
    }
}
header("Content-Type: text/plain");
$data = $_POST['data'] ?? file_get_contents('php://input');
if ($data === '' || $data === null) { echo "[import] no data\n"; exit; }
$r = @unserialize($data);
echo "[import] PHP ", PHP_VERSION, " result=", var_export($r !== false, true), "\n";
echo "SCRIPT-END\n";
