<?php
/**
 * NativePHP Mobile lab harness — faithful mini-clone of the attack-relevant
 * framework surface (nativephp/mobile-air, main @ Oct 2026):
 *
 *   POST /_native/api/call   → NativeCallController clone (routes/api.php:8):
 *                              nativephp_call($method, $params) — registry gate
 *                              only. Registered functions below mirror the
 *                              Kotlin/Swift bridge 1:1 (raw paths, no checks).
 *   POST /_native/api/events → DispatchEventFromAppController clone
 *                              (routes/api.php:7): new $eventClass(...$payload),
 *                              class_exists gate only + event() dispatch.
 *   GET  /_assets/*          → asset handler clone (PHPSchemeHandler.swift /
 *                              PHPWebViewClient.handleAssetRequest): serves
 *                              public/** with no restriction.
 *   POST /upload             → stands in for ANY app feature that persists
 *                              user-supplied bytes to a file (avatar upload,
 *                              import, export, cached response...).
 *
 * Runs under php -S with the fully-patched PHP 8.5.12 build — the same
 * var.c/var_unserializer.c code the shipped NativePHP 8.4.27/8.3.36 binaries
 * carry for this path.
 */

error_reporting(E_ALL);
ini_set('display_errors', '0');

if (!defined('LAB_ROOT')) {
    define('LAB_ROOT', __DIR__);
    define('ASYNC_SPOOL', LAB_ROOT . '/storage/framework/async/payload');
    define('UPLOADS', LAB_ROOT . '/storage/app/uploads');
    define('PUBLIC_DIR', LAB_ROOT . '/public');
}

/* ---- definitions first (router script re-executes per request) ---- */

if (!function_exists('nativephp_call')):
function nativephp_call(string $method, array $params): array {
    switch ($method) {
        /* FileFunctions.kt / FileFunctions.swift — File(from)/File(to),
         * no sandbox check, no canonicalization, no allowlist. */
        case 'File.Copy':
            $from = $params['from'] ?? '';
            $to = $params['to'] ?? '';
            if ($from === '' || $to === '') return ['success' => false, 'error' => 'params required'];
            if (!is_file($from)) return ['success' => false, 'error' => 'Source file does not exist'];
            @mkdir(dirname($to), 0777, true);
            $ok = @copy($from, $to);
            return ['success' => (bool) $ok];

        case 'File.Move':
            $from = $params['from'] ?? '';
            $to = $params['to'] ?? '';
            if ($from === '' || $to === '') return ['success' => false, 'error' => 'params required'];
            if (!is_file($from)) return ['success' => false, 'error' => 'Source file does not exist'];
            @mkdir(dirname($to), 0777, true);
            $ok = @rename($from, $to);
            return ['success' => (bool) $ok];

        /* AsyncFunctions.Dispatch — takes an arbitrary id string, asks the
         * async executor to run the runner for it. The runner (a separate
         * PHP context on device) reads+unserializes the spool file. */
        case 'AsyncTask.Dispatch':
            $id = $params['id'] ?? '';
            if (!preg_match('/^[A-Za-z0-9._-]+$/', $id)) return ['success' => false, 'error' => 'missing id'];
            $runnerBin = getenv('NATIVEPHP_RUNNER_PHP') ?: 'php';
            $alloc = getenv('LAB_RUNNER_ALLOC');
            $alloc = ($alloc === false || $alloc === '') ? '1' : $alloc;
            $script = getenv('LAB_RUNNER_SCRIPT') ?: 'runner.php';
            $runner = escapeshellarg(LAB_ROOT . '/' . $script);
            $env = "NATIVEPHP_TASK_ID=" . escapeshellarg($id) . " USE_ZEND_ALLOC=" . $alloc . " ";
            if (getenv('LAB_RUNNER_GDB') === '1') {
                $cmd = $env . "gdb -q -batch -ex run -ex 'bt 6' -ex 'info registers rax' --args "
                    . escapeshellarg($runnerBin) . " -n " . $runner . " 2>&1";
            } else {
                $cmd = $env . escapeshellarg($runnerBin) . " -n " . $runner . " 2>&1";
            }
            exec($cmd, $out, $code);
            return ['success' => true, 'runner_exit' => $code,
                    'runner_bin' => $runnerBin, 'runner_alloc' => $alloc,
                    'runner_out' => implode("\n", $out)];

        default:
            return ['success' => true];
    }
}

/* Minimal event() so the forged-event demo works without full Laravel. */
function event(object $e): void {
    if (method_exists($e, '__handle')) { $e->__handle(); }
    // On a device: Laravel dispatcher fires every registered listener for
    // this event class with this payload (#[On] handlers, fluent callbacks,
    // app listeners — e.g. anything keying off PaymentCompleted).
}
endif;

/* Demo event classes mirroring Native\Mobile\Events\* (the framework ships
 * Wallet\PaymentCompleted, App\UpdateInstalled, Push\TokenGenerated, ...). */
if (!class_exists('App\Events\PaymentCompleted')) {
    eval(<<<'PHP'
namespace App\Events;
class PaymentCompleted {
    public function __construct(public string $orderId = '', public float $amount = 0.0) {}
    public function __handle(): void {
        file_put_contents(LAB_ROOT.'/storage/forged_event_fired.txt',
            "PaymentCompleted fired with orderId=" . $this->orderId . " amount=" . $this->amount . "\n", FILE_APPEND);
    }
}
PHP
    );
}

foreach ([ASYNC_SPOOL, UPLOADS, PUBLIC_DIR] as $d) {
    if (!is_dir($d)) { @mkdir($d, 0777, true); }
}

/* -------------------------------------------------------------------- */
/* Routing                                                              */
/* -------------------------------------------------------------------- */

$method = $_SERVER['REQUEST_METHOD'];
$uri = $_SERVER['REQUEST_URI'];
$path = parse_url($uri, PHP_URL_PATH);

/* Asset handler clone — serves public/** unconditionally
 * (PHPSchemeHandler: appPath + "/public/" + relativeAssetPath) */
if ($method === 'GET' && str_starts_with($path, '/_assets/')) {
    $rel = rawurldecode(substr($path, strlen('/_assets/')));
    $file = PUBLIC_DIR . '/' . $rel;
    if (is_file($file)) {
        header('Content-Type: application/octet-stream');
        header('Content-Length: ' . filesize($file));
        readfile($file);
        return true;
    }
    http_response_code(404);
    echo "Asset not found";
    return true;
}

/* App file-save feature (the universal app premise: any endpoint
 * that stores user bytes on disk). */
if ($method === 'POST' && $path === '/upload') {
    $name = preg_replace('/[^A-Za-z0-9._-]/', '', $_SERVER['HTTP_X_FILENAME'] ?? 'payload.bin');
    $body = file_get_contents('php://input');
    $dest = UPLOADS . '/' . $name;
    file_put_contents($dest, $body);
    header('Content-Type: application/json');
    echo json_encode(['success' => true, 'path' => $dest, 'bytes' => strlen($body)]);
    return true;
}

/* NativeCallController clone (src/Http/Controllers/NativeCallController.php) */
if ($method === 'POST' && $path === '/_native/api/call') {
    // $request->input() — works for JSON and form-encoded bodies alike
    // (form-encoded = the cross-origin "simple request" shape: no CORS
    // preflight, so a page in the app's webview can fire it even from
    // another origin).
    $input = $_POST;
    if (isset($_SERVER['CONTENT_TYPE']) && str_contains($_SERVER['CONTENT_TYPE'], 'application/json')) {
        $input = json_decode(file_get_contents('php://input'), true) ?: [];
    }
    $bridgeMethod = $input['method'] ?? '';
    $params = is_array($input['params'] ?? null) ? $input['params'] : [];

    header('Content-Type: application/json');

    if ($bridgeMethod === '') {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'code' => 'MISSING_METHOD']);
        return true;
    }

    // nativephp_can() = "is it in the registry" — everything below is
    // registered on device (BridgeFunctionRegistration.kt).
    $registry = ['File.Copy', 'File.Move', 'AsyncTask.Dispatch', 'AsyncTask.Complete', 'Event.Broadcast'];

    if (!in_array($bridgeMethod, $registry, true)) {
        http_response_code(404);
        echo json_encode(['status' => 'error', 'code' => 'METHOD_NOT_FOUND']);
        return true;
    }

    $result = nativephp_call($bridgeMethod, $params);
    echo json_encode(['status' => 'success', 'data' => $result]);
    return true;
}

/* DispatchEventFromAppController clone
 * (src/Http/Controllers/DispatchEventFromAppController.php) */
if ($method === 'POST' && $path === '/_native/api/events') {
    $input = $_POST;
    if (isset($_SERVER['CONTENT_TYPE']) && str_contains($_SERVER['CONTENT_TYPE'], 'application/json')) {
        $input = json_decode(file_get_contents('php://input'), true) ?: [];
    }
    $eventClass = $input['event'] ?? '';
    $payload = is_array($input['payload'] ?? null) ? $input['payload'] : [];

    header('Content-Type: application/json');

    if (!class_exists($eventClass)) {
        echo json_encode(['success' => false]);
        return true;
    }

    // constructorArguments() clone: drop unknown named params
    $ref = new ReflectionClass($eventClass);
    $ctor = $ref->getConstructor();
    $names = [];
    if ($ctor !== null) {
        foreach ($ctor->getParameters() as $p) {
            if ($p->isVariadic()) { $names = null; break; }
            $names[$p->getName()] = true;
        }
    }
    $args = $payload;
    if (!array_is_list($payload) && $names !== null) {
        $args = array_filter($payload, fn ($k) => is_int($k) || isset($names[$k]), ARRAY_FILTER_USE_KEY);
    }

    $event = new $eventClass(...array_values($args));
    event($event);
    echo json_encode(['success' => true, 'callback' => false]);
    return true;
}

http_response_code(404);
echo "Not found";
return true;
