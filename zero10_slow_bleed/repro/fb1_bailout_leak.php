<?php
// fb1 — POST-FIX SHAPE (08f4b64 applied): bailout mid-walk abandons the
// destroy loops; every object AFTER the bailing one keeps its destructor
// uncalled (destructor bypass) and every remaining context leaks.
//
// Fixed destroy: else if (!--level) { data=NULL; var_destroy(&d); efree(d); }
// Outer walk (d1, level already 0) -> B::__destruct -> nested unserialize
// (d2, level 0->1) -> nested destroy walk -> X::__destruct bails (E_USER_ERROR)
//   => nested walk abandoned: Y, Z destructors NEVER called
//   => efree(d2), efree(d1) never run; outer walk never resumes
//      (outer elements after B also keep their destructors uncalled)
// Receipts: marker_X present; marker_Y/marker_Z ABSENT; LSan leak report.
class B {
    public function __destruct() {
        $p = 'a:3:{i:0;O:1:"X":0:{}i:1;O:1:"Y":0:{}i:2;O:1:"Z":0:{}}';
        @unserialize($p);
    }
}
class X { public function __destruct() {
    file_put_contents("/tmp/fb1_X", "X ran\n");
    trigger_error("bail inside nested destroy walk", E_USER_ERROR);
} }
class Y { public function __destruct() { file_put_contents("/tmp/fb1_Y", "Y ran\n"); } }
class Z { public function __destruct() { file_put_contents("/tmp/fb1_Z", "Z ran\n"); } }
class W { public function __destruct() { file_put_contents("/tmp/fb1_W", "W ran (outer, after B)\n"); } }

foreach (["/tmp/fb1_X","/tmp/fb1_Y","/tmp/fb1_Z","/tmp/fb1_W"] as $f) @unlink($f);

$els = [];
for ($k = 0; $k <= 1015; $k++) { $els[] = "i:$k;i:1;"; }
$els[] = 'i:9998;O:1:"B":0:{}';      // B: slot-owned via dup-key overwrite
$els[] = 'i:9998;O:1:"W":0:{}';      // W: outer element AFTER B — outer walk
                                     // is abandoned by the same bailout
$els[] = 'i:9997;i:5;';
$payload = 'a:1019:{' . implode('', $els);
$r = @unserialize($payload);
echo "outer done\n";
