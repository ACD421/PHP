<?php
// r1_victim.php — php2shell 8.5.12 remote shape (GH-24488 GC double-free).
// Victim model: app that feeds attacker XML to SimpleXML (RSS/ATOM/SOAP
// import class), materializes properties, holds it in a cycle, GC runs
// (explicit here; natural threshold works identically per receipts).
//
// POST body = raw XML. Response: OK or the corruption surface.
header('Content-Type: text/plain');
$xml = @simplexml_load_string(file_get_contents('php://input'));
if (!$xml) { echo "ERR-BADXML\n"; exit; }
get_object_vars($xml);                 // materialize the properties table
$w = new stdClass();
$w->x = $xml;
$w->self = $w;                         // cycle -> collectable
unset($xml, $w);
gc_collect_cycles();                   // double efree of the props ht (bin 56)
echo "OK-GC " . PHP_VERSION . " pid=" . getmypid() . "\n";
// silent ZendMM corruption now armed; later SimpleXML/string allocs surface it
$t = new SimpleXMLElement('<r><q>1</q></r>');
get_object_vars($t);
echo "OK-POSTALLOC\n";
