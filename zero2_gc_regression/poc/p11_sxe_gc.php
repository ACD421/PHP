<?php
// P11: php-src GH-24488 — GC double-free of SimpleXMLElement properties
// table on 8.4.27/8.5.12 (regression from GH-24050's gc_add_garbage of
// get_gc tables). Receipt for the Elise-class double-free confirmation.
$xml = new SimpleXMLElement("<root><a>1</a><b>2</b></root>");
get_object_vars($xml);          // materialize properties table
$wrapper = new stdClass();
$wrapper->x = $xml;
$wrapper->self = $wrapper;      // cycle
unset($xml, $wrapper);
gc_collect_cycles();
echo "survived gc\n";
