<?php
$xml = new SimpleXMLElement("<root a=\"1\"><b>2</b><c>3</c></root>");
get_object_vars($xml);
$w = new stdClass(); $w->x = $xml; $w->self = $w;
unset($xml, $w);
gc_collect_cycles();
$xml2 = new SimpleXMLElement("<r><q>1</q></r>");
get_object_vars($xml2);
$w2 = new stdClass(); $w2->x = $xml2; $w2->self = $w2;
unset($xml2, $w2);
gc_collect_cycles();
echo "v_twice survived\n";
