<?php
$w = new stdClass(); $w->self = $w;
$xml = new SimpleXMLElement("<root a=\"1\"><b>2</b><c>3</c></root>");
$w->x = $xml;
get_object_vars($xml);
unset($xml, $w);
gc_collect_cycles();
echo "v_props survived\n";
