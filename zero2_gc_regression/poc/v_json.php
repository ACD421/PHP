<?php
$xml = new SimpleXMLElement("<root a=\"1\"><b>2</b><c>3</c></root>");
json_encode($xml);
$w = new stdClass(); $w->x = $xml; $w->self = $w;
unset($xml, $w);
gc_collect_cycles();
echo "v_json survived\n";
