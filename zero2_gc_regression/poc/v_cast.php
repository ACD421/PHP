<?php
$xml = new SimpleXMLElement("<root a=\"1\"><b>2</b><c>3</c></root>");
$x = (array)$xml;
$w = new stdClass(); $w->x = $xml; $w->self = $w;
unset($xml, $x, $w);
gc_collect_cycles();
echo "v_cast survived\n";
