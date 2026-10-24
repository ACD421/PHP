<?php
// p32 control — same 1000-child XML + cycle + GC, but NO properties
// materialization (no (array) cast, no get_object_vars) => sxe->properties
// never built => GH-24488 never arms. If this never segfaults, the p27 SEGV
// is caused by the double-free path.
$n = 1000;
$parts = [];
for ($i = 0; $i < $n; $i++) { $parts[] = "<c$i>v$i</c$i>"; }
$xml = new SimpleXMLElement('<root>' . implode('', $parts) . '</root>');
// NO materialization here
$w = new stdClass();
$w->self = $w;
$w->x = $xml;
unset($xml, $w);
gc_collect_cycles();
echo "control survived\n";
