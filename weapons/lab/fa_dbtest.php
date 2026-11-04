<?php
$c = @fsockopen('172.18.0.2', 3306, $errno, $errstr, 3);
if ($c) { echo "DB-REACHABLE\n"; fclose($c); }
else { echo "NO: $errno $errstr\n"; }
