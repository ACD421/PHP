# VB_STATUS — zero4 IN-BAND BOOTSTRAP (no gdb, no baked addresses, live ASLR)

Agent: vb (bootstrap lane). Start: 2026-10-23. Target: plain2 8.5.12,
/tmp/php8512_build/plain2/sapi/cli/php, default ZendMM, ASLR ON, run DIRECTLY.

## Goal

Remove the two dependencies of the proven chain (vdR1/vdR2/vdR3 + pwn_zero4.sh):
- gdb discovery pass (CHUNK/BASE/D baked from a debugger run)
- ASLR-off (fixed addresses)

Everything must come out IN-BAND from userland unserialize() alone.

## DESIGN (source-verified against /tmp/php8512_build/php-8.5.12)

Layout corrections vs the coordinator sketch (verified in var_unserializer.re):
- var_entries = {zend_long used_slots @+0; void *next @+8; zval *data[1018] @+16}
  (NOT next-first). 8160 B = 2 ZendMM pages. Large alloc => free() does NOT
  clobber used_slots/data (vd2 receipt: freed-chain R: read returns real zval*).
- R:n => var_access(n-1). Walk: while id>=1018 && used_slots==1018 => next block,
  id-=1018. Walk stops at a reclaimed block (used_slots = garbage != 1018).
- Re-entrant pushes: var_push writes a REAL zval* at data[used_slots] and does
  used_slots++ (8-byte store) — into the freed/reclaimed block2.
- 'a:' rule PRE-SIZES a MIXED array in ONE allocation: array_finit_size_mixed
  => nTableSize = next_pow2(N), alloc = 8*nTableSize (hash, uint32 slots,
  reset to 0xFFFFFFFF) + 32*N (Bucket {zval val; zend_ulong h; zend_string *key}).
  No resize possible afterwards.
- Element values are decoded with rval = &bucket[i].val (zend_hash_lookup) and
  are PUSHED into the dying context (keys are NOT pushed; var_hash=NULL).

### The "dance" (M1 heap leak, in-band)

Payload outer: a:1020:{...1018 ints, i:9998;O:1:"D":0:{} i:9998;i:5;} (proven:
1021 pushes, block2 residual used_slots=3, D slot-owned via dup-key, __destruct
fires mid var_destroy walk with block2 freed and BG(unserialize) reuse-live).

Inside D::__destruct, unserialize #2 = a:127:{i:129;i:5; i:128;i:1; ... i:16128;i:1;}
(all INTEGER keys — key&127 in {0,1} so no lookup ever touches corrupted hash
slots; element 0 => slot 1, elements 1..126 => slot 0):
- arData alloc = 1024 + 127*32 = 5088 B = 2 pages => RECLAIMS freed block2.
  arData[0] lands at block2+0 => hash[] overlays used_slots(+0)/next(+8).
- used_slots now = hash[0] + (hash[1]<<32). Element 0's insert sets hash[1]=0
  (bucket 0 chains at slot 1) => high dword 0 forever.
- Dance: element k's insert (slot 0) sets hash[0]=k; its push writes
  data[k] = &bucket[k].val and used_slots++ sets hash[0]=k+1.
- Element 0's push: used_slots = -1 (hash[0]=-1, hash[1]=0) => writes
  data[-1] = block2+8 (hash[2,3], never looked up) and sets hash[0,1]=0,0.
- Element 126's push: data[126] = block2+16+8*126 = block2+1024 =
  bucket[0].val.value (victim m=0; element 0's value i:5 is IS_LONG, so the
  type half stays 4) => **$arr[129] = (int)(block2 + 5104) = HEAP LEAK**,
  read before anything touches bucket[0]. Miss detection: value stays 5.
- Element pushes land data[1..125] = block2+24..1016 = hash slots (corrupt,
  but only slots 2..255; all keys hash to 0/1 => never read).

Counter chain after the dance (hash[0] = 127), all top-level pushes
(a:0:{} => ZVAL_EMPTY_ARRAY, no allocs, no elements):
- u2 = unserialize('a:0:{}') -> data[127] = &rval (bucket[0].u1u2; bucket[0]
  already read + unset => UNDEF, skipped at destroy)
- u3, u4, u5 same -> data[128] (bucket[0].h), data[129] (bucket[0].key),
  data[130] = block2+1056 = **bucket[1].val.value** (element 1 value IS_LONG)
  => foreach($arr) (linear walk, no hash lookup) reads $vm = (int)&rval_5,
  the VM-stack return slot of u5. u5's payload 'a:0:{}' leaves
  *rval_5 = {&zend_empty_array, IS_ARRAY} — a BINARY .data pointer parked
  in a dead VM temp that only D's own code could overwrite (it doesn't).

### String reclaim + oracle (M2)

unset($arr) frees arData=block2 (destroy-safe: bucket[0] UNDEF-skip or
non-refcounted garbage dtor; key release of &rval_3 hits a huge "refcount",
no free). $s1 = str_repeat($pat1, 102) (8184 B = 2 pages) re-reclaims block2;
string val starts block2+24 => data[1]=val[0..8] (R:1020), data[2] (R:1021),
data[3] (R:1022) — exactly the proven vdR1 slot mapping.
- pat1 bakes fake zval {&rval_5-16, IS_STRING} => strlen() oracle reads
  qword at &rval_5 = &zend_empty_array => **BASE = leak - off(zend_empty_array)**.
- Canary fake zval pointing at baked magic bytes => self-verify the string
  landed at block2 (mismatch = clean bail, no crash: the miss path reads
  freed arData bytes = old i:1 zvals => harmless).

### Forge (M3)

unset($s1); $s2 = str_repeat($pat2, 4) (2040*4 = 8160) re-reclaims block2;
pat2 = vdR3's forged zend_object + handlers (dtor_obj/get_class_name/
get_debug_info = zif_system) + fake execute_data (num_args@+44) + arg
zend_string "sh /tmp/e", all pointers = block2+24+off and BASE+0x523c60 —
now computed from the in-band leaks. R:1020 => $r1 = ref -> fake object;
var_dump($r1) => zif_system(fake_execute_data) => system("sh /tmp/e")
=> /tmp/pwned_zero4_live marker.

### Robustness (M4)

- Env-drift root cause (bug-5 team): script-path FORM (absolute vs relative)
  shifts startup allocs one ZendMM page. DISCIPLINE: fixed cwd, RELATIVE
  script path, discovery+fire same invocation shape.
- Every stage has a clean-miss bail (miss = reclaim landed elsewhere =>
  writes go into freed memory only; PHP-visible values stay the planted
  constants).
- Retry envelope: loop unserialize($payload) attempts (fresh context each).

## STATUS

- [x] Source verification (var_unserializer.re, zend_hash.c, zend_types.h,
      zend_API.h): all layout facts read from the tree. CORRECTION vs the
      coordinator sketch: var_entries = {used_slots@0, next@+8, data@+16}.
- [x] Symbols (nm): zif_system=0x523c60, zend_empty_array=0xffe460,
      std_object_handlers=0xffe4a0, zval_ptr_dtor=0x722310 (matches vdR1).
- [x] **M1 DONE** — vb1_dance.php: heap chunk (block2) leaked as a PHP
      integer, live ASLR, no gdb, plain `php -n vb1_dance.php`.
      Receipt vb1_m1_gdb_receipt.log: parallel gdb calibration run —
      gdb-observed block2 = 0x7ffff54c9000 == in-band printed block2; the
      no-gdb runs print randomized addrs (0x74938a2c9000 etc).
      Mechanism: the "dance" — unserialize #2 = a:127 mixed array whose
      5120B arData (2 pages) reclaims freed block2; hash[0]/hash[1] overlay
      used_slots; integer keys land only in safe hash slots; R:1 no-push
      elements advance the insert chain; element 126's push writes
      data[126] = block2+1024 = bucket[0].val.value = block2+5056.
      Plus &rval5 (VM temp of the 4th a:0:{} call) leaked via
      data[130] = bucket[1].val.value + foreach (linear) read.
- [~] **M2 MECHANISM PROVEN, DONOR ARRANGEMENT IN PROGRESS** — vb2_base.php.
      The victim-snapshot oracle WORKS (in-band, live ASLR, no gdb):
      a u-call push overwrites bucket[2].val.value with &rval_u9 while the
      element's own type (STRING) survives; R:1020 snapshots the victim
      zval into a fresh zend_reference; strlen($r) then reads the qword at
      rval_u9+16 AFTER later statements fill that slot. Measured: the
      oracle returned the snapshot call's own ref pointer (0x7495786572c0)
      — proving the arbitrary-qword read — because the statement at
      rval_u9+16 was the snapshot itself. Remaining: place an
      unserialize('a:0:{}') donor as the statement at rval_u9+16 whose
      push corrupts bucket[2].val.u1u2 only AFTER the snapshot (the
      snapshot can sit between the writer u9 and the donor u10 — its own
      temp then occupies rval_u9+16, which is the open choreography
      problem; candidate fixes: a no-temp statement between, or shifting
      the victim to bucket[1]/data[130] so the writer is u5 and the donor
      u6 with the snapshot's temp elsewhere, or the march-deflected donor
      whose push lands in the owned 2-page tail past data[1017]).
      gdb calibration (vb2_dump.gdb) confirmed every u-call result temp
      holds {&zend_empty_array, IS_ARRAY} (0x00005555563fe460 = BASE+
      0xffe460 under gdb), 16 bytes apart: 0x...c030..c0a0.
      Blockers solved this session: (1) destructor string-concat carves
      the freed run (prebuild all payloads); (2) hash slot = key&255 not
      key&127; (3) hash[0]=-1,hash[1]=0 composes to POSITIVE 4294967295
      (element 0's key must avoid slots 0/1 so the first counter reads -1);
      (4) the re-entrant call-result VAR leaks +1 on the dance array
      (rc=2 after assign, unset 2->1, frame death does NOT release) — the
      dance array NEVER frees before shutdown => string-reclaim-of-block2
      oracle abandoned in favor of the victim mechanism (the leak is now
      irrelevant: the dance arData stays as the live slot array).
- [ ] M3: pwn_zero4_live.php — merged chain, marker from plain run.
      Design mapped (no string reclaim needed): the fake zend_object built
      FROM DANCE BUCKETS — obj@&bucket[M].val: gc=bucket[M].val.value
      (INT element, controlled), ce=bucket[M].h (garbage, unused in the
      var_dump path), **handlers=bucket[M].key = the KEY ZEND_STRING*
      (STRING-KEYED element — the handlers table = the key string's bytes:
      get_debug_info@key-val[128..136] = baked zif_system!)**, and the
      arg/execute_data fields from buckets M+1/M+2 (arg1 = a STRING
      element's real zend_string* — the command). num_args@+44 =
      bucket[M+1].val.u2 = the chain-next index (choreograph =1).
- [ ] M4: 5 cwds hit-rate + envelope

## Engineering lessons (this lane)

- No allocations in the destructor before the dance arData (any alloc can
  trigger a small-bin refill that carves the freed 2-page run => wild
  used_slots => SEGV).
- ZendMM large allocs = BEST-FIT whole pages, scan from page 0, exact fit
  taken immediately (zend_alloc.c:1107+).
- zend_array_destroy with all-integer keys = static-keys branch: no key
  release, no UNDEF skip (dtor on every bucket).
- The R: walk reads block2's bytes WHATEVER occupies them (dance arData,
  string, freed residue) — the walk only needs block1->used_slots==1018
  (embedded block1 is never freed) and block2->used_slots != 1018 to stop.

## FILES
- vb1_dance.php, vb1_*.log — M1
- vb2_base.php, vb2_*.log — M2
- pwn_zero4_live.php — M3 merged weapon
- VB receipts: vb*_receipt.log
