# LEAK STAGE — receipts + wall analysis (2026-10-21, this session)

Lane A: 8.1.2 Apache lab — orphan-context leak chase (pre-pivot).
Lane B: 8.5.12 remote GH-24488 GC double-free — leak/escalation attempt.

## Lane B receipts (8.5.12 plain2, php -S remote shape)

B1. REMOTE DOUBLE-FREE KILL (r1_victim.php + r1_serve.sh + r1_drive.sh,
    port 18196): unauth XML POST -> SimpleXML -> get_object_vars -> cycle ->
    gc_collect_cycles. Request 1 completes 200 OK-GC/OK-POSTALLOC; request 2
    -> curl=56 (reset), empty body, SERVER DEAD. Log: leak_stage_r1_remote.log.
    Mechanism (matches p12b churn receipt): first gc corrupts silently,
    next bin-56 pop hits the corrupted freelist.

B2. ABORT BACKTRACE (r2c_segv.gdb, CLI replica): SIGABRT at
      zend_mm_panic("zend_mm_heap corrupted")            zend_alloc.c:404
      zend_mm_get_next_free_slot                        zend_alloc.c:1456
      zend_mm_alloc_small -> _emalloc -> zend_objects_new
    i.e. the SECOND bin-56 allocation after the double-free pops the slot
    whose next/shadow pair was clobbered by the first reclaim.

B3. THE WALL (source, php-8.5.12/Zend/zend_alloc.c):
      #ifndef ZEND_MM_HEAP_PROTECTION / #define 1        (line 151: ON in
      every default build)
      shadow(slot) = BSWAP(next) ^ heap->shadow_key       (line 1419-1439)
      stored at slot + bin_data_size - 8  (bin 56 -> +48 = reclaiming
      string's content[24..31]).
      pop check: next == decode(shadow) else panic        (line 1452-1458)
      shadow_key = zend_random_bytes_insecure per heap    (line 2144)
    => Any same-bin overlay (p19/p20/p21 geometry, our r2 string-then-object
    or object-then-string) fails the check on the second pop: the first
    reclaim's own header (gc=refcount+type_info at +0 = the "next" the pop
    reads; content[24..31] at +48 = the "shadow") can never satisfy
    shadow == BSWAP(next) ^ key without knowing the 64-bit random key.
    The p20/p21 sweeps on plain2 = 0/10 and 1/10 crashes — all this abort,
    not exploitable overlays.
    Sequence verified in gdb (r2_allocs2.gdb): double EFREE of props ht
    (0x7ffff54591f8-style) -> POST-ALLOC#1 size=56 strtolower(31 chars,
    zend_string_falloc len=31) -> POST-ALLOC#2 size=56 zend_objects_new
    (class V{public $p}) -> panic. First pop is CLEAN (free#2 rewrites
    next+shadow consistently = self-loop); every subsequent pop panics.
    Shutdown self-heals the list only if no post-arm 56-alloc happens.

B4. SYSTEM-MALLOC MODE (USE_ZEND_ALLOC=0, remote php -S port 18197,
    r2_malloc.sh): req1 -> empty + "free(): double free detected in tcache 2",
    server DEAD (glibc 2.35 tcache key detection). Log:
    leak_stage_r2_malloc.log. (Fastbin-bypass groom = open but different
    lane; minority deployment config.)

B5. Symbols (framework --syms):
      lab 8.1.2 libphp8.1.so: zval_ptr_dtor=0x2cdcf0 zend_call_function=0x2c15a0 delta=0xc750
      8.5.11 libphp.so:      zval_ptr_dtor=0x611eb0 zend_call_function=0x55f9a0 delta=0xb2510
      (8.5.12 plain2 CLI re-extract pending if that lane reopens)

## Lane A receipts (8.1.2, leak design + why each channel died)

A1. Channel U (orphaned BG(unserialize) + `q|R:N;` payload): full design
    validated in source (PHP-8.1.2 fetched to /tmp/php2shell_src): R: bypasses
    var_push (var_unserializer.re:862), var_access reads stale entries.data[N]
    (+72+8N), ZVAL_NEW_REF copies 16 bytes from freed memory into the tree,
    flush-encode serializes them into the sess file + reflect response.
    THE U-ARM COULD NOT LAND ON APACHE: every p1/pressure variant completes
    all decodes (gdb: U pairs balanced); the OOM lands at the sess-file READ
    (1302528) or in the multipart parser buffer (2098791 = 2x filler growth;
    53248 = 50KB part page-rounding) — logs leak_stage_fillsweep*.log,
    leak_stage_bigsweep*.log, leak_stage_run1.log. The decode-OOM window
    (read fits, decode crosses) is narrower than any coarse pressure knob we
    could deliver through the Apache streaming parser.
A2. Wiz Set-Cookie channel on 8.1.2: DEAD — session RINIT runs
    php_rinit_session_globals() -> PS(id)=NULL on any normal request
    (session.c:106-122), and the rfc1867 path forces PS(send_cookie)=0
    (session.c:3095). The dangling-id cookie emission their 8.4/8.5 recipe
    uses does not exist in 8.1.2 code paths.
A3. S-side encode walk: crash-only — string-reclaimed ctx arData = string
    len (32..39), find reads arData + (key|mask)*4 with mask only OR-ing
    bits -> always unmapped -> SIGSEGV. Unreclaimed ctx walks the static
    uninitialized_bucket cleanly (zend_hash_init sets arData=&uninitialized_
    bucket[2], mask=-2 -> clean miss) — take_A's surviving fire explained.
A4. Lab receipts reproduced this session: arm 1.3MB -> 500 + alive +
    sess tree 1,300,325B; arm 1.8MB -> 500 + alive + sess 0B; pre-RINIT
    fatals "in Unknown on line 0" (leak_stage_run1.log).

## Scripts created this session (php2shell-claude/)
8.1.2 lane: leak_lab.sh leak_stage.py leak_reflect.php leak_armsweep.sh
  leak_trace.sh leak_uarm.sh leak_uarm_sweep.sh leak_fillsweep.sh
  leak_bigsweep.sh leak_patch_p1big.py (+ logs leak_stage_*.log)
8.5.12 lane: r1_victim.php r1_serve.sh r1_drive.sh r2_victim.php
  r2_trace.php r2_allocs.gdb r2_allocs2.gdb r2b_loop.php r2c_victim.php
  r2c_segv.gdb r2_hits.sh r2_malloc.sh (+ logs leak_stage_r1_remote.log,
  leak_stage_r2_envelope.log, leak_stage_r2_malloc.log)
