# GC_WEAPON_STATUS — GH-24488 weaponization state (2026-10-21, end of session 2)

Builds: /tmp/php8512_build/plain2 (gcc -g, stock config), source tree
/tmp/php8512_build/php-8.5.12. Everything below is from live runs today.
New instruments: poc_matrix/{p22..p34_*}, tracer.c (LD_PRELOAD allocator
tracer with caller PCs), replay.py, p28_decode*.sh. Key logs:
p22_ground.log, p23_m1m2.log, p24_probe2.log, p24_id.log, p25_watch.log,
p26_matrix.log, p27_rep.log, p27_segv.log, p32_control.log,
p33_segv.log, p34_allcrashes.log.

## 1. OPEN QUESTION ANSWERED (why p21 was 0/12)

sizeof(HashTable)=sizeof(zend_object,1 prop)=zend_string(31)=56 — geometry was
right; the SEQUENCE was wrong. Post-GC the ZendMM bin-6 freelist is an
INFINITE 2-CYCLE  head->B->X->B->X->...  (B=props ht header; X=another 56B
block the GC frees between B's two frees; p22_ground.log dumped via
alloc_globals.mm_heap->free_slot[]). emalloc(56) returns B,X,B,X,... forever.
p21's second new V() got X (healthy) — that alone explains 0/12. Fix = three
allocations (#1,#3 => B). p23 gdb run proved alloc#1=B (0x7ffff54591f8),
alloc#2=X (0x7ffff54592a0) — then alloc#3 PANICKED (see the wall).

## 2. THE ZENDMM WALL (default builds) — confirmed twice, mechanism exact

ZEND_MM_HEAP_PROTECTION=1 (zend_alloc.c:151): free slots carry
shadow = BSWAP(next)^heap->shadow_key at slot+bin_size-8 (bin6 => +48);
every pop re-derives and panics otherwise (zend_alloc.c:1456 <- 1545).
A live claim's +0 (its gc header) and +48 (zval u1/u2 or string content
[24..31]) can never satisfy the pair without the 64-bit CSPRNG key
(zend_alloc.c:2144). Same-bin double-pop = dead on stock builds.
(Consistent with LEAK_STAGE_8512_RECEIPTS.md B3.)

## 3. TARGET 1 (pre-pop UAF write into freed block) — CLOSED NEGATIVE

Full hw-watchpoint catalog across gc_collect_cycles (p25_watch.log): the ONLY
writes into freed B are the two freelist pushes (B+0 next, B+48 shadow). The
IS_ARRAY garbage branch (zend_gc.c:2147-2156) that would write GC_TYPE_INFO /
HT_ALLOW_COW_VIOLATION and run a second zend_hash_destroy (freed-arData walk
+ arData double free) is UNREACHABLE:
  (a) zend_array_destroy nulls GC_TYPE_INFO(ht) at zend_hash.c:2037 BEFORE
      efree#1, so at branch time GC_TYPE(B)=GC_NULL -> neither branch taken;
  (b) garbage root entries are appended AFTER cycle roots (gc_add_garbage =>
      next_unused), so the sxe entry (whose free_obj does efree#1) always
      runs first. Structural, not luck.
Also learned: HT_GET_DATA_ADDR means freelist metadata lands in the hash-slot
area (arData-32), NOT in buckets — buckets survive the free intact; the
@attributes sub-array header is ITSELF a 56B bin-6 block.

## 4. GLIBC MODE (USE_ZEND_ALLOC=0) — CLOSED (deterministic abort)

Full malloc/free traces (tracer.c, /tmp/p24_trace.log, 16k events, caller
PCs). Facts:
- The real efree#1 -> efree#2 window (zend_gc.c:2142 -> 2170) contains ONLY
  frees (arData 320, @attributes sub-header 56, sxe obj 152, key 40). No
  mallocs in default shapes.
- free#1(B) ALWAYS enters tcache: the GC's own pre-free allocation storm
  (dozens of 48-byte root-buffer/gc entries => chunk 0x40) drains tcache[2]
  below 7 first. Any userland tcache pre-fill (my p24/p29/p30 fills) is eaten
  by the storm => tcache-full/fastbin plan is STRUCTURALLY dead.
- free#2(B) then hits the tcache key-scan: abort 100% (p24_id.log bt:
  _int_free malloc.c:4473 <- zend_gc.c:2170).
- One layout (first tracer run, non-setarch) had a 56B malloc reclaim B
  inside the window => free#2 freed a LIVE block silently, run continued
  through more double-frees, aborted later. Not user-controllable (no PHP
  code runs inside the GC; the reclaiming allocs are GC/libc-internal).
- FALSE ALARM RETRACTED: the "same-site double release from simplexml" I
  chased was ZEND_UNSET_CV (my own unset()s), verified by gdb bt at the site.

## 5. THE STOCK-BUILD ESCALATION — NEW, RECEIPTED (session's main find)

Variant: N=1000 distinct child elements, properties materialized
((array) cast OR get_object_vars), cycle, gc_collect_cycles — i.e. gc-sweep's
gcx_sxe_big shape, driven to crash on DEFAULT ZendMM + default php.ini:

- ~10-30% of runs SIGSEGV INSIDE zend_gc_collect_cycles. Two crash classes:
  (i)  zend_gc.c:2138  current->ref = GC_MAKE_GARBAGE(obj - obj->handlers->
      offset): dereferences a corrupted handlers pointer of a garbage-root
      "object" whose memory is a reclaimed/freed block (p27_segv.log,
      p33_segv.log: obj+0x10=0x19 (bogus ce), obj+0x18=0x1 (bogus handlers),
      handle slot holds a heap pointer). NOTE: line 2142 in the same branch
      is  obj->handlers->free_obj(obj)  — an INDIRECT CALL one step later;
      if handlers ever points at attacker-shaped readable memory this is the
      RIP primitive on stock builds, and it never pops the shadow-checked
      freelist (the stale GC root entry IS the UAF).
  (ii) zend_hash.c:1996  ht->pDestructor(&p->val)  =>  call *%rax through a
      corrupted pDestructor (p34_allcrashes.log: rax = 0x5a678f7dcfb152eb,
      0xa123b26d53caed20 — i.e. BSWAP(next)^key freelist-shadow values, the
      block is still ON the bin-6 freelist when the destroy walk reaches it).
      Indirect call + attacker-influenceable argument slot (&p->val from
      arData), but on stock runs the target bytes are the random shadow key.
- CONTROL (p32_control.log): identical XML + cycle + GC with NO properties
  materialization: 0/10 crashes. Materialized: 3/10 (props), 3/10 (cast).
  => Both crash classes are CAUSED by the GH-24488 double-free path.
- p33 (25-char values => value strings are 56B/bin-6, attacker bytes at
  content[0..8] and [24..31] = the ht arData/pDestructor slots): crashes
  reproduce (1-2/12) but the reclaimed block at the crash was still
  freelist-metadata (shadow bytes), not a value string — no in-GC allocation
  of attacker data exists on ZendMM (gc_buffer grows 16n, skipping bin 6).

## 6. CRASH-RATE TABLE (zendmm, stock, this session)

  N=1000 children, no materialization ....... 0/10   (control, clean)
  N=1000 children, get_object_vars ........... 3/10 SIGSEGV in-GC
  N=1000 children, (array) cast .............. 3/10 SIGSEGV in-GC
  N=1000 children, 25-char values ............ 1-2/12 SIGSEGV in-GC
  small XML (p11..p25 shapes) ................ silent corruption only
  glibc mode, any shape ...................... 100% abort (tcache 2)

## 7. WHERE THE WEAPON LANE ACTUALLY STANDS

- ZENDMM stock: silent corruption (small shapes) + probabilistic in-GC
  crashes at two corruption-surfacing sites (one is an indirect call). Full
  RIP needs attacker bytes reclaiming a garbage-root block inside the GC
  window — no known in-GC attacker allocation on ZendMM; the 25-char-value
  experiment did not land our bytes at the crash. NEXT IDEA (untested): a
  SECOND GC run in the same request (first gc arms the stale roots, userland
  allocates attacker strings between runs, second gc walks the stale roots
  over RECLAIMED blocks — the roots survive to the next run? gc_compact may
  prune them; needs one experiment).
- glibc hosts: deterministic abort (DoS receipt only).
- Publishable NOW: stock-build crash escalation with control experiment
  (section 5+6), plus the hardening analysis (section 2+3) explaining WHY
  8.5's shadow freelist turns the old exploit recipe into a panic.

## 8. TWO-GC-PASS EXPERIMENT (p35/p36, done)

arm (N=1000, cast) -> gc pass 1 (silent) -> spray 2000 x 31-char 'ABCD'
strings (bin 6, attacker bytes) -> gc pass 2: 2/10 SIGSEGV, again at
zend_hash.c:1996  call *%rax  (p36_catch.log: rax=0x33914b97b7dbe884 —
shadow-random; rdi=&p->val = real heap ptr 0x76571d8be000). Surviving runs:
spray content fully intact (no observable aliasing — shadow wall again).
=> The indirect call primitive (call *corrupted_pDestructor(heap_ptr_arg))
fires reliably across shapes on stock builds; the missing piece remains
attacker bytes at the freed block's +48 before the walk reaches it.

## 9. COORDINATION

gc-sweep's gcx_* matrix exists; their large-arData N=1000 shapes are what
section 5 drives to receipts (their script survives because the crash needs
ASLR entropy — under gdb with randomization off it never fires; use
`set disable-randomization off`). If another agent wants to chase M-RIP on
stock: the lane is section 5(i) line 2142 free_obj call — make the garbage
root's block contain attacker bytes between the two GC passes (see 7).
