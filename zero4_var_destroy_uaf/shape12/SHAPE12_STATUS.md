# SHAPE12_STATUS — two weaponizations (2026-10-24, shape12 lane)

Lane: shape12 (gc-compose + fresh-code handoff). Builds: /tmp/php8512_build/plain2
(8.5.12, -g, stock ZendMM), /tmp/php8512_build/asan2 (ASAN). All plain runs
are `php -n`, ASLR on, no debugger unless stated.

## MISSION 2 — C: FORMAT SECOND ENTRY INTO THE ZERO4 UAF: DONE, RCE

`poc_matrix/shape12_c_entry.php` — the full pwn_zero4_live chain (M1 heap
leak → M2 base oracle → M3 forge → zif_system) with BOTH destroy-walk
destructor objects created by the C: custom-serialization format:

    i:9998;O:6:"Stage1":0:{}  ->  i:9998;C:6:"Stage1":0:{}
    O:4:"FIRE":0:{}           ->  C:4:"FIRE":0:{}

Works because object_custom() on the whole 8.4/8.5 release fleet
unconditionally object_init_ex()'s any class with ce->unserialize == NULL
(GH-22046 fix never left master; fc lane receipts). The C:-created object
carries __destruct, the dup-key slot trick fires it inside var_destroy's
unbracketed dtor walk, the destructor re-enters unserialize() on the dying
context — zero4 chain verbatim, new entry format.

Receipts:
- poc_matrix/shape12_c_entry.php first run: full chain (M1/M2/M3 lines,
  ELF-magic base verify) → `uid=0(root) gid=0(root) groups=0(root)`
  marker /tmp/pwned_zero4_c_entry (stack-smash abort after the call is the
  known expected post-call behavior; marker first).
- 5/5 stability matrix: shape12_c_matrix.log (5x uid=0).
- ASAN: shape12_c_entry_asan.log (fresh run: C:-created object's destructor
  fires during var_destroy, n=1) + canonical UAF stack receipt at
  fc_c_destroywalk_asan.log (heap-use-after-free var_unserializer.c:906 via
  var_destroy → destructor → re-entrant unserialize, C: entry).
- Payload generator: poc_matrix/shape12_gen.py (--format O|C, --class,
  --file) — emits the 1020-element outer payload with either entry format.

Attack-surface doubling: any unserialize() sink is now reachable via BOTH
formats; O:-filters (classic POP-chain mitigation) do not touch C:, and C:
additionally instantiates arbitrary internal classes (fc_c_crashmatrix.txt:
141/224 classes, Dom\Element/HashContext/Uri NULL-deref crashers).

## MISSION 1 — GC N-FORMULA + HEAP-LEAK COMPOSITION: DoS -> CONTROLLED CALL

`poc_matrix/shape12_nfcompose.php` (+ shape12_nf.gdb / shape12_nf2.gdb /
runners). Upgrades the zero2 GC shape (double-freed sxe props HashTable B,
rg lane) from deterministic DoS to an attacker-directed indirect call, by
composing the zero4 leak machinery with a 4GB-boundary mmap spray.

### What the rg lane had proven (and what this lane breaks)

rg's RIP_GROOM_STATUS section 4 "proved" the :2138 deref can never see a
valid mapping: handlers = (nNumUsed<<32)|nNumOfElements = (N<<32)|N, and
"mapped addresses all have high-dword << low-dword". That argument only
covers the addresses a process normally HAS. A top-down mmap walk that
crosses a 4GB boundary puts a mapping at [H<<32, H<<32+2MB) whose low
dword starts at 0 — and (H<<32)|H = boundary + H lands INSIDE it. The
composition makes the "impossible" address mapped and attacker-filled.

### The composed chain (all stages receipted)

1. PHASE A — zero4 dance leak in the same process (mode any):
   `PHASE-A leak: block2=0x... base=0x...` — M1 heap leak + M2 binary-base
   oracle fire from plain userland unserialize() alone (receipts in
   shape12_nf_gdb.log / shape12_nf_call.log, every attempt).
2. In-band /proc/self/maps survey: ZendMM regions are labeled
   [anon:zend_alloc] — heap window H = floor>>32, nibble = H&0xf, the
   4GB boundary B4 = H<<32, distance = floor low dword (shape12_probe.php).
3. Gate 1 — nibble: GC_TYPE(B) = *(uint32*)(B+4)&0xf = low nibble of the
   freelist next pointer's high dword = H&0xf. Must be 8 (IS_OBJECT
   branch). P = 1/16, uniform (receipted: gdb grind 3/40 nibble-8; plain
   grinds 6/150; probe sample 1/40).
4. ARM: N = H distinct XML children; (array)$xml materializes the props
   HashTable B (56B, bin-6) PRE-spray; stdClass cycle; no GC yet.
5. SPRAY: K = ceil(dist/2MB)+4 strings, each exactly one 2MB
   [anon:zend_alloc] mmap, packed contiguously downward (kernel merges
   them into one VMA — receipt: BOUNDARY string line, merged size
   0x25600000 = 297x2MB). 16-byte pattern planted at every
   handlers-aligned phase: [offset int32][pad][free_obj ptr].
6. The N-formula deref: handlers = *(B+0x18) = {nNumUsed=N,
   nNumOfElements=N} = (H<<32)|H = B4+H — lands in the sprayed VMA:
   * :2138 `current->ref = GC_MAKE_GARBAGE(obj - obj->handlers->offset)`
     reads OUR planted offset (r11 in the disassembly), rewrites B's
     garbage-root entry with B - planted_offset.
   * :2142 `obj->handlers->free_obj(obj)` reads OUR planted target.
7. Gate 2 — IS_OBJ_FREE_CALLED = 1<<9 of *(uint32*)(B+4): B+4 = high
   dword of the freelist next = H itself, so the gate = bit 9 of H — an
   independent per-run ASLR coin (P=1/2 within nibble-8 runs).
   * Gate OPEN (H mod 0x400 < 0x200): the call FIRES.

### Receipt: CONTROLLED INDIRECT CALL (2 independent gate-open captures)

shape12_nf_gdb.log (grind with shape12_nf.gdb, `set disable-randomization
off`, fresh ASLR per run), capture #1 (H=0x7c08) and capture #2 (H=0x78a8):

    PHASE-A leak: block2=0x7c08244e2000 base=0x64d23b000000
    HEAP floor=0x7c0824400000 H=0x7c08 nibble=8 bit9=0 boundary=0x7c0800000000
    BOUNDARY string [0x7c07ff000000,0x7c0824600000) sz=0x25600000 covers B4 ...
    [2142] CALL obj=0x7c08244584d0 free_obj=0x4242424242424242
    SIGSEGV at zend_gc.c:2142 (the call instruction)

    HEAP floor=0x78a8c4000000 H=0x78a8 nibble=8 bit9=0 boundary=0x78a800000000
    [2142] CALL obj=0x78a8c4058498 free_obj=0x4242424242424242
      r10=0x78a8000078a8 rax=0x78a8c638d010 rdx=0x78a8c638d030 rcx=0xa8
      rsi=0x78a8b2f47387
    Program received signal SIGSEGV ... zend_gc.c:2142 obj->handlers->free_obj(obj);

- free_obj IS the planted marker qword: r10 (= obj->handlers) receipts as
  0x78a8000078a8 = (H<<32)|H — the N-formula address — INSIDE the sprayed
  VMA, and *(r10+8) = 0x4242424242424242 (the planted pattern) was loaded
  and CALLED. This is simultaneously the proof that the :2138/:2142
  dereferences read attacker bytes (the rg lane's "always faults" claim
  broken) and that the call target is attacker-chosen.
- Gate-closed nibble-8 runs receipted in the same log (H=0x7b68, 0x72f8
  bit9=1): no call, walk continues — the bit-9 ASLR coin.
- The zero2 GC bug class is thereby upgraded from "attacker-chosen FAULT
  address" (rg's terminal state) to "attacker-chosen VALID dereference +
  controlled indirect call" — a call-where primitive.

### Receipt: the :2138 instruction-level read (the movslq itself)

shape12_nf3_gdb.log (break at *zend_gc_collect_cycles+0xffc, the
`movslq (%r10),%r11`), attempt 24, gate-closed nibble-8 run:

    [READ] B=0x7b7845258498 typeinfo=0x00007b78          <- B+4 = H itself
    [READ] r10=handlers=0x7b7800007b78                   <- (H<<32)|H, in-spray
           *handlers(int32 offset)=286331153 (0x11111111) <- PLANTED offset read
           *(handlers+8)=0x4242424242424242              <- PLANTED free_obj read

Contrast receipt in the same run (the real sxe object, first entry):
handlers = real binary pointer, offset = 0 — only the zombie B's deref
lands on the spray. typeinfo = 0x00007b78 receipts that B+4 IS the high
dword of the freelist next pointer (nibble = 8, flags = 0x370 = bit 9 set
-> gate closed this run).

### Receipt: gate-open in-band runs (plain php, no debugger)

shape12_nf_call2.log attempt 150 (H=0x7df8) and shape12_nf_call3.log
attempt 30 (H=0x7498), both nibble=8 bit9=0: full chain ran from plain
`php -n` — leak, arm (~30K children), spray, boundary covered, FIRE ->
`zend_mm_heap corrupted` core dump FROM INSIDE gc_collect_cycles. The
gdb-mode=call receipt below decodes exactly what these runs hit: the
planted call fires, and the callee's error-reporting allocation dies on
the GC-poisoned bin-6 freelist. The in-band runs receipt the composed
chain end to end in a plain process with no debugger.

### Receipt: the call EXECUTES a planted zif_system (gdb, mode=call)

shape12_nf4_gdb.log attempt 16 (H=0x71f8 nibble=8 bit9=0, free_obj planted
= base+0x523c60 = zif_system):

    [READ] B=0x71f806458498 typeinfo=0x000071f8
    [READ] r10=handlers=0x71f8000071f8 *offset=286331153
           *(handlers+8)=0x586835323c60                     <- planted ZIF
    [2142] CALL obj=0x71f806458498 free_obj=0x586835323c60   <- CALLED
    abort: zend_mm_panic("zend_mm_heap corrupted")
      #6 zend_mm_get_next_free_slot (bin_num=6) zend_alloc.c:1456
      #7 zend_mm_alloc_small ... #8 _emalloc_56
      #9 _zend_new_array_0 zend_hash.c:326
      #10 zend_fetch_debug_backtrace zend_builtin_functions.c:2092
      #11 zend_default_exception_new zend_exceptions.c:299

Reading: the GC walk CALLED the planted zif_system(B); num_args=0 made the
arg-parse raise; the exception machinery built a debug backtrace, whose
first allocation is a 56-byte array — bin 6 — whose freelist head is B
itself with the call-site GC_ADDREF having +1'd B+0 (the next pointer) —
zend_mm_get_next_free_slot panics mid-error-report. This is why the plain
in-band gate-open runs die with `zend_mm_heap corrupted` and no warning
text: the call fires, the error report dies on the poisoned bin.
(The first [READ]/[2142] pair in the same log = the real sxe object with
its real handlers and offset=0 — the contrast that only the zombie's
dereference lands in the spray.)

### The last mile to command exec — status: analyzed, blocked at rdi

The call is obj->handlers->free_obj(obj) with obj = B (the compiler keeps
obj in rbp; obj is never reassigned — the offset only feeds current->ref).
So the callee runs with rdi = B, whose layout is engine-controlled:

    B+0..8   freelist next (heap ptr, +1 from GC_ADDREF)
    B+4      H (ASLR bits: the nibble + flags gates)
    B+8      u.flags (small int -> valid objects_store handle)
    B+16     arData stale, B+24/28 N counts, B+32 nTableMask
    B+40     nNextFreeElement = 0 -> zif_system num_args (at B+44) = 0
    B+48     heap-protection shadow, B+56.. neighbor bin-6 slot

zif_system(B) therefore cannot reach its command argument (num_args=0,
and the arg would be read from B+80 = the neighboring heap slot).

Escape attempts, all negative-receipted (byte-hunt over the 49MB plain2
binary, poc_matrix receipts in this doc's logs):
- rsp pivots: zero `mov rsp,[rdi+0x18];ret`, `xchg rsp,rax;ret`,
  `mov rsp,rax;ret`, `mov rsp,r10;ret`, `mov rsp,r11;ret`, `mov rsp,rdi;ret`.
- r10/r11-keyed dispatches: zero `mov rdi,r10;call [r10..]`,
  `mov rdi,r11;call [r11..]`, `mov rdi,[r10+X]+call`, `mov rax,r10;ret`
  exists but returns into the GC loop.
- rax-keyed dispatches exist (`mov rdi,rax;call [rax+X]` x8,
  `mov rdi,r10;call [rax+8]` x1) but rax at the call = root-buffer area,
  not the spray (receipted).
- nNextFreeElement -> num_args: numeric child names are impossible (XML
  NameStartChar; libxml rejects <4294967296> — receipted
  shape12_numtag_test.php); a numeric write through $x = (array)$xml
  separates (COW), it cannot touch B.
- The two remaining openings, in effort order:
  1. gate-closed runs: efree(B - planted_offset) with a fake zend_mm_chunk
     header planted at the 2MB-aligned base inside the spray (the :2170
     steer receipt is the entry point; needs AG(mm_heap) leak = first
     chunk base + fixed delta, maps-derivable, gdb-calibratable).
  2. neighbor-slot control: arg1 for zif_system is read at B+80 =
     neighbor+24; a pre-placed live bin-6 string whose val[0..16] =
     {fake zend_string*, IS_STRING} would complete zif_system(B) IF
     num_args could be made nonzero (still blocked by nNextFreeElement=0).

### Per-run success envelope

P(gate-open) = P(nibble-8) * P(bit9 clear) = 1/32 per fresh process;
rejected attempts exit pre-spray in <1s (probe/call modes print the gate
state; runners shape12_nf_call.sh / shape12_nf_gdb.sh loop fresh
processes). Spray cost = dist(0..4GB)/2MB strings, ~0.5-3GB RSS typical
on this WSL (meminfo-guarded, REJECT budget otherwise).

## FILE MAP

- poc_matrix/shape12_c_entry.php — C:-format zero4 RCE weapon (MISSION 2)
- poc_matrix/shape12_gen.py — payload generator (--format O|C)
- poc_matrix/shape12_c_matrix.sh / shape12_c_matrix.log — 5/5 uid=0
- shape12_c_entry_asan.log — ASAN/fresh C:-dtor receipt
- poc_matrix/shape12_nfcompose.php — MISSION 1 weapon (modes probe/gdb/call)
- poc_matrix/shape12_probe.php / shape12_huge_test.php / shape12_numtag_test.php
  — maps/allocator/XML-name probes (receipts for the design decisions)
- poc_matrix/shape12_nf.gdb / shape12_nf2.gdb / shape12_nf3.gdb /
  shape12_nf4.gdb + runners (shape12_nf_gdb.sh / shape12_nf2_gdb.sh /
  shape12_nf3_gdb.sh / shape12_nf4_gdb.sh / shape12_nf_call.sh) — receipt
  harnesses
- shape12_nf_gdb.log — controlled-call receipts (2 gate-open captures +
  gate-closed contrast + register state)
- shape12_nf2_gdb.log — attempt-20 gate-closed run (single-efree walk)
- shape12_nf3_gdb.log — THE movslq instruction receipt (planted
  offset/free_obj read from the spray) + sxe contrast
- shape12_nf4_gdb.log — planted-zif_system CALL EXECUTION receipt + the
  bin-6 panic backtrace that decodes the in-band runs' fate
- shape12_nf_call.log / shape12_nf_call2.log / shape12_nf_call3.log —
  in-band grinds (gate states; call2 #150 / call3 #30 = gate-open FIRE)
- shape12_gate_sample.log — H/nibble distribution sample (plain, 40 runs)
