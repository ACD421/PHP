# The 2026-10-21 PHP security patch shipped a weaponizable GC double-free (SimpleXMLElement properties table)

**Andrew Dorman (@acd421) — 2026-10-21**
**Status: regression introduced by the CVE-2026-109618/19 fix wave (GH-24050 class), live in every patched branch today. Base bug publicly filed as php-src #24488; this write-up adds the weaponization properties with receipts. Works on PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35.**

## Abstract

`gc_collect_white()` gained `gc_add_garbage()` for `get_gc`-returned tables
(Zend/zend_gc.c:1575-1580, php-8.5.12). SimpleXML owns and frees its
properties table itself (`sxe_object_free_storage` →
`zend_hash_release(sxe->properties)`), so the GC now frees the same
56-byte block twice inside a single `gc_collect_cycles()` call. On the
fully patched 8.5.12 this yields, with receipts:

1. **Two `efree()` of the same address in one GC pass** — gdb backtraces:
   free #1 at `Zend/zend_gc.c:2142` (free_obj path), free #2 at
   `Zend/zend_gc.c:2170` (garbage-entry tail efree).
2. glibc abort (`free(): double free detected in tcache 2`) — 4/4 trigger
   variants under `USE_ZEND_ALLOC=0`.
3. ASAN `heap-use-after-free` at `zend_gc.c:2131`, reached from a plain
   userspace function call (`ZEND_DO_ICALL`).
4. **Silent corruption under the default allocator (ZendMM)** — no
   detector fires at double-free time; subsequent allocations surface
   `zend_mm_heap corrupted` + core dump. This is the weaponization-critical
   property.
5. **Allocator-defense analysis (limits the exploit class — verified).**
   The classic double-pop/overlay escalation (two allocations receiving the
   same block, string content over a surviving object's `handlers` at
   +0x18) is **structurally blocked on stock ZendMM in 8.5**: every build
   ships `ZEND_MM_HEAP_PROTECTION` on — each free slot stores
   `shadow = BSWAP(next) ^ heap->shadow_key` at `slot+bin_size-8`
   (bin 56 ⇒ +48), every pop re-derives and compares, and `shadow_key` is
   a 64-bit random per heap (Zend/zend_alloc.c, `shadow_key` init ~line
   2144). gdb receipt: after the double efree, the **first** bin-56 pop
   succeeds (the second free rewrote next+shadow consistently as a
   self-loop); the **second** pop panics in `zend_mm_get_next_free_slot`
   (zend_alloc.c:1456) ← `zend_mm_alloc_small` ← `_emalloc` ←
   `zend_objects_new`. This is why the class presents as crash/abort on
   stock builds and as `tcache` aborts on `USE_ZEND_ALLOC=0` hosts
   (glibc ≥2.35 tcache key check).
6. The double-freed table's **keys and values derive from attacker-supplied
   XML** (SimpleXML property names/values), giving content control inside
   the corrupted block.
7. **Remote receipt:** one-file php -S victim
   (`simplexml_load_string(php://input)` + `get_object_vars` + cycle +
   GC) — warmup request 200 OK; the triggering request kills the server
   process mid-request (curl 56, empty body). PoC: `r1_victim.php`,
   `r1_serve.sh`, `r1_drive.sh` in the source tree.

What is NOT claimed: end-to-end command execution. The escalation state
at publication time:

- **Stock-build (default php.ini, default ZendMM) in-GC crash with an
  indirect-call-through-corrupted-pointer receipt**: N=1000-child XML +
  properties materialization + GC crashes inside `zend_gc_collect_cycles`
  at 10–30% per attempt, at two sites: (a) `zend_gc.c:2138` — deref of a
  corrupted `obj->handlers` on a stale garbage root, one instruction
  before the `free_obj` indirect call; (b) **`zend_hash.c:1996` —
  `ht->pDestructor(&p->val)` compiled to `call *%rax` through the
  corrupted pDestructor, with a real heap pointer as rdi.** Control
  experiment: identical XML without materialization = 0/10 crashes; with
  = 3/10 (both `(array)` cast and `get_object_vars` shapes) — the crashes
  are GH-24488-caused, proven. Remaining gap to controlled RIP: at crash
  time the pDestructor slot still holds freelist-shadow bytes (per-heap
  random); no spray shape has landed an attacker string at the crash
  block yet.
- **Allocator walls, both structural and receipted:** (1) stock ZendMM —
  `ZEND_MM_HEAP_PROTECTION` shadow free lists (per-heap CSPRNG key,
  zend_alloc.c:151/1447/1456/2144); post-double-free, bin-6 is an
  infinite two-cycle (B→X→B→X — B = the double-freed header, X = another
  56B block the GC frees between B's two frees), so alternating
  allocations alias on every second pop — and the second same-bin pop
  panics before any alias survives. (2) `USE_ZEND_ALLOC=0` — glibc
  tcache aborts deterministically: the GC's own pre-free 48-byte
  allocation storm always drains tcache[2] below the 7-entry check
  (16,384-event LD_PRELOAD caller-PC trace, `tracer.c`); tcache-full and
  fastbin bypass plans are dead.
- The only writes into the freed block are the two freelist pushes; the
  IS_ARRAY garbage branch is unreachable (`zend_array_destroy` nulls the
  type byte pre-free, zend_hash.c:2037; garbage entries append after
  roots) — so no pre-pop write primitive exists on this path.

Threat model, honestly bounded: on stock builds today = unauthenticated
remote crash (DoS) plus silent heap corruption state, with a
proven indirect-call primitive one grooming step from controlled RIP. On
`USE_ZEND_ALLOC=0` hosts = deterministic abort (DoS only). Full analysis
and crash-rate table: `GC_WEAPON_STATUS.md`. Escalation receipts and the
control experiment are in `receipts/` (p32/p34/p36 logs, the p37 armed-vs-
control script — coordinator re-run: armed 1/10 crashes, control 0/10;
`tracer.c` = the LD_PRELOAD allocation tracer).

## Trigger (stock 8.5.12, all four variants in poc/)

```php
$xml = new SimpleXMLElement('<root a="1"><b>2</b><c>3</c></root>');
$x = (array)$xml;                        // materialize sxe->properties
                                         // (get_object_vars / json_encode also work;
                                         //  foreach/property access do NOT)
$w = new stdClass(); $w->x = $xml; $w->self = $w;   // GC-collectable cycle
unset($xml, $x, $w);
gc_collect_cycles();
```

No `gc_collect_cycles()` call is required in a victim — unattended cycles
cross the GC threshold automatically.

## Remote reachability shape

Any application that parses attacker-controlled XML with SimpleXML
(RSS/ATOM/sitemap/SOAP/XML-RPC importers), materializes element properties
(`(array)` cast, `get_object_vars`, `json_encode` — standard in XML→JSON
conversion code), and lets the element join a collectable cycle or
accumulate toward the GC threshold. No configuration prerequisites;
`session.upload_progress` irrelevant.

## Fix direction

Unlink the table from the GC buffer before the owner frees it
(evankford's PR #24494: `zend_array_release` / `GC_REMOVE_FROM_BUFFER`),
or restrict the new `gc_add_garbage()` to `obj->properties` only. An
engine-level audit of every extension returning an owned table from
`get_gc` is warranted — SimpleXML is the confirmed instance, unlikely the
only candidate.

## Credits

- **Base regression discovery and upstream filing:** evankford (php-src
  #24488, verified by devnexen; PR #24494).
- **Weaponization analysis — both-free gdb map, silent-corruption property
  under stock ZendMM, ASAN line receipt, php -a/core receipts, 56-byte
  overlay geometry, content-control and reachability analysis:** Andrew
  Dorman (@acd421), with Claude (Anthropic) agent tooling, 2026-10-21.
- **Public corroboration of the double-free class on 8.5.12:** "Elise"
  (@elise@katze.sh), same-day ASAN receipt (uncredited in the PHP
  advisories; her PoC remains unpublished).
- **Regression source:** the GH-24050 fix (part of the CVE-2026-109618/19
  patch wave) by the PHP security team (arnaud-lb, iluuu1994, bukka,
  ndossche), shipping in 8.2.35/8.3.36/8.4.27/8.5.12.

## Reproduce

Build (see package README), then:

```
USE_ZEND_ALLOC=0 sapi/cli/php -d zend.enable_gc=1 poc/v_cast.php   # tcache double-free (SIGABRT)
sapi/cli/php -a  (statements in poc/p12b_churn.sh)                 # zend_mm_heap corrupted + core
gdb -q -batch -x poc/../receipts/p22_ground.gdb sapi/cli/php       # both-free backtraces (or see p22_ground.log)
```

## Timeline

- 2026-10-21: patch ships (04:00-ish UTC class); evankford files #24488
  same day; weaponization receipts (this package) 2026-10-21 evening UTC.
