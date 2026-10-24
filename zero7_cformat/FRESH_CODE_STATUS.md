# FRESH_CODE_STATUS — audit of the freshest var-layer code (Oct 2026)

Scope: the three newest var-layer change-sets vs PHP 8.5.12 (our tree
/tmp/php8512_build/php-8.5.12), plus the 08f4b64 post-fix edges on the
coordinator's fixed tree (/tmp/php8512_build/php-fixed = 8.5.12 + 08f4b64
manually applied; builds fixedasan (no dom module) / plain3fix (dom on)).

Git facts established first (GitHub API + raw branch fetches):
- 4bf700e (Sep 30, master) "Create incomplete objects again from the `C`
  format" and b50b30c (Jun 12, master, the GH-22046 fix "Fail unserialization
  when the C format is used for classes that are not Serializable") were
  NEVER merged to the PHP-8.4 or PHP-8.5 release branches. Both branch heads
  still carry the ancient unconditional `object_init_ex` in object_custom().
- b4a63ec (Sep 29, master) "Don't share the unserialize() context with enum
  autoloaders" IS in the PHP-8.5 branch head but NOT in 8.5.12 (merged after
  the release was cut). 8.5.12 therefore still shares the context with enum
  autoloaders.
- 08f4b64 (Oct 22, master + PHP-8.5 head) = the GH-24373 destroy reorder.
  Not in 8.5.12; WILL be in 8.5.13.
- 3584a98 (Oct 18) "Avoid state corruption via bailout" — the
  incomplete_classes_only/keep_payload machinery in our 8.5.12 tree came in
  with this wave (session RFC1867 re-encode support); its var-layer bailout
  hardening (var_restore_prop_default etc.) is master-side and absent here.
- Net: 8.5.12 = no 08f4b64, no b4a63ec, no C:-guard. 8.5.13 (branch head) =
  08f4b64 + b4a63ec but STILL no C:-guard. PHP-8.4 head = no C:-guard.

---

## FC-1 — C: format creates empty objects of ARBITRARY classes on the whole
## 8.4/8.5 release fleet (GH-22046 fix never left master) — STRONGEST FINDING

Mechanism (ext/standard/var_unserializer.re, object_custom(), both release
branches):

    } else if (ce->unserialize == NULL) {
        zend_error(E_WARNING, "Class %s has no unserializer", ...);
        object_init_ex(rval, ce);          /* unconditional! */
    } else if (ce->unserialize(...) != SUCCESS) { return 0; }

Master's b50b30c/4bf700e version returns 0 for every real class that is not
Serializable (only __PHP_Incomplete_Class gets the empty instance). The
release branches instantiate ANY class with ce->unserialize == NULL —
including internal classes whose objects are only valid when constructed by
their factory (internal pointers left NULL by object_init_ex).

Surface measured on stock plain2 (-n, no ini): 141 of 224 declared classes
decode successfully via `C:len:"cls":0:{}` (fc_c_realmatrix.php). Crashers
found by per-class subprocess torture (fc_c_classloop.sh, matrix in
fc_c_crashmatrix.txt; ASAN stacks in fc_c_asanmatrix.log):

- Dom\Element, Dom\HTMLElement — var_dump -> SEGV, NULL WRITE at 0x8 in
  dom_token_list_ctor (ext/dom/token_list.c:255: `ptr->refcount++` where
  element_obj->ptr == NULL), via dom_get_debug_info -> classList read.
  (fc_c_domelement.php; plain core dump + ASAN receipt.) The DIRECT
  userland trigger also crashes stock: fc_c_dom_prop.php — a single
  `$el->classList` read on the C:-created object core-dumps plain2 AND
  plain3fix (8.5.13 preview).
- HashContext — var_dump -> SEGV, NULL READ in zim_HashContext___debugInfo
  (ext/hash/hash.c:1584). (Note: 8.1.2's HashContext has no __debugInfo and
  survives — the crasher is 8.3+/8.4+/8.5-era.)
- Uri\Rfc3986\Uri — clone -> object survives until request shutdown, then
  SEGV in zval_call_destructor (shutdown free path derefs the NULL'd
  internals).
- Uri\WhatWg\Url — serialize() of the C:-created object -> SEGV, NULL READ
  at 0x8 in lxb_url_serialize_body (ext/lexbor .../url.c:4633) via
  zim_Uri_WhatWg_Url___serialize. This is EXACTLY GH-22046's reported
  mechanism ("segfault when non-Serializable internal classes are serialized
  back with the C format") — i.e. the original bug is still live on the
  release branches, 4+ months after being fixed on master.

Fleet/next-release claim (receipt): fc_c_url.php crashes IDENTICALLY on
8.5.12 asan2 and on the 08f4b64-fixed tree (fixedasan, the 8.5.13 preview):
`SEGV lxb_url_serialize_body url.c:4633`. Unless the release branches pick
up the guard, 8.5.13 ships these crashers. PHP-8.4 head verified missing
the guard too (Dom\* exists there since 8.4).

Severity: unserialize() of attacker data + any ordinary follow-up op
(var_dump / print_r / clone / serialize) -> NULL-deref DoS. Fixed offsets
(0x0/0x8), no attacker-controlled address — DoS tier, but a clean
release-branch regression gap with a public master fix that never landed.

C:-format checklist from the task (documented):
- length/depth arithmetic in object_custom: reviewed clean — datalen<0
  rejected, `(max - *p) <= datalen` checked before `(*p)[datalen]`; the
  parse_iv2 before the `max - *p < 2` check can only read the NUL
  terminator of the zend_string buffer.
- keep_payload / MAGIC_MEMBER_SERIALIZED path: reachable only from the
  session RFC1867 re-encode (incomplete_classes_only, pre-RINIT, no user
  code); reserved-member rejection present (is_incomplete_class_reserved_member).
- C: crossing the 1018-slot boundary: C: elements var_push exactly like any
  other element; no format-specific divergence.
- C: + __destruct during destroy: the zero4 destroy-walk UAF entered via a
  C:-recreated object — fc_c_destroywalk.php, ASAN receipt on 8.5.12
  (heap-use-after-free var_unserializer.c:906), clean on the fixed tree.
  Same bug, new format tag — the C: path adds no NEW mid-walk hook beyond
  the pre-existing unserialize_callback_func/autoloader brackets (both
  already serialize_lock-bracketed in the O:/C: shared class-resolution
  block).

## FC-2 — E: enum-autoload context sharing on 8.5.12 (GH-23981/b4a63ec gap):
## functional corruption live; memory-safety escalation = documented dead-end

8.5.12's E: branch calls zend_lookup_class()/zval_update_constant_ex() with
NO serialize_lock bracket (b4a63ec added the brackets on master). Runtime
proof (fc_probe_enum_share2.php, plain2 AND fixedasan): the autoloader's
unserialize() REUSES the outer context — the outer payload's R:3/r:3
resolve into the autoloader-created values ("SHARED-CONTEXT (vulnerable)",
R:3 -> int(5)). Push order for `a:3:{i:0;E:..;i:1;..;i:2;r:N;}`: [1]=array,
[2]=elem0, [3]=INNER autoloader value. Receipt: fc_probe_enum_share2.log.

Memory-safety attempt and why it fails (documented dead-end, receipts
fc_debug_enum.php / fc_enum_uaf.php): the inner call runs with
BG(unserialize).level > 1, so php_unserialize_with_options() routes its
result through var_tmp_var() — a var_dtor_entries slot that holds +1 until
the OUTER var_destroy. Consequences:
- the inner value cannot reach rc 0 before the outer destroy (fc_debug:
  "after unset: freed=false", and r:3 still resolves to the live object);
- the tmp-slot reference is invisible to the GC scanner, so it acts as a
  phantom external ref and BLOCKS cycle collection (gc_collect_cycles()
  returns 0 for a cycle whose only real holder is the stale slot).
So decode-time dangling via the shared chain is not reachable through this
path on 8.5.12; the corruption is id-confusion / delayed-__unserialize
semantics (the functional GH-23981 bug) until the outer destroy — where it
converges onto the already-filed destroy-walk family. 8.5.13 gets b4a63ec
and closes this.

## FC-3 — 08f4b64 post-fix edges (unserialize+serialize destroy reorder)

Lane 1 — SERIALIZE-side mirror of fb1: CONFIRMED, receipts.
fc_fb_s1.php on fixedasan (LSan on): outer serialize -> pin release fires
D::__destruct inside zend_hash_destroy(d1->ht) -> nested serialize takes
the FRESH branch (d2) -> its own destroy walk releases the BailObj pin ->
E_USER_ERROR bailout. Receipts (fc_fb_s1.log + markers via
fc_check_markers.sh):
- fatal stack: trigger_error <- BailObj->__destruct <- serialize(Array) <-
  D->__destruct <- serialize(Array);
- TObj (later bucket in the SAME nested walk): pin never released,
  destructor bypassed (marker absent);
- U (pin in the OUTER walk): destructor bypassed (marker absent);
- LSan: 5504 bytes leaked in 34 allocations on the FIXED tree.
Delta receipt: the same input on unfixed 8.5.12 asan2 hits the known
serialize-side UAF instead (php_var_serialize_destroy -> zend_hash_destroy
-> i_zval_ptr_dtor, heap-use-after-free) — the fix converts the UAF into
the leak/bypass lifecycle bug. Honest tier: low — config-gated
(USE_ZEND_ALLOC=0) destructor-bypass + leak, not stock memory-safety.

Lane 2 — lock-branch / level stranding under the new reorder:
- Stranded counter receipt (gdb): fc_lockstrand2.php + fc_lockstrand.gdb on
  fixedasan — a bailout inside an under-lock dtor walk (delayed __wakeup
  section, fresh inner context, lock-inherited destroy) skips the
  delayed-section `BG(serialize_lock)--`; at shutdown (break zif_var_dump
  from the registered shutdown function): `serialize_lock = 1`, level = 0.
  Rest-of-request serialize()/unserialize() all take the fresh-context
  path. State corruption, low tier, no memory-safety consequence found
  (fc_lockstrand_receipt.log).
- Mixed init-at-0/destroy-at-1 interleavings: analyzed + spot-tested —
  post-fix, destroy-under-lock only ever frees contexts that init created
  under lock (BG(unserialize).data never points at them); the no-lock
  branch is zero-or-one decrement per call (bailout = zero decrements), so
  no double-decrement interleaving exists; data==NULL with level!=0 is
  unreachable (init sets both together, destroy clears at 0). A bailout
  strands level=1/data=<leaked-but-valid d> (fb1 family) — the next
  unserialize() reuses an INTACT stale context (its values leaked-alive),
  i.e. functional staleness, not UAF.

Lane 3 — abandoned mid-store-del object at shutdown: documented dead-end.
fc_abandoned_gc.php on fixedasan: the bailout abandons X mid
zend_objects_store_del (dtor ran, free_obj skipped, DESTRUCTOR_CALLED set);
the shutdown function's gc_collect_cycles() returns 0 twice, object churn
clean, no ASAN memory error — only the leak (LSan 10662 bytes / 15
allocations). The shutdown free path handles the abandoned object
(fc_abandoned_gc.log).

## Master-side note (for the 8.6/next-minor picture)

Master additionally has 3584a98's bailout hardening (var_restore_prop_default,
zend_object_set_properties_reinitable around delayed __unserialize, the
refactored __wakeup call) which our 8.5.12 tree lacks — the fixed-tree
lanes above were tested WITHOUT that hardening, matching what 8.5.13 will
actually ship. Testing them against full master remains open (build master
or cherry-pick 3584a98 on top of php-fixed) — the fb1/fc_fb_s1 leak family
plausibly survives it too, since it is an ownership/lifecycle gap, not a
typed-prop issue.

## Files (all in C:\Users\andre\Downloads\php2shell-claude\)

PoCs: fc_c_domelement.php, fc_c_dom_prop.php, fc_c_url.php, fc_c_realmatrix.php,
fc_c_classprobe.php, fc_c_torture.php, fc_c_destroywalk.php,
fc_probe_enum_share.php/.php(fc_probe_enum_share2.php), fc_debug_enum.php,
fc_enum_uaf.php, fc_isolate.php, fc_idmap.php, fc_fb_s1.php,
fc_lockstrand.php/.gdb, fc_lockstrand2.php, fc_abandoned_gc.php,
fc_check_markers.sh.
Harnesses: fc_c_classloop.sh, fc_c_asanmatrix.sh.
Receipts: fc_c_crashmatrix.txt, fc_c_asanmatrix.log, fc_c_torture_plain.log,
fc_c_destroywalk_asan.log, fc_fb_s1.log, fc_lockstrand_receipt.log,
fc_abandoned_gc.log, fc_probe_enum_share2.log, fc_c_one.log.
Reference material fetched: fix_08f4b64.patch, fix_b4a63ec.patch,
fix_4bf700e.patch, fix_b50b30c.patch, fix_3584a98.patch,
master_var_unserializer.re, master_var.c, php85_var_unserializer.re (branch
head), php84_var_unserializer.re, php81_var_unserializer.re,
gh_commits*.json.
