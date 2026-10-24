# VERIFIER_REPORT — independent verification of the DeepSeek critiques

Date: 2026-10-24. Verifier: independent session (Claude Opus 4.7 via Claude Code).
Method: read every receipt log (all 20 in `weapons/receipts/`), the weapon source, the
package docs, php.net / web record; then RE-FIRED chains myself as www-data against
`/tmp/php8512_build/plain2/sapi/cli/php` (PHP 8.5.12, stock tarball build).

## Independent re-fires performed by this verifier (not Andrew's runs)

1. **zero4 as www-data** (`sudo -u www-data pwn_unserialize.py --local --chain zero4 --cmd 'id; touch /tmp/nopriv_verifier_z4'`):
   `=== zero4: RCE === freed-block base 0x7ffff54a2000` →
   `RECEIPT (command output): uid=33(www-data) gid=33(www-data) groups=33(www-data)`;
   marker `/tmp/nopriv_verifier_z4` created, owned `www-data:www-data`.
2. **zero5 as www-data**: `=== zero5: RCE === freed-block base 0x7ffff5480000` →
   `RECEIPT: uid=33(www-data) ... 6.18.54.1-microsoft-standard-WSL2`.
3. **zero7 C: crasher as www-data** (`c8_direct.php` = `unserialize('C:11:"Dom\Element":0:{}')` + read):
   `Warning: Class Dom\Element has no unserializer` then **Segmentation fault**.
4. Negative-space receipt: first www-data zero4 run's command failed with
   `cannot create /tmp/RZ5: Permission denied` — the spawned shell itself ran with
   www-data credentials against a root-owned leftover. Chain executes AS the invoking uid.

---

## Critique 1 — "uid=0 just means the lab ran as root"

**VERDICT: PARTIAL** (critique literally CONFIRMED; the counter-claim "all 10 fired,
receipts in /tmp/nopriv_test" is NOT what the directory shows).

- The critique is correct on its face: 9 receipt logs show `uid=0(root)`
  (local_zero4_php8512, local_zero4_php812_jammy, local_zero5_php8511/8512,
  unified_zero4_jammy_812, vanilla_zero4/05_docker_8511, vanilla_zero4/05_wordpress_8336)
  because the runs were invoked as root / `docker exec` (default root). No receipt
  anywhere shows privilege ESCALATION — the uid always equals the invoking user. Nothing
  in the package claims otherwise, but the receipts alone couldn't disprove the critique.
- The chain is in fact uid-independent — **independently verified**: my www-data runs of
  zero4 AND zero5 both reached full RCE with `uid=33(www-data)` receipts, and the C:
  crasher segfaulted under www-data. The bug is engine memory corruption; uid only
  determines whose shell you get.
- **However**: `/tmp/nopriv_test/` contains only TWO artifacts — `fb1_out.txt` (an ASAN
  LeakSanitizer receipt for the fb1 family, owned by root, i.e. captured by a root
  shell) and `z4_marker` (empty, owned www-data — corroborates one www-data zero4 run).
  It does NOT contain receipts for "all 10". The all-lanes-as-www-data claim is
  under-receipted as of now.
- **Correction needed**: `CVE_COUNT.txt` line "ALL RECEIPTS AS www-data uid=33 — no
  root privilege in any receipt" is contradicted by the receipts directory (9 uid=0
  logs). Replace with: "chain verified at uid 0 and uid 33; receipt uid = invoking
  user (no escalation claimed)". My verifier runs now supply genuine uid=33 receipts
  for zero4, zero5, zero7; regenerate the rest as www-data or soften the line.

## Critique 2 — "WordPress receipt is CLI, not remote HTTP"

**VERDICT: CONFIRMED.**

`vanilla_zero4_wordpress_8336.log` (and the zero5 twin) shows:
`PHP 8.3.36 (docker:/usr/local/bin/php)` / `Server API => Command Line Interface`,
then `staged /tmp/w/vdR4_call.php ... exploit-as-oracle sweep`. The weapon's docker
mode (php2shell.py `DockerRunner`) stages carriers with `docker cp` and fires with
`docker exec`. There is no HTTP request to WordPress anywhere in the receipt. What it
DOES prove: the full chain (UAF → reclaim → forged zval → zif_system via runtime RELA
scan) works on the real wordpress:latest stack's unmodified PHP 8.3.36 binary — the
docroot listing (wp-admin, wp-activate.php…) confirms it was genuinely the WP image.
It is a binary-target receipt, not a remote-exploitation receipt. WEAPONS.md's "Honest
bounds" already concedes exactly this.

## Critique 3 — "The trycloudflare URL was their own tunnel"

**VERDICT: CONFIRMED.**

`lab/tunnel_up.sh` runs `cloudflared tunnel --url http://127.0.0.1:8085` — a quick
tunnel pointed at the local `van85` Docker container started by `up_van85_remote.sh`
(php:8.5.11-apache + author's ini + author's gadget). The receipt
(`live_tunnel_sessgap_public.log`) shows the revshell connection coming from
`172.17.0.2` — the Docker bridge network. Victim = our own container; tunnel = our own.
What it legitimately proves: the sessgap chain survives delivery through the real
Cloudflare edge over public HTTPS (uid=33 webshell + interactive revshell through the
tunnel). It is NOT evidence of third-party compromise, and shouldn't be presented as
one.

## Critique 4 — "DeferredWriter gadget written by the author"

**VERDICT: PARTIAL** (flag exists; critique valid for every receipt).

- `--gadget-class` EXISTS: php2shell.py:1313 (`default="DeferredWriter"`), and
  `pwn_unserialize.py --gen-trigger --gadget-class`. So the class name is
  parameterized, not hardcoded-only.
- But: (a) every RCE receipt used author-authored gadget classes — `DeferredWriter`
  (defined in `lab/up_van85_remote.sh`, `exact_unserialize.php`) or `AppCacheFlusher`;
  (b) the injected object's properties are HARDCODED to the DeferredWriter shape —
  `fire_sessgap` calls `build_gadget_injection(gadget, {"path": shell_path,
  "data": WEBSHELL})` — so pointing it at a real phpGGC-style gadget (different
  property names/chains) would inject a malformed object; (c) there is no gadget
  enumeration mode or known-gadget catalog. WEAPONS.md says the quiet part: "on real
  targets enumerate the app's own gadget, phpGGC-style" — i.e., manual, unreceipted.
- Net: the flag is real but is naming-only parameterization; "real-world gadget
  enumeration" does not exist in the weapon, and no receipt demonstrates fire on a
  non-author gadget.

## Critique 5 — "None is a default-config remote unauth RCE"

**VERDICT: PARTIAL** — valid for THIS repo's receipts as a set; refuted as an absolute
claim by third-party evidence.

Valid for our receipts:
- zero4/zero5 full-RCE receipts are local/docker CLI under `setarch -R` (ASLR OFF —
  WEAPONS.md: docker needs `--security-opt seccomp=unconfined` FOR setarch -R).
  Remote zero4 delivery receipts are crash-only: `remote_pwnunserialize_glibc_kill.log`
  (worker SIGSEGV) and `live_tunnel_pwnunserialize_remote.log` (silent; weapon itself
  prints "full remote RCE requires the leak/calibration stage").
- sessgap full-RCE receipts (the only remote full RCE we hold: uid=33 + revshell)
  require serialize_handler divergence + cleanup=0-style ini + an app gadget — the van85
  victim had a custom `zz-p2s.ini` and the author's gadget. Stock `php`/`php` both
  sides = no fire (WEAPONS.md concedes).
- Both remote uprog runs (`remote_uprog_van85_8511.log`, `remote_uprog_jammy_wp.log`)
  end "no kill signature in budget". Both live cformat attempts: no crash (endpoint
  didn't touch the object).
Refuting the absolute claim:
- **Trail of Bits has a working exploit that gets a shell on an UNMODIFIED MediaWiki
  installation, no LFI required** (Dan Guido @dguido, Oct 22; ToB account: "getting
  freed memory reused just right takes some tinkering under normal traffic" — a
  reliability caveat, not an existence caveat). A stock popular app on default config
  IS remotely exploitable in the wild for this bug class.
- Our zero4/zero5/zero7 triggers DO fire on stock php.ini (my c8 run: no ini flags,
  segfault; the vd triggers are pure unserialize with no session/ini dependence). What
  needs more than stock config is the full-address-knowledge RCE step, not the bug.
On the specific question — is `--local`/docker mode against the vanilla official image
equivalent to remote exploitation? **No.** Three gaps: (1) delivery — staged file +
docker exec vs a network-reachable unserialize/serialize surface; (2) ASLR — off via
setarch vs on in the wild (the leak oracle — Wiz's Set-Cookie 512B heap leak class —
is mapped but NOT implemented in this weapon; receipts have no ASLR-on full RCE);
(3) process model — fresh CLI per sweep attempt vs persistent worker. What it DOES
prove, and this is non-trivial: the chain works on the unmodified, stripped,
official-image binary with zero build-specific symbol info (runtime RELA scan found
zif_system on the stripped 8.5.11 at +0x60ca60 and fired in 11s) — no lab-build
cheating in the binary. The remaining gap is delivery-surface + ASLR, both
app-dependent — and ToB's MediaWiki receipt shows the class is closable in the wild.

## Critique 6 — "NativePHP is not PHP core"

**VERDICT: CONFIRMED** (and already conceded by the package).

NativePHP is a third-party framework that ships its OWN prebuilt PHP binaries
(bin.nativephp.com; NATIVEPHP_STATUS.md: 8.4.27 default / 8.3.36 optional). The
critical primitives in zero6 — ungated `/_native/api/call` bridge, raw-path
File.Copy, AsyncTaskRunner raw unserialize — are framework bugs. The repo's own
`CVE_COUNT.txt` categorizes zero6 under "THIRD-PARTY FRAMEWORK (not PHP core)".
Nuance that keeps it in the package legitimately: the var_destroy UAF the bridge
delivers IS a php-core bug still present in the bundled 8.4.27/8.3.36, and the
finding is "framework delivery surface for a core memory bug", not a claim of a new
core CVE. If any outward claim framed zero6 as a PHP-core vuln, that framing would be
wrong; the corrected inventory doesn't.

## Critique 7 — "Windows O_NOFOLLOW needs local access" (AV:L vs AV:N)

**VERDICT: CONFIRMED** (valid; already correctly classified in the inventory).

The full zero9 chain = plant a hardlink/symlink named `sess_<sid>` in
session.save_path + ONE unauth multipart POST. WIPE3/WIPE4 receipts prove: the plant
needs NO privilege (hardlink via `mklink /H`, python `os.link`, or PHP's own stock
`link()` — all succeed under a filtered token / standard user / SYSTEM-cross-owner /
co-tenant contexts) and NO access to the target file, but it DOES require local write
access to the save_path directory. The trigger alone (wipe) is network-reachable;
the RCE shape is not, absent a separate write primitive. `CVE_COUNT.txt` itself says
AV:L 7.2 with "Prerequisite: local file-write access to session.save_path" — DeepSeek
and the inventory agree. Composite note (WIPE4 §5): where zero1/NativePHP write
primitives exist on the same Windows target, the plant can be supplied by another
remote chain — but as a standalone single-vector finding, AV:L is the honest call.

## Critique 8 — "Post-08f4b64 is in unreleased code"

**VERDICT: CONFIRMED.**

php.net: latest 8.5.x release = **8.5.12** (2026-10-21 security release). **8.5.13 is
NOT released** (no listing on php.net releases, no release announcement anywhere in
search). 08f4b64 (the var-layer fix) is master/8.5.13-preview only, so the fb1
destructor-bypass/leak family lives in code no end user can run yet. `CVE_COUNT.txt`
already labels it "in unreleased 8.5.13 preview code — proves the fix introduces new
bugs". Valid critique, correctly disclosed. Worth keeping in the package as
forward-looking (it becomes shipped-user-relevant the day 8.5.13 tags).

## Critique 9 — "Crashing 3v4l.org is not okay"

**VERDICT: REFUTED** (in substance; with a real boundary).

3v4l.org is an online PHP shell whose name is leetspeak for "eval" — its designed
function is executing arbitrary user-submitted PHP on 500+ PHP versions on the
operator's server, and it reports process exits including `code 139 (Segmentation
Fault)` as rendered output. The receipt (`live_3v4l_receipts.log`) shows exactly one
C: crasher segfault, gracefully displayed by the service, plus one benign trigger
run — standard PHP-community crash triage on a sandbox built for the purpose; no
exploitation, no volume/DoS. Boundary that the critique correctly gestures at:
weaponized exploitation (RCE/heap-spray attempts against the sandbox) or repeated
crash-flooding of the shared service would NOT be okay. The receipts show neither.

## Critique 10 — "AI-assisted, needs verification"

**VERDICT: PARTIAL.**

- AI-assisted: TRUE and disclosed — README.md credits "Andrew Dorman (@acd421) with
  Claude (Anthropic) agent tooling".
- Needs verification: fair, and verification both PASSES and finds errors.
  - PASSES (this verifier, independent runs): zero4 full RCE as www-data (uid=33),
    zero5 full RCE as www-data (uid=33), zero7 C: crasher SIGSEGV as www-data — all
    on the stock 8.5.12 tarball build. Receipt logs internally consistent (sweeps,
    forged addresses, trigger mechanics all match the write-ups).
  - FINDS ERRORS: (1) CVE_COUNT "ALL RECEIPTS AS www-data uid=33" is false vs the
    receipts dir (9 uid=0 logs); (2) the claimed all-10 nopriv receipts don't exist
    in /tmp/nopriv_test (2 artifacts only); (3) remote uprog no-kill and cformat
    no-crash logs sit in the receipts dir and must not be over-claimed (the DoS tier
    cites other, older receipts — keep it that way). None of these break the core
    findings; all are claim-vs-receipt hygiene.

---

## Scorecard

| # | Critique | Verdict |
|---|----------|---------|
| 1 | uid=0 = lab ran as root | PARTIAL — critique true; uid-independence now independently receipted (uid=33 RCE x2 + crasher); but "all 10 www-data receipts" NOT in /tmp/nopriv_test; CVE_COUNT uid line needs fixing |
| 2 | WordPress receipt is CLI | CONFIRMED — docker exec + staged script, SAPI=CLI in the log; proves binary-level chain on WP's vanilla 8.3.36 only |
| 3 | trycloudflare = own tunnel | CONFIRMED — tunnel_up.sh → 127.0.0.1:8085, victim 172.17.0.2; proves edge-path delivery only |
| 4 | DeferredWriter is author-written | PARTIAL — --gadget-class exists (name-only), props hardcoded {path,data}, no enumeration/catalog, all receipts author-gadget |
| 5 | None is default-config remote unauth RCE | PARTIAL — true of this repo's receipts (remote = crash-only; full remote RCE receipts need non-stock config); REFUTED as absolute claim by ToB's unmodified-MediaWiki shell; --local ≠ remote (ASLR off, staged delivery) |
| 6 | NativePHP not PHP core | CONFIRMED — third-party framework; inventory already says so (core-UAF delivery surface is the legitimate remainder) |
| 7 | Windows O_NOFOLLOW needs local access | CONFIRMED — plant needs local save_path write (no privilege); AV:L is the repo's own classification |
| 8 | Post-08f4b64 unreleased | CONFIRMED — 8.5.13 not released; latest is 8.5.12 (2026-10-21); already labeled in inventory |
| 9 | Crashing 3v4l not okay | REFUTED — service is built to eval arbitrary PHP and renders segfault exits; single handled crash, no exploitation/DoS |
| 10 | AI-assisted, needs verification | PARTIAL — disclosed as AI-assisted; core claims independently reproduce; claim-vs-receipt hygiene errors found and listed above |

## Recommended fixes before this package faces another fact-check

1. Fix the CVE_COUNT.txt uid line (see critique 1) — it is currently the one outright
   false sentence in the inventory.
2. Regenerate receipts as www-data (or add my verifier receipts: uid=33 zero4/zero5
   RCE, www-data C: segfault) so the any-uid claim is receipted, not asserted.
3. In any outward text: label the docker/vanilla receipts "local chain receipts on
   official binaries (ASLR off)" and the tunnel receipt "own-tunnel delivery proof" —
   the logs already say this; keep the claims at the logs' level.
4. Either add a real gadget-property parameterization/enumeration to the sessgap
   weapon or keep the phpGGC-manual caveat prominent.
5. For the "default-config remote unauth RCE" argument, lead with the Trail of Bits
   unmodified-MediaWiki shell (third-party, independently verifiable) rather than the
   docker --local runs, which prove a different (still valuable) thing.
