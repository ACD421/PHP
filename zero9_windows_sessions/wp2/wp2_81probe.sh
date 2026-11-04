#!/bin/bash
# wp2_81probe.sh - does Ubuntu 8.1.2-1ubuntu2.27 have the invalid-key reject+warning?
mkdir -p /tmp/p2s_c2/p81
cd /tmp/p2s_c2/p81
rm -f sess_*
echo "=== 8.1.2 CLI: pipe key in \$_SESSION, write close ==="
/usr/bin/php -d session.save_path=/tmp/p2s_c2/p81 -d session.serialize_handler=php -d display_errors=1 -d log_errors=0 -r '
session_id("probesid0000000000000000000000");
session_start();
$_SESSION["inj|O:14:\"X\""] = 1;
$_SESSION["pref"] = "keepme";
session_write_close();
echo "written\n";
' 2>&1
echo "file: $(stat -c %s sess_probesid0000000000000000000000 2>/dev/null || echo missing)"
xxd sess_probesid0000000000000000000000 2>/dev/null | head -4
echo
echo "=== 8.5.12 CLI: same probe ==="
/tmp/php8512_build/plain2/sapi/cli/php -d session.save_path=/tmp/p2s_c2/p81 -d session.serialize_handler=php -d display_errors=1 -d log_errors=0 -r '
session_id("probesid85");
session_start();
$_SESSION["inj|O:14:\"X\""] = 1;
$_SESSION["pref"] = "keepme";
session_write_close();
echo "written\n";
' 2>&1
echo "file: $(stat -c %s sess_probesid85 2>/dev/null || echo missing)"
xxd sess_probesid85 2>/dev/null | head -4
