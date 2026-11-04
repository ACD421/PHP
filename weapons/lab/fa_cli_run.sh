#!/bin/sh
# fa_cli_run.sh — fa chain CLI self-test in-container, rc captured
# usage: fa_cli_run.sh [attempts] [groom] [flavor]
A=${1:-4}
G=${2:-0}
F=${3:-8511}
php -n -d error_reporting=0 -r 'require "/tmp/fa/fa_cli_core.php"; fa_cli_main(array("x", "'"$A"'", "'"$G"'", "'"$F"'"));' > /tmp/o.txt 2>&1
RC=$?
echo "rc=$RC"
echo "---- output (tail 40) ----"
tail -40 /tmp/o.txt
echo "---- diag ----"
cat /tmp/fa_diag.log 2>/dev/null
echo "---- marker ----"
cat /var/www/html/fa_rce_receipt.txt 2>/dev/null || echo "(no marker)"
