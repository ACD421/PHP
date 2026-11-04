#!/bin/sh
# fa_rc.sh — run a container PHP script and report rc + output tail
P=$1
S=$2
php -n "$P" "$S" > /tmp/rc_out.txt 2>&1
RC=$?
echo "rc=$RC"
tail -12 /tmp/rc_out.txt
