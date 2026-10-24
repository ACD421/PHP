#!/bin/bash
# Rigorous arm->fire sequence + negative control on the WP jammy victim.
set -u
NEG=${1:-0}   # 1 = negative control (fire without arm)
PORT=8080
SID=wp0123456789abcdefghijklmnopqrstu

restart_victim() {
  for P in $(pgrep -f "apache2 -X -f /tmp/v_wp/wp.conf" 2>/dev/null); do sudo -n kill -9 "$P" 2>/dev/null; done
  sleep 0.5
  : > /tmp/v_wp/error.log
  sudo -n apache2 -X -f /tmp/v_wp/wp.conf > /tmp/v_wp/x.log 2>&1 &
  disown
  for i in $(seq 1 40); do curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$PORT/" && break; sleep 0.4; done
}

restart_victim
echo "[seq] victim fresh; front: $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:$PORT/)"

if [ "$NEG" = "0" ]; then
  bash /mnt/c/Users/andre/Downloads/php2shell-zeros/weapons/lab/test_arm_wp.sh 2>/dev/null | grep -E 'ARM status|front'
fi

bash /mnt/c/Users/andre/Downloads/php2shell-zeros/weapons/lab/test_fire_wp.sh 2>/dev/null | grep -E 'fire#|KILL|front'
echo "[seq] x.log tail: $(tail -2 /tmp/v_wp/x.log 2>/dev/null | tr '\n' ' ')"
grep -icE 'exhausted' /tmp/v_wp/error.log | sed 's/^/[seq] exhausted-lines: /'
