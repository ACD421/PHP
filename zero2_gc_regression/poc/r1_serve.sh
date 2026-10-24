#!/bin/bash
# r1_serve.sh — php -S lab on the 8.5.12 plain2 build (remote shape).
#   r1_serve.sh start|stop|log|alive [port]
set -u
PORT=${2:-18196}
ROOT=/tmp/php2shell_r
PHP=/tmp/php8512_build/plain2/sapi/cli/php
DIR=/mnt/c/Users/andre/Downloads/php2shell-claude

start() {
  stop >/dev/null 2>&1
  mkdir -p $ROOT
  cp $DIR/r1_victim.php $ROOT/index.php 2>/dev/null
  cp $DIR/r2_victim.php $ROOT/r2.php 2>/dev/null
  : > $ROOT/server.log
  (cd $ROOT && exec $PHP -n -S 127.0.0.1:$PORT -t $ROOT) > $ROOT/server.log 2>&1 &
  echo $! > $ROOT/server.pid
  disown
  sleep 1
  curl -s --max-time 3 -X POST --data '<root><a>1</a></root>' http://127.0.0.1:$PORT/index.php && echo " [up pid=$(cat $ROOT/server.pid)]"
}

stop() {
  [ -f $ROOT/server.pid ] && kill -9 $(cat $ROOT/server.pid) 2>/dev/null
  echo stopped
}

case "${1:-}" in
  start) start ;;
  stop)  stop ;;
  restart) stop >/dev/null 2>&1; sleep 0.3; start ;;
  log)   tail -n "${2:-20}" $ROOT/server.log ;;
  alive) [ -f $ROOT/server.pid ] && kill -0 $(cat $ROOT/server.pid) 2>/dev/null && echo "ALIVE $(cat $ROOT/server.pid)" || echo DEAD ;;
  *) echo "usage: r1_serve.sh start|stop|restart|log|alive [port]"; exit 1 ;;
esac
