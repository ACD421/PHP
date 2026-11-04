#!/bin/bash
# wp2_binobj_loop.sh - determinism loop for the php_binary+pipe+obj case
CL=$(cd "$(dirname "$0")" && pwd)
BIN_OBJ='036f626a4f3a363a2253706c4f626a223a323a7b733a313a2261223b733a313a2263223b733a343a2273656c66223b723a313b7d'
for i in 1 2 3 4 5 6 7 8 9 10; do
  TAG="cxloop_$i" HANDLER=php_binary VICTIM=custom VICTIM_HEX="$BIN_OBJ" \
    POISON=4162637C4F3A3130 FILESIZE=4096 bash "$CL/wp2_shot.sh"
done
echo LOOP-DONE
