#!/bin/bash
# wp2_extralong.sh - 4MB/8MB/16MB keys + percent/format-string-heavy keys
CL=$(cd "$(dirname "$0")" && pwd)
mkdir -p /tmp/p2s_c2/keys
python3 - <<'EOF'
import os
d = "/tmp/p2s_c2/keys"
def w(name, b): open(f"{d}/{name}.hex", "w").write(b.hex())
for n in [4*1024*1024, 8*1024*1024, 16*1024*1024]:
    w(f"xlong{n}", b"A"*(n-1) + b"|")
w("pct", b"%s%s%d%n%p%%|" + b"%x" * 40)
w("pct_nul", b"\x00" + b"%s%n%p|" * 10 + b"\x00")
w("fmt", b"%1$s%2$s|")
w("esc", b"\x1b[31mRED\x1b[0m|")
w("utf16ish", ("\x00a\x00b\x00c|").encode("latin1"))
EOF
for N in 4194304 8388608 16777216; do
  TAG="xl_${N}" POISON_FILE="/tmp/p2s_c2/keys/xlong${N}.hex" FILESIZE=4096 bash "$CL/wp2_shot.sh"
done
for K in pct pct_nul fmt esc utf16ish; do
  TAG="xk_${K}" POISON_FILE="/tmp/p2s_c2/keys/${K}.hex" FILESIZE=4096 bash "$CL/wp2_shot.sh"
done
echo EXTRALONG-DONE
