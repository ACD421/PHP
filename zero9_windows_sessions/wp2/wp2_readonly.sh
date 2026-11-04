#!/bin/bash
# wp2_readonly.sh - reject path when save_path is unwritable/broken (angle 2)
CL=$(cd "$(dirname "$0")" && pwd)
ART=/tmp/p2s_c2
RO=/tmp/p2s_c2/ro
SID=vicsid00000000000000000000000

echo "== ro1: read-only directory (chmod 555) =="
rm -rf "$RO"; mkdir -p "$RO"
printf 'pref|s:6:"keepme";' > "$RO/sess_$SID"
chmod 555 "$RO"
TAG=ro_dir POISON=417C42 SAVEPATH="$RO" bash "$CL/wp2_shot.sh"
chmod 755 "$RO"

echo "== ro2: save_path is a FILE not a dir =="
rm -rf "$RO"; printf 'x' > "$RO"
TAG=ro_file POISON=417C42 SAVEPATH="$RO" bash "$CL/wp2_shot.sh"

echo "== ro3: save_path nonexistent dir =="
rm -rf "$RO"
TAG=ro_missing POISON=417C42 SAVEPATH=/tmp/p2s_c2/nosuchdir bash "$CL/wp2_shot.sh"

echo "== ro4: session file itself read-only (dir writable) =="
rm -rf "$RO"; mkdir -p "$RO"
printf 'pref|s:6:"keepme";' > "$RO/sess_$SID"
chmod 444 "$RO/sess_$SID"
TAG=ro_sessfile POISON=417C42 SAVEPATH="$RO" bash "$CL/wp2_shot.sh"
echo "  size-after: $(stat -c %s "$RO/sess_$SID" 2>/dev/null || echo -1)"
chmod 644 "$RO/sess_$SID"
echo READONLY-DONE
