#!/bin/bash
# wp2_collect_receipts.sh - copy key receipts from /tmp/p2s_c2 to durable Windows storage
DST="$(cd "$(dirname "$0")" && pwd)/receipts"
SRC=/tmp/p2s_c2
mkdir -p "$DST"
cp "$SRC/fuzz_keys_all.report"            "$DST/" 2>/dev/null
cp "$SRC/fuzz_keys_fk_L65536.report"      "$DST/" 2>/dev/null
cp "$SRC/fuzz_keys_fk_LEN.report"         "$DST/" 2>/dev/null
cp "$SRC/fuzz_keys_fc_.report"            "$DST/" 2>/dev/null
cp "$SRC/shots.index"                     "$DST/" 2>/dev/null
cp "$SRC/strace/trace.log"                "$DST/strace_reject_path.log" 2>/dev/null
cp "$SRC/gdb/gdb_out.log"                 "$DST/gdb_live_key.log" 2>/dev/null
cp "$SRC/binobj_trace/trace.log"          "$DST/strace_php_binary_roundtrip.log" 2>/dev/null
cp "$SRC/race/reader1.log"                "$DST/" 2>/dev/null
cp "$SRC/race/reader2.log"                "$DST/" 2>/dev/null
cp "$SRC/race/srv_err.log"                "$DST/race_srv_err.log" 2>/dev/null
cp "$SRC/chaos/srv_err.log"               "$DST/chaos_srv_err.log" 2>/dev/null
cp "$SRC/anomaly/server_err.log"          "$DST/anomaly_asan_srv_err.log" 2>/dev/null
cp "$SRC/runs/dfF_nopipe_enospc/server_err.log" "$DST/dfF_enospc_srv_err.log" 2>/dev/null
cp "$SRC/runs/cx_php_v_ser_pipe/server_err.log" "$DST/cx_mismatch_destroy_srv_err.log" 2>/dev/null
cp "$SRC/runs/cx_php_v_php_pipe/server_err.log" "$DST/cx_baseline_reject_srv_err.log" 2>/dev/null
ls -la "$DST" | head -30
echo COLLECTED
