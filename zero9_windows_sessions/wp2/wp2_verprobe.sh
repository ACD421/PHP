#!/bin/bash
# wp2_verprobe.sh - which versions warn on the invalid-key reject?
mkdir -p /tmp/p2s_c2/pver; cd /tmp/p2s_c2/pver; rm -f sess_*
for BIN in /usr/bin/php /tmp/php8511_build/out/sapi/cli/php /tmp/php8512_build/plain2/sapi/cli/php /tmp/php8512_build/asan2/sapi/cli/php; do
  [ -x "$BIN" ] || continue
  V=$("$BIN" -r 'echo PHP_VERSION;')
  rm -f sess_verprobe
  OUT=$("$BIN" -d session.save_path=/tmp/p2s_c2/pver -d session.serialize_handler=php -d display_errors=1 -d log_errors=0 -d error_reporting=E_ALL -r '
session_id("verprobe"); session_start();
$_SESSION["inj|O:14:\"X\""] = 1; $_SESSION["pref"] = "keepme";
session_write_close();' 2>&1)
  SZ=$(stat -c %s sess_verprobe 2>/dev/null || echo missing)
  W=$(echo "$OUT" | grep -c "invalid key")
  echo "php=$V bin=$BIN size=$SZ warn=$W"
done
echo "=== after=6 file content (cx_php_serialize_v_phpnoclass_pipe) ==="
xxd /tmp/p2s_c2/runs/cx_php_serialize_v_phpnoclass_pipe/sess/sess_vicsid00000000000000000000000 2>/dev/null | head -3
