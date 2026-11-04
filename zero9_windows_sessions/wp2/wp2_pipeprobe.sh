#!/bin/bash
# probe: what does a '|' in a -d ini value do to the CLI php?
P=/tmp/php8512_build/asan2/sapi/cli/php
echo "--- prefix with trailing pipe ---"
"$P" -d session.upload_progress.prefix="PPPP|" -r 'var_dump(ini_get("session.upload_progress.prefix"));' 2>&1
echo "--- prefix with mid pipe ---"
"$P" -d session.upload_progress.prefix="P|P" -r 'var_dump(ini_get("session.upload_progress.prefix"));' 2>&1
echo "--- prefix plain ---"
"$P" -d session.upload_progress.prefix="PPPP" -r 'var_dump(ini_get("session.upload_progress.prefix"));' 2>&1
echo "--- ini file variant ---"
printf 'session.upload_progress.prefix="PPP|Q"\n' > /tmp/p2s_c2/pref.ini
"$P" -c /tmp/p2s_c2/pref.ini -r 'var_dump(ini_get("session.upload_progress.prefix"));' 2>&1
