#!/bin/bash
setarch x86_64 -R /tmp/php8512_build/plain2/sapi/cli/php -n -r 'echo file_get_contents("/proc/self/maps");' | head -60
echo "=== sr2 run maps (via marker crash? no - just show) ==="
