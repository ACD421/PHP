#!/bin/bash
# manual carrier runs inside the vanilla container, output to files
docker exec van85 sh -c 'cd /tmp/w && setarch x86_64 -R /usr/local/bin/php -n sr2_call.php 0000000000000000 0000000000000000' > /tmp/van_run0.txt 2>&1
echo "rc0=$?"
cat /tmp/van_run0.txt
echo "==== run with 1 1 ===="
docker exec van85 sh -c 'cd /tmp/w && setarch x86_64 -R /usr/local/bin/php -n sr2_call.php 0000000000000001 0000000000000001' > /tmp/van_run1.txt 2>&1
echo "rc1=$?"
cat /tmp/van_run1.txt
echo "==== maps chunks seen by the carrier ===="
docker exec van85 cat /tmp/.p2s_maps 2>/dev/null | grep -c zend_alloc
docker exec van85 cat /tmp/.p2s_maps 2>/dev/null | grep zend_alloc | head -5
