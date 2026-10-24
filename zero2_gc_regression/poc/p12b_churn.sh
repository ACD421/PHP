#!/bin/bash
# P12b: php -a + post-corruption churn to surface the SEGV (image-3 shape).
P=${1:-/tmp/php8512_build/plain2/sapi/cli/php}
printf '$shared = new SimpleXMLElement("<root a=\\"1\\"><b>2</b><c>3</c></root>");\nget_object_vars($shared);\n$w = new stdClass();\n$w->x = $shared;\n$w->self = $w;\nunset($shared, $w);\ngc_collect_cycles();\nfor ($i = 0; $i < 50; $i++) { $a[$i] = new SimpleXMLElement("<r><x>1</x></r>"); get_object_vars($a[$i]); }\ngc_collect_cycles();\n$s = serialize($a);\nunset($a);\ngc_collect_cycles();\necho "churn-done\\n";\nexit\n' | timeout 30 $P -a -d zend.enable_gc=1 2>&1 | tail -4
echo "p12b-exit=$?"
