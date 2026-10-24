set pagination off
set confirm off
break var_destroy
run
printf "== var_destroy #1 (outer)\n"
set $d = var_hashx
set $b = (var_entries *)$d->entries.next
set $i = 0
while ($b != 0 && $i < 4)
  printf "  chained_block[%d] = %p used_slots=%ld\n", $i, $b, $b->used_slots
  set $b = (var_entries *)$b->next
  set $i = $i + 1
end
delete 1
break zif_str_repeat
continue
set $rv = $rsi
finish
printf "== GROOM str_repeat returned zend_string* = %p (val = string+24)\n", ((struct _zval_struct *)$rv)->value.str
printf "RECLAIM-VERDICT: groom result vs first chained block above\n"
continue
quit
