set pagination off
set confirm off
set auto-load safe-path /
set disassemble-next-line off

# M1: receipt that a re-entrant-serialize-context allocation (the Groomer
# __sleep str_pad) reclaims the old arData block freed by the mid-walk resize.
break php_var_serialize_destroy
run -n sr2_reclaim.php marker 4141414141414141

# hit 1 = OUTER serialize teardown (the script's first and only outer serialize)
set $d  = d
set $ht = &$d->ht
set $base = (char *)((char *)$ht->arData + 4*(int)$ht->nTableMask)
printf "== OUTER destroy entry: d=%p arData=%p mask=%d nNumUsed=%u nTableSize=%u pDestructor=%p\n", $d, $ht->arData, $ht->nTableMask, $ht->nNumUsed, $ht->nTableSize, $ht->pDestructor
printf "== old arData block (640B = 128 hash + 16 buckets x 32): %p ; bucket-4 val: %p\n", $base, $base + 256

# catch the resize: zend_hash.c:1542 = the post-pefree zend_hash_rehash line
tbreak zend_hash.c:1542
continue
printf "== RESIZE (mid-walk): old_data=%p  new arData=%p  -> old 640B block FREED\n", old_data, ht->arData
printf "   old_data == base ? %s\n", ($base == (char *)old_data) ? "YES" : "NO"

# M1 watchpoint: bucket-4 val.value (base+256). The efree writes only
# base+0..8 (bin freelist push); the resize rehash writes only the NEW block.
# First write here = the reclaiming allocation copying payload bytes.
watch *(unsigned long *)($base + 256)
continue
printf "== M1: FIRST write into the freed arData block @ %p\n", $base + 256
bt 14
printf "== groomed bucket-4 val now:\n"
x/4gx $base + 256
delete 3
disable 1
continue
printf "== M2 (bonus, same run): stop after walk resumed on groomed block\n"
bt 10
info registers rax rbx rcx rdx rsi rdi rip
x/i $pc
