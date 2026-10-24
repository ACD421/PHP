set pagination off
set confirm off
set auto-load safe-path /
break var_destroy
run -n vdR3_call.php 0000000000000000 0093824990838784
set $d = *(struct php_unserialize_data **)var_hash
printf "D=%p LAST=%p FIRST_DTOR=%p\n", $d, $d->last, $d->first_dtor
kill
quit
