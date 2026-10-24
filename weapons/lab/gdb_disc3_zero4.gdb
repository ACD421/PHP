set pagination off
set confirm off
set auto-load safe-path /
break var_destroy
run -n vdR3_call.php 0000000000000000 0093824990838784
set $vh = *(char **)0x7fffffffa448
printf "VH=%p\n", $vh
x/8gx $vh
kill
quit
