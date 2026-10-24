set pagination off
set confirm off
set auto-load safe-path /
break var_destroy
run -n vdR3_call.php 0000000000000000 0093824990838784
printf "PARAM_SLOT:\n"
x/6gx 0x7fffffffa448
kill
quit
