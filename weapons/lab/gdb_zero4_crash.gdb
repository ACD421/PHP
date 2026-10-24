set pagination off
set confirm off
run
printf "== CRASH STATE ==\n"
info registers rip rdi rsi rax
bt 12
x/3i $pc
quit
