<?php
header("Content-Type: text/plain");
echo "POST[p] len=" . strlen($_POST["PHP_SESSION_UPLOAD_PROGRESS"] ?? "")
    . " val=[" . ($_POST["PHP_SESSION_UPLOAD_PROGRESS"] ?? "-") . "]\n";
