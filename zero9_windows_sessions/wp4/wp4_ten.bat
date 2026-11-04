set "WP4BASE=%~dp0"
set "WP4BASE=%WP4BASE:~0,-1%"
@echo off
whoami > "%WP4BASE%\win_lab\x4\sess\wp4ten_plant.log" 2>&1
mklink /H "%WP4BASE%\win_lab\x4\sess\sess_x4aaaaaaaaaaaaaaaaaaaaaaaaaa" "%WP4BASE%\win_lab\x4\docroot\empty4.php" >> "%WP4BASE%\win_lab\x4\sess\wp4ten_plant.log" 2>&1
