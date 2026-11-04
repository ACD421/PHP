@echo off
REM wp4_sys.bat - run the wp4 lab PHP server as NT AUTHORITY\SYSTEM (schtasks /ru SYSTEM).
REM Invoked by wp4_deploy.sh phase E. Serves until the task is ended (schtasks /end).
setlocal
set "WP4BASE=%~dp0"
set "WP4BASE=%WP4BASE:~0,-1%"
if not defined WP3PHP set "WP3PHP=%WP4BASE%\..\wp3\winphp\8512\php.exe"
if not exist "%WP3PHP%" set "WP3PHP=C:\Users\andre\Downloads\php2shell-claude\wp3\winphp\8512\php.exe"
set LAB=%WP4BASE%\win_lab\sys8512
cd /d "%LAB%"
"%WP3PHP%" -c "%LAB%\php.ini" -S 127.0.0.1:18816 -t "%LAB%\docroot" >> "%LAB%\server_out.log" 2>> "%LAB%\server_err.log"
