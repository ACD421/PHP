@echo off
REM wp4_unpriv.bat - NO-PRIVILEGE plant capability audit, run under a FILTERED
REM (non-elevated) token via:  runas /trustlevel:0x20000 "cmd /c wp4_unpriv.bat"
REM Everything writes into WP4BASE; caller harvests the log.
setlocal enableextensions
set "WP4BASE=%~dp0"
set "WP4BASE=%WP4BASE:~0,-1%"
set PHP85=%WP4BASE%\..\wp3\winphp\8512\php.exe
set PHP81=%WP4BASE%\..\wp3\winphp\8134\php.exe
if not exist "%PHP85%" set "PHP85=C:\Users\andre\Downloads\php2shell-claude\wp3\winphp\8512\php.exe"
if not exist "%PHP81%" set "PHP81=C:\Users\andre\Downloads\php2shell-claude\wp3\winphp\8134\php.exe"
set PY=C:\Python313\python.exe
set LOG=%WP4BASE%\receipts\unpriv_audit.log
set D=%WP4BASE%\unpriv_lab
if not exist %D% mkdir %D%
echo ===== wp4 unpriv audit %date% %time% ===== > "%LOG%"
echo --- whoami /priv (filtered token) --- >> "%LOG%"
whoami >> "%LOG%" 2>&1
%SystemRoot%\System32\whoami.exe /priv >> "%LOG%" 2>&1

echo --- [U1] cmd mklink /H (hardlink, existing target) --- >> "%LOG%"
echo x > %D%\t.txt
mklink /H %D%\hl_cmd.txt %D%\t.txt >> "%LOG%" 2>&1

echo --- [U2] powershell New-Item HardLink --- >> "%LOG%"
powershell -NoProfile -Command "New-Item -ItemType HardLink -Path '%D%\hl_ps.txt' -Target '%D%\t.txt' | Out-Null; if ($?) { 'PS-HARDLINK-OK' } else { 'PS-HARDLINK-FAIL' }" >> "%LOG%" 2>&1

echo --- [U3] python os.link + os.symlink (dangling file symlink) --- >> "%LOG%"
%PY% -c "import os;os.link(r'%D%\t.txt',r'%D%\hl_py.txt');print('PY-LINK-OK')" >> "%LOG%" 2>&1
%PY% -c "import os;os.symlink(r'%D%\no_such_target.php',r'%D%\dang_py.txt');print('PY-SYMLINK-DANGLING-OK')" >> "%LOG%" 2>&1
%PY% -c "import os;os.symlink(r'%D%\t.txt',r'%D%\sym_py.txt');print('PY-SYMLINK-OK')" >> "%LOG%" 2>&1

echo --- [U4] PHP link() (hardlink) stock builds --- >> "%LOG%"
"%PHP85%" -n -r "var_dump(link('%D%/t.txt', '%D%/hl85.txt'));" >> "%LOG%" 2>&1
"%PHP81%" -n -r "var_dump(link('%D%/t.txt', '%D%/hl81.txt'));" >> "%LOG%" 2>&1

echo --- [U5] PHP symlink() (relative existing target, process CWD) stock builds --- >> "%LOG%"
cd /d %D%
"%PHP85%" -n -r "var_dump(symlink('t.txt', 'sym85.txt')); var_dump(is_link('sym85.txt'));" >> "%LOG%" 2>&1
"%PHP81%" -n -r "var_dump(symlink('t.txt', 'sym81.txt')); var_dump(is_link('sym81.txt'));" >> "%LOG%" 2>&1
cd /d %WP4BASE%

echo --- inventory --- >> "%LOG%"
dir /a %D% >> "%LOG%" 2>&1
echo ===== end ===== >> "%LOG%"
