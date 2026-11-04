@echo off
REM wp4_devmode.bat - Dev Mode OFF/ON capability boundary, run under FILTERED token.
REM arg1: current devmode state label (OFF or ON)
setlocal
set "WP4BASE=%~dp0"
set "WP4BASE=%WP4BASE:~0,-1%"
set PY=C:\Python313\python.exe
set D=%WP4BASE%\devmode_lab
set L=%WP4BASE%\receipts\devmode_%1.log
if not exist %D% mkdir %D%
echo x > %D%\t.txt
echo ===== DevMode=%1 (filtered token) ===== > "%L%"
%SystemRoot%\System32\whoami.exe /priv | findstr /i "SeChangeNotify SeCreateSymbolicLink" >> "%L%"
echo --- python os.symlink (existing target) --- >> "%L%"
%PY% -c "import os; os.symlink(r'%D%\t.txt', r'%D%\sym_%1.txt'); print('PY-SYMLINK-OK')" >> "%L%" 2>&1
echo --- python os.symlink (dangling) --- >> "%L%"
%PY% -c "import os; os.symlink(r'%D%\nope_%1.php', r'%D%\dang_%1.txt'); print('PY-SYMLINK-DANGLING-OK')" >> "%L%" 2>&1
echo --- python os.link (hardlink control) --- >> "%L%"
%PY% -c "import os; os.link(r'%D%\t.txt', r'%D%\hl_%1.txt'); print('PY-LINK-OK')" >> "%L%" 2>&1
dir /a %D% >> "%L%" 2>&1
