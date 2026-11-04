@echo off
REM wp4_access.bat - CreateHardLink target-access matrix under the FILTERED token.
REM Cases are prepared (elevated) by wp4_deploy.sh phase B. Logs to receipts\access_matrix.log
setlocal enableextensions
set "WP4BASE=%~dp0"
set "WP4BASE=%WP4BASE:~0,-1%"
set PY=C:\Python313\python.exe
set D=%WP4BASE%\access_lab
set LOG=%WP4BASE%\receipts\access_matrix.log
echo ===== CreateHardLink target-access matrix (filtered token) %date% %time% ===== > "%LOG%"

echo [B0 normal target] >> "%LOG%"
mklink /H %D%\hl_normal.txt %D%\t_normal.txt >> "%LOG%" 2>&1
%PY% -c "import os; os.link(r'%D%\t_normal.txt', r'%D%\hlp_normal.txt'); print('PY-LINK-OK')" >> "%LOG%" 2>&1

echo [B1 readonly-attribute target] >> "%LOG%"
mklink /H %D%\hl_roattr.txt %D%\t_roattr.txt >> "%LOG%" 2>&1
%PY% -c "import os; os.link(r'%D%\t_roattr.txt', r'%D%\hlp_roattr.txt'); print('PY-LINK-OK')" >> "%LOG%" 2>&1

echo [B2 ACL deny write-data+append target] >> "%LOG%"
mklink /H %D%\hl_denyw.txt %D%\t_denyw.txt >> "%LOG%" 2>&1
%PY% -c "import os; os.link(r'%D%\t_denyw.txt', r'%D%\hlp_denyw.txt'); print('PY-LINK-OK')" >> "%LOG%" 2>&1

echo [B3 ACL RX-only target] >> "%LOG%"
mklink /H %D%\hl_rxonly.txt %D%\t_rxonly.txt >> "%LOG%" 2>&1
%PY% -c "import os; os.link(r'%D%\t_rxonly.txt', r'%D%\hlp_rxonly.txt'); print('PY-LINK-OK')" >> "%LOG%" 2>&1

echo --- inventory --- >> "%LOG%"
dir /a %D% >> "%LOG%" 2>&1
echo ===== end ===== >> "%LOG%"
