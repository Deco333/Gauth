@echo off
REM gauth-pc: сразу открыть графическое окно с кодами 2FA.
REM Создайте ярлык на этот файл — и держите его на рабочем столе/панели задач.
setlocal
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (
    REM -3w = Python 3 без консольного окна
    py -3w gauth.py gui
    if errorlevel 1 py -3 gauth.py gui
    goto :eof
)

where pythonw >nul 2>nul
if %errorlevel%==0 (
    pythonw gauth.py gui
    goto :eof
)

python gauth.py gui
endlocal
