@echo off
REM gauth-pc: запуск без установки. Примеры:
REM   run codes
REM   run import ga --qr C:\Users\me\Desktop\ga-qr.png
REM   run get google --bare
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 gauth.py %*
) else (
  python gauth.py %*
)
endlocal
