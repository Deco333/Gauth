@echo off
REM ============================================================
REM  gauth-pc - ��⠭���� ����ᨬ��⥩ ����� ����᪮� (Windows)
REM  ������� ���� �� �⮬� 䠩��.
REM ============================================================
setlocal
cd /d "%~dp0"
chcp 65001 >nul

where py >nul 2>nul
if %errorlevel%==0 (set PY=py -3) else (set PY=python)

echo.
echo [1/2] Проверяю Python...
%PY% --version
if errorlevel 1 (
    echo.
    echo  ОШИБКА: Python не найден.
    echo  Установите его с https://www.python.org/downloads/
    echo  и ОБЯЗАТЕЛЬНО отметьте галочки:
    echo    - "Add python.exe to PATH"
    echo    - "tcl/tk and IDLE"   ^(нужно для графического окна^)
    echo.
    pause
    exit /b 1
)

echo.
echo [2/2] Ставлю библиотеки...
%PY% -m pip install --upgrade pip
%PY% -m pip install cryptography zxing-cpp pillow pyqrcode pypng pyperclip keyring
if errorlevel 1 (
    echo.
    echo  Не удалось поставить библиотеки. Проверьте интернет и попробуйте:
    echo      %PY% -m pip install cryptography
    echo  ^(без остальных программа тоже работает, но не умеет читать фото QR^)
)

echo.
echo ============================================================
echo  Готово! Теперь запустите окно с кодами:
echo      gauth-gui.cmd
echo ============================================================
echo.
pause
