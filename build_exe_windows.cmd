@echo off
REM Скрипт для сборки gauth-pc в Windows EXE файл
REM Запустите этот файл на компьютере с Windows

echo Установка зависимостей...
pip install pyinstaller
pip install -r requirements.txt

echo Сборка EXE файла...
pyinstaller --onefile --windowed --name gauth-pc --icon=NONE gauth.py

echo.
echo Готово! EXE файл находится в папке dist\gauth-pc.exe
pause
