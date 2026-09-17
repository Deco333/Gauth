#!/bin/bash
# Скрипт для сборки gauth-pc в Linux исполняемый файл

echo "Установка зависимостей..."
pip install pyinstaller
pip install -r requirements.txt

echo "Сборка исполняемого файла..."
pyinstaller --onefile --windowed --name gauth-pc --icon=NONE gauth.py

echo ""
echo "Готово! Исполняемый файл находится в папке dist/gauth-pc"
