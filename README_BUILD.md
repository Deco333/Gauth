# Инструкция по сборке gauth-pc

## Изменения в проекте:
1. ✅ Убран ввод пароля при входе в приложение (для незашифрованных хранилищ)
2. ✅ Добавлено сохранение QR-кодов через контекстное меню (ПКМ → "Сохранить QR…")
3. ✅ Добавлена возможность копирования кода через Ctrl+C или ПКМ → "Копировать код"

## Сборка на Windows (.exe):

### Вариант 1: Автоматическая сборка
1. Откройте командную строку (cmd) в папке проекта
2. Запустите: `build_exe_windows.cmd`
3. Дождитесь завершения сборки
4. Готовый файл: `dist\gauth-pc.exe`

### Вариант 2: Ручная сборка
```cmd
pip install pyinstaller
pip install -r requirements.txt
pyinstaller --onefile --windowed --name gauth-pc gauth.py
```

## Сборка на Linux:

### Автоматическая сборка
```bash
./build_exe_linux.sh
```

### Ручная сборка
```bash
pip install pyinstaller
pip install -r requirements.txt
pyinstaller --onefile --windowed --name gauth-pc gauth.py
```

Готовый файл: `dist/gauth-pc`

## Сборка на macOS:
```bash
pip install pyinstaller
pip install -r requirements.txt
pyinstaller --onefile --windowed --name gauth-pc gauth.py
```

Готовое приложение: `dist/gauth-pc.app`

## Использование:

### Запуск GUI приложения:
- Windows: `gauth-pc.exe gui`
- Linux: `./gauth-pc gui`
- macOS: `./gauth-pc gui`

### Копирование кода:
1. Выделите нужную запись в списке
2. Нажмите **Ctrl+C** или **ПКМ → Копировать код**
3. Код скопирован в буфер обмена на 25 секунд

### Сохранение QR-кода:
1. Выделите нужную запись в списке
2. Нажмите **ПКМ → Сохранить QR…**
3. Выберите место для сохранения PNG файла

## Примечания:
- Приложение создаёт незашифрованное хранилище (без пароля)
- Если у вас есть старое зашифрованное хранилище, создайте новое через меню
- Для работы GUI требуется установленный tkinter (обычно идёт с Python)
