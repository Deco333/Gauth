# Быстрая шпаргалка gauth-pc

## Установка (один раз)

```bash
# Windows (в PowerShell):
py -3 -m pip install -r requirements.txt

# Linux / macOS:
python3 -m pip install -r requirements.txt
```

Обязателен только `cryptography`. Для чтения фото с QR нужен один из:
`zxing-cpp` + `pillow` (рекомендуется), `opencv-python` или `pyzbar`.

Проверка: `python3 gauth.py doctor` (Windows: `run.cmd doctor`).

---

## Перенос кодов с телефона — 4 команды

```bash
# 1. создать зашифрованное хранилище (придумайте пароль!)
python3 gauth.py init

# 2. на телефоне: Google Authenticator → ⋮ → «Перенос аккаунтов»
#    → «Экспорт аккаунтов» → пройти проверку → СФОТОГРАФИРОВАТЬ QR
#    (скриншот на Android не делается — экран защищён)

# 3. закинуть фото на ПК и импортировать (можно несколько файлов сразу)
python3 gauth.py import ga --qr ~/Desktop/qr1.jpg ~/Desktop/qr2.jpg

# 4. смотреть коды
python3 gauth.py codes
```

Фото QR удалить сразу после импорта — это ключи от всех аккаунтов.

---

## Графическое окно (рекомендую для Windows)

Двойной клик по **`gauth-gui.cmd`** — или `python3 gauth.py gui`.

В окне: таблица кодов с обратным отсчётом, поиск, крупный код выбранного
аккаунта, кнопки «📷 Импорт QR…», «📋 Копировать», «⏱ Сверить с телефоном».
Горячие клавиши: `Ctrl+C` — копировать, `Ctrl+F` — поиск, `Del` — удалить.

При первом запуске окно само предложит создать хранилище и задать пароль.

Если окно не открывается — в Python нет tkinter: установщик Python с
python.org → *Modify* → отметить **tcl/tk and IDLE**. Терминальный режим
(`run.cmd codes`) при этом работает.

---

## Повседневное использование

| Задача | Команда |
|---|---|
| Окно с кодами (GUI) | `gauth-gui.cmd` / `gauth gui` |
| Все коды в терминале, обновляются сами | `gauth codes` |
| Только нужные | `gauth codes google` |
| Один код крупно | `gauth get github` |
| Только цифры (вставить/в скрипт) | `gauth get github --bare` |
| Скопировать в буфер | `gauth copy github` |
| Список аккаунтов с номерами | `gauth list` |
| Код не принимается — найти причину | `gauth check google` |
| Окно кодов поверх всех окон (Windows) | `powershell -ExecutionPolicy Bypass -File .\run-live-codes.ps1` |

В скриптах:

```bash
CODE=$(gauth get github --bare)
curl -H "X-2FA-Code: $CODE" https://example.com/login
```

---

## Если что-то не так

| Симптом | Что делать |
|---|---|
| GUI не открывается | Нет tkinter: установщик Python → Modify → «tcl/tk and IDLE». Или работайте в терминале |
| «QR-коды на картинке не найдены» | `pip install zxing-cpp pillow`, переснять QR крупнее и резче |
| Скриншот экспорта чёрный | Это защита Android. Фотографируйте экран другим устройством/вебкой |
| Код не совпадает с телефоном | `gauth check google` — покажет расхождение часов в секундах |
| Забыл пароль хранилища | Восстановить нельзя. `gauth init --force` и повторный импорт с телефона |
| QR несколько («1 из 3») | Снять все и передать разом; программа скажет, если части не хватает |
| Сервис требует 8 цифр / 60 секунд | `gauth edit имя --digits 8 --period 60` |
| Steam (5 символов) | `gauth add --name X --issuer Steam --secret KEY --steam` |

---

## Где что лежит

| | |
|---|---|
| Хранилище (Windows) | `%APPDATA%\gauth-pc\vault.enc.json` |
| Хранилище (macOS) | `~/Library/Application Support/gauth-pc/vault.enc.json` |
| Хранилище (Linux) | `~/.config/gauth-pc/vault.enc.json` |
| Шифрование | пароль → scrypt(n=2¹⁵) → Fernet (AES-128-CBC + HMAC) |
| Сеть | не используется вообще, коды считаются локально (RFC 6238) |

Чтобы не вводить пароль каждый раз: `pip install keyring`
или `GAUTH_PASSWORD_FILE=~/.gauth-pass` (файл с паролем, `chmod 600`).

---

## Безопасность — коротко

* Скриншот/фото QR экспорта = доступ ко всем вашим аккаунтам. **Удалите после импорта.**
* Не кладите `vault.enc.json` и `gauth export` в облако, репозиторий, мессенджер.
* Держите включённым шифрование диска (BitLocker / FileVault / LUKS).
* Храните резервные коды 2FA от важных сервисов — это единственный способ
  войти, если потеряете и телефон, и компьютер.
* `gauth copy` сам стирает буфер обмена через 25 секунд.
