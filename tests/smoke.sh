#!/usr/bin/env bash
# Сквозной смоук-тест CLI (без интерактива): экспорт GA -> импорт -> коды -> экспорт.
set -euo pipefail
cd "$(dirname "$0")/.."

export GAUTH_VAULT="$(mktemp -d)/vault.enc.json"
export GAUTH_PASSWORD="test-password-123"
export NO_COLOR=1
G="python3 gauth.py"

hr() { printf '\n\033[1m=== %s ===\033[0m\n' "$1"; }

hr "0. doctor (до создания vault)"
$G doctor || true

hr "1. init (пароль дважды в stdin — в CI нет терминала)"
printf '%s\n%s\n' "$GAUTH_PASSWORD" "$GAUTH_PASSWORD" | $G init --force

hr "2. import ga из двух QR (batch 1/2 + 2/2) — dry-run"
$G import ga --qr tests/fixtures/ga_export_1of2.png tests/fixtures/ga_export_2of2.png --dry-run

hr "3. import ga — реально"
$G import ga --qr tests/fixtures/ga_export_*.png

hr "3b. повторный импорт (дубликаты должны быть пропущены)"
$G import ga --qr tests/fixtures/ga_export_1of2.png

hr "3c. import из ФОТО экрана (скриншот экспорта Android блокирует)"
$G import ga --qr tests/fixtures/phone_photo_typical.jpg
$G import ga --qr tests/fixtures/phone_photo_harsh.jpg
$G import ga --qr tests/fixtures/phone_rotated_90.png

hr "4. list"
$G list

hr "5. codes --once"
$G codes --once

hr "6. get (поиск по 'github'), --bare"
$G get github --bare --force-first

hr "7. get --wait 3 (ждёт свежий код)"
time $G get aws --bare --force-first --wait 3

hr "8. copy (в буфер; в контейнере может не быть xclip — проверим graceful fail)"
$G copy vk --force-first || echo "(буфер обмена недоступен — ожидаемо в sandbox)"

hr "9. add вручную (Steam-формат + обычный)"
$G add --name "player_two" --issuer "Steam" --secret "JBSWY3DPEHPK3PXP" --steam
$G add --name "extra@mail.com" --issuer "Cloudflare" --secret "ORSXG5BAOVQWK4TBNRWS6" --digits 8 --period 60
# секрет скрытым вводом из stdin (без --secret)
printf 'JBSWY3DPEHPK3PXP\n' | $G add --name "hidden@mail.com" --issuer "Test"

hr "10. list --json"
$G list --json | head -25

hr "11. codes --once (проверка 8-значного и Steam)"
$G codes --once

hr "12. edit (заметка)"
$G edit cloudflare --note "рабочий аккаунт" -y
$G list | grep -i cloudflare

hr "13. qr --url и qr в терминале"
$G qr github --force-first --url
$G qr vk --force-first | head -8

hr "14. export --format uris / aegis / json"
$G export --format uris --no-secrets | head -3
$G export --format aegis | python3 -c "import json,sys; d=json.load(sys.stdin); print('aegis entries:', len(d['db']['entries']))"
$G export --out /tmp/gauth-export.json
head -c 200 /tmp/gauth-export.json; echo

hr "15. passwd (смена пароля: старый из env-файла, новый — из пайпа)"
printf 'brand-new-pass-456\nbrand-new-pass-456\n' > /tmp/newpw.txt
echo "$GAUTH_PASSWORD" > /tmp/oldpw.txt
GAUTH_PASSWORD_FILE=/tmp/oldpw.txt $G passwd < /tmp/newpw.txt
GAUTH_PASSWORD=brand-new-pass-456 $G info
export GAUTH_PASSWORD=brand-new-pass-456
rm -f /tmp/oldpw.txt /tmp/newpw.txt

hr "15b. HOTP --bump (счётчик растёт и сохраняется)"
$G get yubikey --bare --force-first
$G get yubikey --bare --force-first --bump
$G list | grep -i yubikey

hr "16. rm"
$G rm yubikey -y
$G list

hr "17. неверный пароль"
GAUTH_PASSWORD="wrong-one" $G codes --once || echo "(ожидаемо: отказано)"

hr "18. doctor (после)"
GAUTH_PASSWORD="brand-new-pass-456" $G doctor

rm -f /tmp/gauth-export.json
hr "СМОУК-ТЕСТ ПРОЙДЕН"
