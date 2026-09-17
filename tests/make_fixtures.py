"""Генерация фикстур для тестов распознавания QR.

Создаёт:
  tests/fixtures/ga_export_*.png        «чистые» QR экспорта Google Authenticator
  tests/fixtures/phone_screenshot.png   QR внутри интерфейса приложения
  tests/fixtures/phone_photo_*.jpg      реалистичные ФОТО экрана (скриншот
                                        экрана экспорта Android блокирует,
                                        поэтому QR обычно фотографируют)
  tests/fixtures/phone_rotated_90.png   фото в другой ориентации

Запуск: python3 tests/make_fixtures.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from make_fake_ga_export import DEMO, migration_uri  # noqa: E402

OUT = Path(__file__).resolve().parent / "fixtures"


def phone_screenshot(uri: str) -> "object":
    """Имитация экрана «Перенос аккаунтов» с QR по центру."""
    from PIL import Image, ImageDraw

    import pyqrcode

    q = pyqrcode.create(uri, error="M")
    mods = [[bool(v) for v in row] for row in q.code]
    n = len(mods)
    scale, border = 7, 4
    qr_px = (n + 2 * border) * scale

    W, H = 540, 900
    img = Image.new("RGB", (W, H), (255, 255, 255))
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, 96], fill=(24, 90, 219))
    d.text((24, 40), "Google Authenticator", fill=(255, 255, 255))
    d.text((24, 120), "Перенос аккаунтов", fill=(30, 30, 30))
    d.text((24, 150), "Отсканируйте QR-коды на новом устройстве", fill=(110, 110, 110))
    x0, y0 = (W - qr_px) // 2, 200
    for y in range(n + 2 * border):
        for x in range(n + 2 * border):
            my, mx = y - border, x - border
            if 0 <= my < n and 0 <= mx < n and mods[my][mx]:
                d.rectangle([x0 + x * scale, y0 + y * scale,
                             x0 + (x + 1) * scale - 1, y0 + (y + 1) * scale - 1],
                            fill=(0, 0, 0))
    d.text((24, y0 + qr_px + 24), "1/1  •  2 аккаунта", fill=(110, 110, 110))
    return img


def photo_like(img, *, contrast=0.55, grain=26, blur=0.6, angle=0.0):
    """Реалистичное фото экрана: приглушённый контраст, мыло, зерно, наклон."""
    from PIL import Image, ImageChops, ImageEnhance, ImageFilter, ImageOps

    im = ImageEnhance.Contrast(img).enhance(contrast)
    im = ImageEnhance.Brightness(im).enhance(1.08)
    if blur:
        im = im.filter(ImageFilter.GaussianBlur(blur))
    if angle:
        im = im.rotate(angle, expand=True, fillcolor=(200, 200, 200))
    g = ImageOps.grayscale(im)
    noise = Image.effect_noise(im.size, grain).convert("L")
    noise = noise.filter(ImageFilter.GaussianBlur(0.4))
    return ImageChops.blend(g, noise, 0.22).convert("RGB")


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    uri2 = migration_uri(DEMO[:2], batch_size=1, batch_index=0, batch_id=555)

    shot = phone_screenshot(uri2)
    shot.save(OUT / "phone_screenshot.png")

    photo_like(shot, contrast=0.55, grain=26).save(OUT / "phone_photo_typical.jpg",
                                                   quality=62)
    photo_like(shot, contrast=0.32, grain=44, blur=1.0).save(
        OUT / "phone_photo_harsh.jpg", quality=48)
    photo_like(shot, contrast=0.5, grain=24, angle=2.5).save(
        OUT / "phone_photo_tilted.jpg", quality=60)
    shot.rotate(90, expand=True).save(OUT / "phone_rotated_90.png")

    for f in sorted(OUT.iterdir()):
        print(f"  {f.relative_to(OUT.parent.parent)}  ({f.stat().st_size} байт)")

    # быстрая самопроверка
    from gauth import migration, qr as qrmod

    for name in ("phone_screenshot.png", "phone_photo_typical.jpg",
                 "phone_photo_harsh.jpg", "phone_photo_tilted.jpg",
                 "phone_rotated_90.png"):
        try:
            texts = qrmod.decode_image(str(OUT / name))
            n = len(migration.from_migration_uri(texts[0]).entries)
            print(f"  ✔ {name}: распознано, записей {n}")
        except Exception as exc:  # noqa: BLE001
            print(f"  ⚠ {name}: {type(exc).__name__} (нет бэкенда QR?)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
