"""Распознавание QR-кодов из файла изображения (скриншот или фото экрана).

Порядок попыток (первый доступный бэкенд выигрывает):
  1. zxing-cpp — pip install zxing-cpp pillow   (рекомендуемый)
  2. OpenCV    — pip install opencv-python
  3. pyzbar    — pip install pyzbar pillow      (Linux: нужен libzbar0)

Поскольку экран экспорта Google Authenticator запрещает скриншоты (FLAG_SECURE),
QR обычно приходится фотографировать вторым устройством или вебкой. Такие снимки
шумные, заваленные и в невысоком разрешении, поэтому перед распознаванием
применяется набор препроцессоров (масштаб, ч/б, порог, повороты).

Если ничего не помогло — отсканируйте QR на телефоне сторонним сканером и
вставьте текст ссылки: import ga --text 'otpauth-migration://…'
"""

from __future__ import annotations

import os


class NoQRBackend(Exception):
    pass


# --------------------------------------------------------------------------
# препроцессинг: помогает на фото экрана (шум, перспектива, низкое разрешение)
# --------------------------------------------------------------------------
def _otsu(gray):
    """Порог Отсу (без numpy) — отделяет QR от фона при неравномерной засветке."""
    hist = gray.histogram()
    total = sum(hist)
    if not total:
        return 128
    sum_all = sum(i * h for i, h in enumerate(hist))
    sum_b = 0
    w_b = 0
    best, best_t = 0.0, 128
    for t, h in enumerate(hist):
        w_b += h
        if w_b == 0:
            continue
        w_f = total - w_b
        if w_f == 0:
            break
        sum_b += t * h
        m_b = sum_b / w_b
        m_f = (sum_all - sum_b) / w_f
        var = w_b * w_f * (m_b - m_f) ** 2
        if var > best:
            best, best_t = var, t
    return best_t


def _binarize(gray, thr: int | None = None):
    t = _otsu(gray) if thr is None else thr
    return gray.point(lambda p, t=t: 255 if p > t else 0, "L")


def _pil_variants(img):
    """Генератор вариантов изображения для повторных попыток распознавания."""
    from PIL import Image, ImageFilter, ImageOps  # type: ignore

    yield img
    gray = ImageOps.grayscale(img)
    yield gray

    # медианный фильтр убирает «зерно» с фото экрана — часто решающий шаг
    try:
        med = gray.filter(ImageFilter.MedianFilter(3))
    except Exception:
        med = gray
    yield med
    try:
        yield ImageOps.autocontrast(med).filter(ImageFilter.SHARPEN)
    except Exception:
        pass

    # бинаризация: Отсу + фиксированные пороги (засветка/тени)
    binaries = [_binarize(med)]
    for thr in (100, 128, 160, 190):
        binaries.append(_binarize(med, thr))
    for b in binaries:
        yield b

    # увеличение: мелкие/далёкие QR часто не читаются в исходном размере
    for scale in (2.0, 3.0, 1.5, 4.0):
        w, h = gray.size
        if w * scale > 9000:
            continue
        big_med = med.resize((int(w * scale), int(h * scale)), Image.LANCZOS)
        yield big_med
        yield _binarize(big_med)
        yield ImageOps.autocontrast(big_med)

    # повороты на 90° (фото могли снять в другой ориентации)
    for angle in (90, 180, 270):
        yield med.rotate(angle, expand=True)
        yield _binarize(med).rotate(angle, expand=True)


def _cv_variants(img):
    """То же для OpenCV (numpy)."""
    import cv2  # type: ignore

    yield img
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY) if img.ndim == 3 else img
    yield gray
    for scale in (2.0, 3.0, 1.5):
        yield cv2.resize(gray, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)
    yield cv2.medianBlur(gray, 3)                               # зерно с фото
    blurred = cv2.GaussianBlur(gray, (3, 3), 0)
    yield cv2.addWeighted(gray, 1.6, blurred, -0.6, 0)          # unsharp
    _, thr = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    yield thr
    yield cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                                cv2.THRESH_BINARY, 51, 5)
    for angle in (90, 180, 270):
        h, w = gray.shape[:2]
        m = cv2.getRotationMatrix2D((w / 2, h / 2), angle, 1.0)
        yield cv2.warpAffine(gray, m, (h, w) if angle in (90, 270) else (w, h))


# --------------------------------------------------------------------------
# бэкенды
# --------------------------------------------------------------------------
def _try_zxing(path: str) -> list[str]:
    import zxingcpp  # type: ignore
    from PIL import Image  # type: ignore

    img = Image.open(path)
    img.load()
    try:
        img = img.convert("RGB")
    except Exception:
        pass

    def scan(im):
        try:
            return [r.text for r in zxingcpp.read_barcodes(im) if getattr(r, "text", None)]
        except Exception:
            return []

    found = scan(img)
    if found:
        return found
    for variant in _pil_variants(img):
        found = scan(variant)
        if found:
            return found
    return []


def _try_opencv(path: str) -> list[str]:
    import cv2  # type: ignore

    img = cv2.imread(path)
    if img is None:
        raise NoQRBackend(f"OpenCV не смог открыть {path}")
    det = cv2.QRCodeDetector()

    def scan(im):
        out: list[str] = []
        try:
            ok, texts, _, _ = det.detectAndDecodeMulti(im)
            if ok and texts:
                out.extend(t for t in texts if t)
        except cv2.error:
            pass
        if not out:
            try:
                text, _, _ = det.detectAndDecode(im)
                if text:
                    out.append(text)
            except cv2.error:
                pass
        return out

    found = scan(img)
    if found:
        return found
    for variant in _cv_variants(img):
        found = scan(variant)
        if found:
            return found
    return []


def _try_pyzbar(path: str) -> list[str]:
    from PIL import Image  # type: ignore
    from pyzbar.pyzbar import decode  # type: ignore

    img = Image.open(path)
    img.load()

    def scan(im):
        try:
            return [r.data.decode("utf-8", "replace") for r in decode(im) if r.data]
        except Exception:
            return []

    found = scan(img)
    if found:
        return found
    for variant in _pil_variants(img):
        found = scan(variant)
        if found:
            return found
    return []


_BACKENDS = (_try_zxing, _try_opencv, _try_pyzbar)

HINTS = """Что делать:
  • Установите бэкенд распознавания (любой один):
        pip install zxing-cpp pillow
        pip install opencv-python
        pip install pyzbar pillow        # Linux: sudo apt install libzbar0
  • Переснимите QR: экран экспорта Google Authenticator запрещает скриншоты,
    поэтому фотографируйте экран вторым телефоном/вебкой — ровно, при хорошем
    свете, чтобы QR занимал почти весь кадр, без бликов.
  • Если QR несколько («1 из 3», «2 из 3»…), снимите каждый и передайте разом:
        gauth import ga --qr 1.jpg 2.jpg 3.jpg
  • Обходной путь без фото: отсканируйте QR любым сторонним сканером на
    телефоне (он покажет текст ссылки otpauth-migration://…) и вставьте:
        gauth import ga --text 'otpauth-migration://offline?data=…'
  • Совсем без QR: зайдите в настройки 2FA каждого сервиса, выберите
    «Другой способ»/«Ввести ключ вручную» и добавьте секрет:
        gauth add --name mail --issuer Google --secret XXXX
"""


def decode_image(path: str) -> list[str]:
    """Возвращает список строк из всех QR-кодов, найденных на картинке."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"Файл не найден: {path}")

    errors = []
    for backend in _BACKENDS:
        try:
            found = backend(path)
        except ImportError as exc:
            errors.append(f"{backend.__name__}: нет модуля ({exc})")
            continue
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{backend.__name__}: {exc}")
            continue
        if found:
            return found
    raise NoQRBackend(
        "QR-коды на картинке не найдены.\n" + HINTS +
        ("\nДиагностика бэкендов: " + "; ".join(errors) if errors else "")
    )


def decode_images(paths: list[str]) -> list[str]:
    out: list[str] = []
    for p in paths:
        out.extend(decode_image(p))
    return out
