"""Печать QR-кода прямо в терминал + генерация otpauth:// ссылок.

Используется, чтобы перенести запись с ПК обратно на телефон
(или на второй компьютер) без ручного ввода секрета.
"""

from __future__ import annotations

import shutil
from urllib.parse import quote

from .migration import Entry


def otpauth_uri(e: Entry) -> str:
    label = f"{e.issuer}:{e.name}" if e.issuer else e.name
    kind = e.kind if e.kind in ("totp", "hotp") else "totp"
    params = [f"secret={quote(e.secret, safe='')}",
              f"issuer={quote(e.issuer, safe='')}",
              f"algorithm={e.algo.upper()}",
              f"digits={e.digits}"]
    if kind == "totp":
        params.append(f"period={e.period}")
    else:
        params.append(f"counter={e.counter}")
    if e.steam:
        params.append("steam=1")
    return f"otpauth://{kind}/{quote(label, safe=':')}?{'&'.join(params)}"


def _modules(uri: str, *, border: int = 2):
    """Возвращает матрицу bool. Пытаемся использовать pyqrcode, иначе zxing/qrcode."""
    try:
        import pyqrcode  # type: ignore

        qr = pyqrcode.create(uri, error="M")
        # pyqrcode хранит матрицу 1/0 в атрибуте .code (без quiet zone)
        m = [[bool(v) for v in row] for row in qr.code]
        n = len(m)
        out = [[False] * (n + 2 * border) for _ in range(n + 2 * border)]
        for y in range(n):
            for x in range(n):
                out[y + border][x + border] = m[y][x]
        return out
    except ImportError:
        pass
    try:
        import qrcode  # type: ignore

        qr = qrcode.QRCode(border=border, box_size=1)
        qr.add_data(uri)
        qr.make(fit=True)
        return [[bool(v) for v in row] for row in qr.modules]
    except ImportError as exc:
        raise RuntimeError(
            "Для QR в терминале нужен пакет: pip install pyqrcode (или qrcode)."
        ) from exc


def render_terminal(uri: str, *, invert: bool = False) -> str:
    """Полублок-рендер: 2 ряда модулей на одну строку терминала."""
    m = _modules(uri)
    h, w = len(m), len(m[0])
    if w > shutil.get_terminal_size((100, 24)).columns - 2:
        # слишком широкий — печатаем по одному модулю на символ
        dark, light = ("██", "  ") if not invert else ("  ", "██")
        return "\n".join("".join(dark if cell else light for cell in row) for row in m)
    dark, light = ("▀", "▄") if not invert else ("▄", "▀")
    full_dark, full_light = ("█", " ") if not invert else (" ", "█")
    lines = []
    for y in range(0, h, 2):
        row = []
        for x in range(w):
            top = m[y][x]
            bot = m[y + 1][x] if y + 1 < h else False
            if top and bot:
                row.append(full_dark)
            elif top and not bot:
                row.append(dark)
            elif bot and not top:
                row.append(light)
            else:
                row.append(full_light)
        lines.append("".join(row))
    return "\n".join(lines)


def save_png(uri: str, path: str, *, scale: int = 8) -> str:
    try:
        import pyqrcode  # type: ignore

        pyqrcode.create(uri, error="M").png(path, scale=scale, quiet_zone=2)
        return path
    except ImportError:
        pass
    try:
        import qrcode  # type: ignore

        img = qrcode.make(uri)
        img.save(path)
        return path
    except ImportError as exc:
        raise RuntimeError("pip install pyqrcode pypng  (или qrcode pillow)") from exc
