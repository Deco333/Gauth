"""Устойчивое декодирование base32-секретов (Google Authenticator часто отдаёт
секрет без padding, в нижнем регистре, с пробелами и дефисами)."""

from __future__ import annotations

import base64
import binascii

_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def clean_secret(raw: str | bytes) -> str:
    """Приводит секрет к каноническому виду: A-Z2-7, длина кратна 8 (с '=')."""
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError:  # уже бинарный ключ -> hex
            return base64.b32encode(raw).decode().rstrip("=")

    s = "".join(ch for ch in raw.strip().upper() if ch in _ALPHABET)
    if not s:
        raise ValueError(f"Секрет пустой или не base32: {raw!r}")
    s += "=" * ((8 - len(s) % 8) % 8)
    return s


def to_bytes(raw: str | bytes) -> bytes:
    """Секрет (base32/hex/строка) -> байты ключа HMAC.

    ВАЖНО: base32 проверяется ПЕРВЫМ. Строка вида "JBSWY3DPEHPK3PXP" состоит
    из символов, которые одновременно являются валидным hex — если бы hex шёл
    первым, мы получили бы другой ключ и неверные коды.
    """
    if isinstance(raw, bytes):
        return raw
    s = raw.strip()
    if not s:
        raise ValueError("Пустой секрет")

    # 1) base32 — основной формат для TOTP
    upper = s.upper().replace(" ", "").replace("-", "")
    if all(ch in _ALPHABET + "=" for ch in upper) and len(upper.rstrip("=")) >= 8:
        try:
            return base64.b32decode(clean_secret(s), casefold=True)
        except (binascii.Error, ValueError):
            pass

    # 2) hex — иногда сервисы отдают ключ в hex
    if len(s) >= 16 and len(s) % 2 == 0:
        try:
            return binascii.unhexlify(s)
        except (binascii.Error, ValueError):
            pass

    # 3) «сырая» строка-пароль (не рекомендуется, но поддерживается)
    return s.encode("utf-8")


def normalize(raw: str | bytes) -> str:
    """Канонический base32 без '=' — так храним в vault."""
    if isinstance(raw, bytes):
        return base64.b32encode(raw).decode().rstrip("=")
    return clean_secret(raw).rstrip("=")
