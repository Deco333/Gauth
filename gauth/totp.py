"""Генерация кодов TOTP/HOTP. Чистый stdlib — без внешних зависимостей."""

from __future__ import annotations

import hashlib
import hmac
import math
import struct
import time
from dataclasses import dataclass

from . import base32x

ALGOS = {
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
    "MD5": hashlib.md5,
}

# Алфавит Steam Guard (5 символов, база 26)
STEAM_ALPHABET = "23456789BCDFGHJKMNPQRTVWXY"


@dataclass
class Code:
    value: str
    counter: int
    period: int
    remaining: float  # секунд до смены кода

    @property
    def expires_at(self) -> float:
        return time.time() + self.remaining


def hotp(key: bytes, counter: int, digits: int = 6, algorithm: str = "SHA1") -> str:
    algo = ALGOS.get(algorithm.upper(), hashlib.sha1)
    digest = hmac.new(key, struct.pack(">Q", counter), algo).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{truncated % (10**digits):0{digits}d}"


def steam_code(key: bytes, counter: int) -> str:
    """Steam Guard: 5 символов из собственного алфавита."""
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    out = []
    for _ in range(5):
        value, rem = divmod(value, len(STEAM_ALPHABET))
        out.append(STEAM_ALPHABET[rem])
    return "".join(out)


def entry_code(entry, *, when: float | None = None, drift: int = 0) -> Code:
    """Универсальная точка входа: учитывает kind/period/digits/algo/counter/steam.

    Для TOTP код зависит от времени, для HOTP — от сохранённого счётчика
    (drift для HOTP сдвигает счётчик).
    """
    if getattr(entry, "kind", "totp") == "hotp":
        counter = int(getattr(entry, "counter", 0) or 0) + int(drift)
        key = base32x.to_bytes(entry.secret)
        digits = int(getattr(entry, "digits", 6) or 6)
        algo = getattr(entry, "algorithm", None) or getattr(entry, "algo", "SHA1")
        value = steam_code(key, counter) if getattr(entry, "steam", False) \
            else hotp(key, counter, digits, algo)
        return Code(value=value, counter=counter, period=int(getattr(entry, "period", 30) or 30),
                    remaining=float("inf"))
    return totp(entry.secret, when=when,
                period=int(getattr(entry, "period", 30) or 30),
                digits=int(getattr(entry, "digits", 6) or 6),
                algorithm=getattr(entry, "algorithm", None) or getattr(entry, "algo", "SHA1"),
                steam=bool(getattr(entry, "steam", False)), drift=drift)


def totp(
    secret: str | bytes,
    *,
    when: float | None = None,
    period: int = 30,
    digits: int = 6,
    algorithm: str = "SHA1",
    drift: int = 0,
    steam: bool = False,
) -> Code:
    """Текущий код TOTP. drift — сдвиг периода (±1 и т.п.) при расхождении часов."""
    now = time.time() if when is None else when
    period = max(1, int(period))
    counter = int(now // period) + int(drift)
    key = base32x.to_bytes(secret)

    if steam:
        value = steam_code(key, counter)
    else:
        value = hotp(key, counter, digits, algorithm)

    elapsed = now - counter * period
    remaining = period - elapsed
    if remaining <= 0:
        remaining += period
    return Code(value=value, counter=counter, period=period, remaining=remaining)


def upcoming(
    secret: str | bytes, *, period: int = 30, digits: int = 6, algorithm: str = "SHA1",
    steam: bool = False, when: float | None = None,
) -> str:
    """Следующий код (полезно, когда текущий вот-вот протухнет)."""
    return totp(
        secret, when=when, period=period, digits=digits,
        algorithm=algorithm, drift=1, steam=steam,
    ).value


def verify(
    secret: str | bytes, code: str, *, period: int = 30, digits: int = 6,
    algorithm: str = "SHA1", window: int = 1, steam: bool = False,
) -> bool:
    """Проверка кода с окном допусков (для отладки/скриптов)."""
    code = code.strip()
    for d in range(-window, window + 1):
        c = totp(secret, period=period, digits=digits, algorithm=algorithm,
                 drift=d, steam=steam)
        if hmac.compare_digest(c.value, code):
            return True
    return False


def seconds_left(period: int = 30) -> float:
    return period - (time.time() % period)


def drift_estimate(secret: str | bytes, code: str, *, period: int = 30,
                   digits: int = 6, algorithm: str = "SHA1",
                   window: int = 20) -> int | None:
    """Ищет сдвиг периодов, при котором код совпадает (диагностика часов)."""
    for d in range(-window, window + 1):
        c = totp(secret, period=period, digits=digits, algorithm=algorithm, drift=d)
        if hmac.compare_digest(c.value, code.strip()):
            return d
    return None


def random_secret(length: int = 20) -> str:
    """Случайный секрет (160 бит по умолчанию) — для ручной настройки 2FA."""
    import base64
    import secrets as _s
    return base64.b32encode(_s.token_bytes(length)).decode().rstrip("=")


def progress(remaining: float, period: int) -> float:
    """Доля истёкшего периода 0..1."""
    return 1.0 - max(0.0, min(period, remaining)) / float(period)


def humanize(seconds: float) -> str:
    s = int(math.ceil(seconds))
    return f"{s:02d}"
