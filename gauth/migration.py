"""Разбор otpauth-migration:// — формата экспорта Google Authenticator.

Это protobuf-сообщение `MigrationPayload`, закодированное в query-параметр
`data=` (base64). Прото-файл Google не публикует, поэтому парсер написан
вручную — без зависимости от protobuf-библиотек.

Схема (reverse-engineered, stable с 2020 г.):

message MigrationPayload {
  message PayloadEntry {
    bytes  secret   = 1;   // «сырой» ключ (НЕ base32!)
    string name     = 2;   // "Issuer:account@mail" или "account@mail"
    string issuer  = 3;
    enum Algorithm { ALGORITHM_UNSPECIFIED=0; SHA1=1; SHA256=2; SHA512=3; MD5=4; }
    enum DigitCount { DIGIT_COUNT_UNSPECIFIED=0; SIX=1; EIGHT=2; }
    enum OtpType { OTP_TYPE_UNSPECIFIED=0; HOTP=1; TOTP=2; }
    Algorithm algorithm = 4;
    DigitCount digits   = 5;
    OtpType type        = 6;
    int64 counter       = 7;
  }
  repeated PayloadEntry otp_parameters = 1;
  int32 version          = 2;
  int32 batch_size       = 3;
  int32 batch_index      = 4;
  int32 batch_id         = 5;
}
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from urllib.parse import parse_qs, unquote, urlparse

ALGO_BY_NUM = {0: "SHA1", 1: "SHA1", 2: "SHA256", 3: "SHA512", 4: "MD5"}
DIGITS_BY_NUM = {0: 6, 1: 6, 2: 8}
TYPE_BY_NUM = {0: "totp", 1: "hotp", 2: "totp"}


class MigrationError(Exception):
    """Не удалось разобрать otpauth-migration://."""


@dataclass
class Entry:
    name: str
    issuer: str = ""
    secret: str = ""            # base32 без '='
    algo: str = "SHA1"
    digits: int = 6
    period: int = 30
    kind: str = "totp"          # totp | hotp
    counter: int = 0
    steam: bool = False
    note: str = ""
    source: str = ""            # откуда импорт: ga-qr, manual, aegis...
    meta: dict = field(default_factory=dict)


# --------------------------------------------------------------------------
# низкоуровневый protobuf reader
# --------------------------------------------------------------------------
def _read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise MigrationError("Оборванное varint-поле")
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift > 70:
            raise MigrationError("Слишком длинное varint-поле")


def _iter_fields(buf: bytes):
    """Генератор (field_number, wire_type, value)."""
    pos = 0
    n = len(buf)
    while pos < n:
        tag, pos = _read_varint(buf, pos)
        fnum, wtype = tag >> 3, tag & 0x07
        if wtype == 0:                                    # varint
            val, pos = _read_varint(buf, pos)
        elif wtype == 2:                                  # length-delimited
            ln, pos = _read_varint(buf, pos)
            if pos + ln > n:
                raise MigrationError("Длина поля больше размера сообщения")
            val = buf[pos : pos + ln]
            pos += ln
        elif wtype == 5:                                  # 32-bit
            val = buf[pos : pos + 4]
            pos += 4
        elif wtype == 1:                                  # 64-bit
            val = buf[pos : pos + 8]
            pos += 8
        else:
            raise MigrationError(f"Неизвестный wire type {wtype}")
        yield fnum, wtype, val


def _parse_entry(buf: bytes) -> Entry:
    e = Entry(name="", source="ga-qr")
    for fnum, wtype, val in _iter_fields(buf):
        if fnum == 1 and wtype == 2:                      # secret (raw bytes)
            e.secret = base64.b32encode(val).decode().rstrip("=")
        elif fnum == 2 and wtype == 2:                    # name
            e.name = val.decode("utf-8", "replace")
        elif fnum == 3 and wtype == 2:                    # issuer
            e.issuer = val.decode("utf-8", "replace")
        elif fnum == 4 and wtype == 0:
            e.algo = ALGO_BY_NUM.get(val, "SHA1")
        elif fnum == 5 and wtype == 0:
            e.digits = DIGITS_BY_NUM.get(val, 6)
        elif fnum == 6 and wtype == 0:
            e.kind = TYPE_BY_NUM.get(val, "totp")
        elif fnum == 7 and wtype == 0:
            e.counter = val
    return e


@dataclass
class MigrationPayload:
    entries: list[Entry] = field(default_factory=list)
    version: int = 0
    batch_size: int = 1
    batch_index: int = 0
    batch_id: int = 0


def parse_payload(data: bytes) -> MigrationPayload:
    out = MigrationPayload()
    for fnum, wtype, val in _iter_fields(data):
        if fnum == 1 and wtype == 2:
            out.entries.append(_parse_entry(val))
        elif fnum == 2 and wtype == 0:
            out.version = val
        elif fnum == 3 and wtype == 0:
            out.batch_size = val
        elif fnum == 4 and wtype == 0:
            out.batch_index = val
        elif fnum == 5 and wtype == 0:
            out.batch_id = val
    return out


def split_name(name: str, issuer: str) -> tuple[str, str]:
    """'Google:ivan@gmail.com' -> issuer='Google', name='ivan@gmail.com'.
    issuer из payload имеет приоритет."""
    name = (name or "").strip()
    if issuer and issuer.strip():
        issuer = issuer.strip()
        prefix = issuer + ":"
        if name.startswith(prefix):
            name = name[len(prefix) :].strip()
        return name, issuer
    if ":" in name:
        head, _, tail = name.partition(":")
        head, tail = head.strip(), tail.strip()
        # не режем, если слева похожий на домен/порт кусок без смысла
        if head and tail and " " not in head and len(head) <= 40:
            return tail, head
    return name, ""


def from_migration_uri(uri: str) -> MigrationPayload:
    """otpauth-migration://offline?data=...&batch_size=..."""
    uri = uri.strip().strip('"').strip("'")
    parsed = urlparse(uri)
    if parsed.scheme.lower() not in ("otpauth-migration", "otpauth"):
        raise MigrationError(
            "Это не otpauth-migration:// ссылка. Проверьте, что отсканировали "
            "QR из «Перенос аккаунтов» в Google Authenticator."
        )
    if parsed.scheme.lower() == "otpauth":
        # одиночная otpauth:// ссылка — тоже поддержим
        e = from_otpauth_uri(uri)
        return MigrationPayload(entries=[e])

    qs = parse_qs(parsed.query)
    raw = qs.get("data") or qs.get("payload")
    if not raw:
        raise MigrationError("В ссылке нет параметра data=")
    b64 = raw[0].replace(" ", "+").replace("-", "+").replace("_", "/")
    b64 += "=" * ((4 - len(b64) % 4) % 4)
    try:
        blob = base64.b64decode(b64, validate=False)
    except (binascii.Error, ValueError) as exc:
        raise MigrationError(f"Не удалось декодировать base64: {exc}") from exc

    payload = parse_payload(blob)
    if not payload.entries:
        raise MigrationError("В экспорте 0 записей.")
    for q in ("batch_size", "batch_index", "batch_id", "version"):
        if q in qs and qs[q][0].lstrip("-").isdigit():
            setattr(payload, q, int(qs[q][0]))
    return payload


def from_otpauth_uri(uri: str) -> Entry:
    """Обычная otpauth://totp/Issuer:account?secret=...&period=30..."""
    uri = uri.strip().strip('"').strip("'")
    p = urlparse(uri)
    if p.scheme.lower() != "otpauth":
        raise MigrationError("Ожидалась ссылка otpauth://")
    # netloc может содержать тип (otpauth://totp/...) либо он в начале path
    head = (p.netloc or "").strip("/")
    rest = p.path.strip("/")
    if head.lower() in ("totp", "hotp"):
        kind, label = head.lower(), unquote(rest)
    else:
        first, _, tail = rest.partition("/")
        if first.lower() not in ("totp", "hotp"):
            raise MigrationError(f"Неподдерживаемый тип: {first or '(пусто)'}")
        kind, label = first.lower(), unquote(tail)
    qs = {k.lower(): v[0] for k, v in parse_qs(p.query, keep_blank_values=True).items()}

    e = Entry(name=label, kind=kind, source="otpauth-uri")
    e.secret = (qs.get("secret") or "").strip()
    if not e.secret:
        raise MigrationError("В otpauth:// ссылке нет secret=")
    e.algo = (qs.get("algorithm") or "SHA1").upper()
    e.digits = int(qs.get("digits") or 6)
    e.period = int(qs.get("period") or 30)
    e.counter = int(qs.get("counter") or 0)
    e.issuer = unquote(qs.get("issuer") or "")
    e.name, e.issuer = split_name(unquote(label), e.issuer)
    e.steam = bool(qs.get("steam")) or e.issuer.lower() == "steam"
    return e


def parse_any(text: str) -> list[Entry]:
    """Принимает otpauth-migration://, otpauth:// или голый base64 payload."""
    text = text.strip()
    if not text:
        raise MigrationError("Пустой ввод")
    if text.lower().startswith(("otpauth-migration", "otpauth")):
        return from_migration_uri(text).entries
    # возможно, просто base64 от protobuf
    b64 = text.replace(" ", "+").replace("-", "+").replace("_", "/")
    b64 += "=" * ((4 - len(b64) % 4) % 4)
    try:
        blob = base64.b64decode(b64, validate=False)
        payload = parse_payload(blob)
        if payload.entries:
            return payload.entries
    except (binascii.Error, ValueError, MigrationError):
        pass
    raise MigrationError(
        "Не распознано. Вставьте otpauth-migration:// ссылку из QR-кода "
        "Google Authenticator или otpauth:// ссылку."
    )
