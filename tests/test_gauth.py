"""Тесты gauth-pc.

Проверяется:
  • TOTP/HOTP по официальным векторам RFC 4226 / RFC 6238
  • Steam Guard код
  • кодирование/декодирование protobuf Google Authenticator (otpauth-migration://)
  • многосоставной экспорт (batch_size > 1)
  • парсинг otpauth:// ссылок
  • шифрование vault: сохранение/чтение, неверный пароль, rekey
  • поиск записей

Запуск:  python3 -m pytest -q   или   python3 tests/test_gauth.py
"""

from __future__ import annotations

import base64
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gauth import base32x, migration, totp as T
from gauth.migration import Entry
from gauth.vault import Vault, WrongPassword

# ---------------------------------------------------------------- RFC 6238
# В RFC 6238 для каждого алгоритма свой seed:
#   SHA1   -> 20 байт "12345678901234567890"
#   SHA256 -> 32 байта, SHA512 -> 64 байта (тот же префикс, повторённый)
def _rfc_secret(nbytes: int) -> str:
    seed = (b"12345678901234567890" * 4)[:nbytes]
    return base64.b32encode(seed).decode().rstrip("=")


RFC_SECRET = _rfc_secret(20)          # SHA1
RFC_VECTORS = [  # (time, digits, algo, expected)
    (59, 8, "SHA1", "94287082"),
    (59, 8, "SHA256", "46119246"),
    (59, 8, "SHA512", "90693936"),
    (1111111109, 8, "SHA1", "07081804"),
    (1111111111, 8, "SHA1", "14050471"),
    (1234567890, 8, "SHA1", "89005924"),
    (2000000000, 8, "SHA1", "69279037"),
    (20000000000, 8, "SHA1", "65353130"),
    (1111111109, 8, "SHA256", "68084774"),
    (1111111109, 8, "SHA512", "25091201"),
    (1111111111, 8, "SHA256", "67062674"),
    (1111111111, 8, "SHA512", "99943326"),
    (1234567890, 8, "SHA256", "91819424"),
    (1234567890, 8, "SHA512", "93441116"),
    (2000000000, 8, "SHA256", "90698825"),
    (2000000000, 8, "SHA512", "38618901"),
    (20000000000, 8, "SHA256", "77737706"),
    (20000000000, 8, "SHA512", "47863826"),
    (59, 6, "SHA1", "287082"),
]

RFC_SECRET_BY_ALGO = {"SHA1": _rfc_secret(20), "SHA256": _rfc_secret(32),
                      "SHA512": _rfc_secret(64)}


def test_rfc6238_vectors():
    for when, digits, algo, expected in RFC_VECTORS:
        secret = RFC_SECRET_BY_ALGO[algo]
        got = T.totp(secret, when=when, digits=digits, algorithm=algo,
                     period=30).value
        assert got == expected, f"T={when} {algo}/{digits}: {got} != {expected}"


def test_rfc6238_upcoming_matches_next_vector():
    """upcoming() = код следующего 30-секундного окна."""
    # T=59  -> counter 1 -> 94287082   (RFC 6238 Table 1)
    # T=60..89 -> counter 2 -> 37359152 (следующий вектор HOTP из RFC 4226)
    assert T.totp(RFC_SECRET, when=59, digits=8).value == "94287082"
    assert T.upcoming(RFC_SECRET, when=59, digits=8) == "37359152"
    assert T.totp(RFC_SECRET, when=60, digits=8).value == "37359152"
    assert T.totp(RFC_SECRET, when=89, digits=8).value == "37359152"
    assert T.totp(RFC_SECRET, when=90, digits=8).value == "26969429"  # HOTP count=3


def test_rfc4226_hotp():
    """RFC 4226 Appendix D — первые 10 HOTP-кодов для ASCII-секрета
    '12345678901234567890'."""
    expected = ["755224", "287082", "359152", "969429", "338314",
                "254676", "287922", "162583", "399871", "520489"]
    key = b"12345678901234567890"
    for counter, want in enumerate(expected):
        got = T.hotp(key, counter)
        assert got == want, f"counter={counter}: {got} != {want}"
    # и то же через base32-представление секрета
    b32 = base64.b32encode(key).decode().rstrip("=")
    assert T.hotp(base32x.to_bytes(b32), 0) == "755224"
    # промежуточные HMAC-SHA1 из Table 1 RFC 4226
    import hashlib, hmac as _h, struct as _s
    dg = _h.new(key, _s.pack(">Q", 1), hashlib.sha1).hexdigest()
    assert dg == "75a48a19d4cbe100644e8ac1397eea747a2d33ab"


def test_remaining_and_counter():
    c = T.totp(RFC_SECRET, when=1000, period=30)
    assert c.counter == 33 and 0 < c.remaining <= 30
    c2 = T.totp(RFC_SECRET, when=1000, period=60)
    assert c2.counter == 16


def test_entry_code_hotp_uses_counter():
    """HOTP: код должен зависеть от счётчика, а не от времени."""
    e = Entry(name="yubikey", issuer="YK", secret=RFC_SECRET, kind="hotp", counter=1)
    c1 = T.entry_code(e)
    assert c1.value == "287082"          # RFC 4226, count=1
    assert c1.remaining == float("inf")  # не истекает по времени
    e.counter = 2
    assert T.entry_code(e).value == "359152"
    assert T.entry_code(e, drift=1).value == "969429"   # count=3
    # время не влияет на HOTP
    e.counter = 0
    assert T.entry_code(e, when=59).value == T.entry_code(e, when=9999999).value == "755224"


def test_entry_code_totp_respects_params():
    e = Entry(name="a", issuer="X", secret=RFC_SECRET_BY_ALGO["SHA256"],
              algo="SHA256", digits=8, period=30)
    assert T.entry_code(e, when=59).value == "46119246"
    e.period = 60
    assert T.entry_code(e, when=59).value == T.totp(RFC_SECRET_BY_ALGO["SHA256"],
                                                    when=59, digits=8,
                                                    algorithm="SHA256", period=60).value


def test_steam_code_format():
    code = T.steam_code(base32x.to_bytes(RFC_SECRET), 0)
    assert len(code) == 5 and all(ch in T.STEAM_ALPHABET for ch in code)
    c = T.totp(RFC_SECRET, when=0, steam=True)
    assert len(c.value) == 5


def test_verify_and_drift():
    now = time.time()
    code = T.totp(RFC_SECRET, when=now).value
    assert T.verify(RFC_SECRET, code)
    assert not T.verify(RFC_SECRET, "000000") or code == "000000"
    assert T.drift_estimate(RFC_SECRET, code) == 0


def test_base32_tolerant():
    raw = "JBSWY3DPEHPK3PXP"
    for variant in (raw, raw.lower(), f"{raw[:4]} {raw[4:8]} {raw[8:]}",
                    raw + "===="):
        assert base32x.to_bytes(variant) == base32x.to_bytes(raw)
    assert base32x.normalize("jbswy3dpehpk3pxp") == raw


# ------------------------------------------------- protobuf-энкодер для теста
def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _field(fnum: int, wtype: int, payload: bytes) -> bytes:
    return _varint((fnum << 3) | wtype) + payload


def _len_delimited(fnum: int, data: bytes) -> bytes:
    return _field(fnum, 2, _varint(len(data)) + data)


ALGO_NUM = {"SHA1": 1, "SHA256": 2, "SHA512": 3, "MD5": 4}
DIGITS_NUM = {6: 1, 8: 2}
TYPE_NUM = {"hotp": 1, "totp": 2}


def encode_entry(e: Entry) -> bytes:
    out = b""
    out += _len_delimited(1, base32x.to_bytes(e.secret))
    out += _len_delimited(2, e.name.encode())
    out += _len_delimited(3, e.issuer.encode())
    out += _field(4, 0, _varint(ALGO_NUM[e.algo.upper()]))
    out += _field(5, 0, _varint(DIGITS_NUM[e.digits]))
    out += _field(6, 0, _varint(TYPE_NUM[e.kind]))
    if e.kind == "hotp":
        out += _field(7, 0, _varint(e.counter))
    return out


def encode_payload(entries: list[Entry], *, version=1, batch_size=1,
                   batch_index=0, batch_id=0) -> bytes:
    out = b""
    for e in entries:
        out += _len_delimited(1, encode_entry(e))
    out += _field(2, 0, _varint(version))
    out += _field(3, 0, _varint(batch_size))
    out += _field(4, 0, _varint(batch_index))
    out += _field(5, 0, _varint(batch_id))
    return out


def make_migration_uri(entries: list[Entry], **kw) -> str:
    blob = base64.b64encode(encode_payload(entries, **kw)).decode()
    return (f"otpauth-migration://offline?data={blob}"
            f"&batch_size={kw.get('batch_size', 1)}"
            f"&batch_index={kw.get('batch_index', 0)}"
            f"&batch_id={kw.get('batch_id', 0)}")


SAMPLE = [
    Entry(name="Google:ivan.petrov@gmail.com", issuer="", secret="JBSWY3DPEHPK3PXP",
          algo="SHA1", digits=6, period=30, kind="totp"),
    Entry(name="GitHub:octocat", issuer="GitHub", secret="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
          algo="SHA1", digits=6, period=30, kind="totp"),
    Entry(name="aws-admin@corp.example", issuer="Amazon", secret="MFRGGZDFMZTWQ2LK",
          algo="SHA256", digits=8, period=60, kind="totp"),
    Entry(name="yubikey-1", issuer="YubiKey", secret="JBSWY3DPEHPK3PXP",
          algo="SHA1", digits=6, kind="hotp", counter=42),
]


def test_migration_roundtrip():
    uri = make_migration_uri(SAMPLE)
    payload = migration.from_migration_uri(uri)
    assert len(payload.entries) == len(SAMPLE)
    got = payload.entries[0]
    assert got.name == "Google:ivan.petrov@gmail.com"
    assert base32x.normalize(got.secret) == "JBSWY3DPEHPK3PXP"
    sha = payload.entries[2]
    assert sha.algo == "SHA256" and sha.digits == 8
    hot = payload.entries[3]
    assert hot.kind == "hotp" and hot.counter == 42


def test_split_name():
    assert migration.split_name("Google:ivan@gmail.com", "") == ("ivan@gmail.com", "Google")
    assert migration.split_name("Google:ivan@gmail.com", "Google") == ("ivan@gmail.com", "Google")
    assert migration.split_name("ivan@gmail.com", "Google") == ("ivan@gmail.com", "Google")
    assert migration.split_name("no-issuer-here", "") == ("no-issuer-here", "")


def test_batched_export():
    """Google Authenticator при >10 аккаунтах показывает несколько QR подряд."""
    a = SAMPLE[:2]
    b = SAMPLE[2:]
    u1 = make_migration_uri(a, batch_size=2, batch_index=0, batch_id=777)
    u2 = make_migration_uri(b, batch_size=2, batch_index=1, batch_id=777)
    total = []
    for u in (u1, u2):
        p = migration.from_migration_uri(u)
        assert p.batch_id == 777
        total += p.entries
    assert len(total) == 4
    assert {e.name for e in total} == {e.name for e in SAMPLE}


def test_otpauth_uri_parsing():
    e = migration.from_otpauth_uri(
        "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
        "&algorithm=SHA1&digits=6&period=30")
    assert e.kind == "totp" and e.issuer == "GitHub" and e.name == "octocat"
    assert e.period == 30 and e.digits == 6
    e2 = migration.from_otpauth_uri("otpauth://hotp/YubiKey:y1?secret=JBSWY3DPEHPK3PXP&counter=7")
    assert e2.kind == "hotp" and e2.counter == 7
    # URL-encoding в label
    e3 = migration.from_otpauth_uri(
        "otpauth://totp/Acme%20Corp:user%40mail.com?secret=JBSWY3DPEHPK3PXP"
        "&issuer=Acme%20Corp")
    assert e3.issuer == "Acme Corp" and e3.name == "user@mail.com"


def test_bad_input_rejected():
    for junk in ("", "http://example.com", "otpauth-migration://offline",
                 "otpauth-migration://offline?data=!!!not-base64!!!"):
        try:
            migration.parse_any(junk)
        except migration.MigrationError:
            continue
        raise AssertionError(f"не отклонено: {junk!r}")


# ------------------------------------- распознавание QR с фото экрана
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _qr_backend_available() -> bool:
    for mod in (("zxingcpp", "PIL"), ("cv2",), ("pyzbar", "PIL")):
        try:
            for m in mod:
                __import__(m)
            return True
        except ImportError:
            continue
    return False


def test_qr_decode_from_phone_photos():
    """QR, снятые как фото экрана (скриншот экспорта Android блокирует)."""
    if not _qr_backend_available():
        print("  …пропущено: не установлен бэкенд чтения QR "
              "(pip install zxing-cpp pillow)")
        return
    from gauth import qr as qrmod

    for name in ("phone_screenshot.png", "phone_photo_typical.jpg",
                 "phone_photo_harsh.jpg", "phone_photo_tilted.jpg",
                 "phone_rotated_90.png"):
        path = FIXTURES / name
        if not path.exists():
            print(f"  …{name}: нет фикстуры (python3 tests/make_fixtures.py)")
            continue
        texts = qrmod.decode_image(str(path))
        assert texts, f"{name}: QR не найден"
        payload = migration.from_migration_uri(texts[0])
        assert len(payload.entries) == 2, name
        assert base32x.normalize(payload.entries[0].secret) == "JBSWY3DPEHPK3PXP"


def test_qr_decode_multi_batch_files():
    if not _qr_backend_available():
        return
    from gauth import qr as qrmod

    total = 0
    for name in sorted(FIXTURES.glob("ga_export_*.png")):
        for text in qrmod.decode_image(str(name)):
            total += len(migration.from_migration_uri(text).entries)
    if any(FIXTURES.glob("ga_export_*.png")):
        assert total == 7, f"ожидали 7 записей из двух частей, получили {total}"


# ------------------------------------------------------------------ vault
def test_vault_encrypt_roundtrip(tmp_path=None):
    tmp = Path(tmp_path or tempfile.mkdtemp())
    path = tmp / "vault.enc.json"
    v = Vault(path)
    v.rekey("correct horse battery staple")
    v.add(Entry(name="ivan@gmail.com", issuer="Google", secret="JBSWY3DPEHPK3PXP"))
    v.add(Entry(name="octocat", issuer="GitHub", secret="GEZDGNBVGY3TQOJQ"))
    v.save(remember=False)

    raw = path.read_text(encoding="utf-8")
    assert "JBSWY3DPEHPK3PXP" not in raw, "секрет попал в файл открытым текстом!"
    assert os.stat(path).st_mode & 0o077 == 0 or os.name == "nt"

    v2 = Vault.open(path, password="correct horse battery staple", prompt=False,
                    use_cache=False)
    assert len(v2.entries) == 2
    assert v2.entries[0].issuer == "Google"
    assert T.totp(v2.entries[0].secret).value == T.totp("JBSWY3DPEHPK3PXP").value

    try:
        Vault.open(path, password="wrong", prompt=False, use_cache=False)
    except WrongPassword:
        pass
    else:
        raise AssertionError("принял неверный пароль")

    # rekey
    v2.rekey("new-password-123")
    v2.save(remember=False)
    v3 = Vault.open(path, password="new-password-123", prompt=False, use_cache=False)
    assert len(v3.entries) == 2


def test_vault_duplicates_and_search():
    tmp = Path(tempfile.mkdtemp())
    v = Vault(tmp / "v.json")
    v.rekey("pw123456")
    v.add(Entry(name="ivan@gmail.com", issuer="Google", secret="JBSWY3DPEHPK3PXP"))
    v.add(Entry(name="work@gmail.com", issuer="Google", secret="GEZDGNBVGY3TQOJQ"))
    v.add(Entry(name="octocat", issuer="GitHub", secret="MFRGGZDFMZTWQ2LK"))
    try:
        v.add(Entry(name="ivan@gmail.com", issuer="Google", secret="AAAA"))
    except Exception:
        pass
    else:
        raise AssertionError("дубликат не отклонён")
    assert len(v.entries) == 3
    v.add(Entry(name="ivan@gmail.com", issuer="Google", secret="GEZDGNBVGY3TQOJQ"),
          replace=True)
    assert v.entries[0].secret == "GEZDGNBVGY3TQOJQ"

    assert [e.name for e in v.search("google")][0] in ("ivan@gmail.com", "work@gmail.com")
    assert len(v.search("google")) == 2
    assert v.search("octocat")[0].issuer == "GitHub"
    assert v.search("git")[0].issuer == "GitHub"      # префикс
    assert v.search("gb")[0].issuer == "GitHub"       # fuzzy
    assert v.search("нет-такого") == []
    assert len(v.search("")) == 3


def test_entry_meta_preserved():
    tmp = Path(tempfile.mkdtemp())
    p = tmp / "v.json"
    v = Vault(p)
    v.rekey("pw123456")
    v.add(Entry(name="a@b.c", issuer="X", secret="JBSWY3DPEHPK3PXP",
                note="рабочий", kind="hotp", counter=5))
    v.save(remember=False)
    v2 = Vault.open(p, password="pw123456", prompt=False, use_cache=False)
    e = v2.entries[0]
    assert e.note == "рабочий" and e.kind == "hotp" and e.counter == 5


def run_all():
    """Простой раннер без pytest."""
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  ✔ {name}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            import traceback
            print(f"  ✘ {name}: {exc}")
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} тестов пройдено")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(run_all())
