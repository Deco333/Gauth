"""Генератор тестового «скриншота» экспорта Google Authenticator.

Делает то же, что показывает телефон: QR-коды otpauth-migration://
(при >10 аккаунтах — несколько QR подряд, batch_index/batch_size).

Использование:
    python3 tests/make_fake_ga_export.py out_dir/
Потом:
    gauth import ga --qr out_dir/qr_*.png
"""

from __future__ import annotations

import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gauth import base32x
from gauth.migration import Entry

# то же, что в test_gauth.py — дублируем минимально, чтобы скрипт был автономным
def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _f(fnum, wtype, payload):
    return _varint((fnum << 3) | wtype) + payload


def _ld(fnum, data):
    return _f(fnum, 2, _varint(len(data)) + data)


ALGO = {"SHA1": 1, "SHA256": 2, "SHA512": 3, "MD5": 4}
DIG = {6: 1, 8: 2}
TYP = {"hotp": 1, "totp": 2}


def enc_entry(e: Entry) -> bytes:
    out = _ld(1, base32x.to_bytes(e.secret))
    out += _ld(2, e.name.encode())
    out += _ld(3, e.issuer.encode())
    out += _f(4, 0, _varint(ALGO[e.algo.upper()]))
    out += _f(5, 0, _varint(DIG[e.digits]))
    out += _f(6, 0, _varint(TYP[e.kind]))
    if e.kind == "hotp":
        out += _f(7, 0, _varint(e.counter))
    return out


def migration_uri(entries: list[Entry], *, batch_size=1, batch_index=0,
                  batch_id=1234, version=1) -> str:
    blob = b""
    for e in entries:
        blob += _ld(1, enc_entry(e))
    blob += _f(2, 0, _varint(version))
    blob += _f(3, 0, _varint(batch_size))
    blob += _f(4, 0, _varint(batch_index))
    blob += _f(5, 0, _varint(batch_id))
    data = base64.b64encode(blob).decode()
    return (f"otpauth-migration://offline?data={data}&batch_size={batch_size}"
            f"&batch_index={batch_index}&batch_id={batch_id}&version={version}")


DEMO = [
    Entry(name="Google:ivan.petrov@gmail.com", issuer="", secret="JBSWY3DPEHPK3PXP"),
    Entry(name="GitHub:octocat", issuer="GitHub", secret="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
    Entry(name="admin@corp.example", issuer="Amazon AWS", secret="MFRGGZDFMZTWQ2LK",
          algo="SHA256", digits=8, period=60),
    Entry(name="user@mail.ru", issuer="VK", secret="MFRGGZDFMZTWQ2LKMN2HE2LO"),
    Entry(name="devops", issuer="GitLab", secret="ORSXG5BAOVQWK4TBNRWS6==="),
    Entry(name="yubikey-1", issuer="YubiKey", secret="JBSWY3DPEHPK3PXP",
          kind="hotp", counter=42),
    Entry(name="player_one", issuer="Steam", secret="JBSWY3DPEHPK3PXP"),
]


def make_png(uri: str, path: Path, *, scale: int = 6) -> Path:
    import png  # pypng

    import pyqrcode

    qr = pyqrcode.create(uri, error="M")
    modules = [[bool(v) for v in row] for row in qr.code]
    border = 4
    n = len(modules) + 2 * border
    rows = []
    for y in range(n):
        row = []
        for x in range(n):
            my, mx = y - border, x - border
            dark = 0 <= my < len(modules) and 0 <= mx < len(modules[0]) and modules[my][mx]
            row.extend([0] * scale if dark else [255] * scale)
        rows.extend([row] * scale)
    with open(path, "wb") as fh:
        png.Writer(width=n * scale, height=n * scale, greyscale=True).write(fh, rows)
    return path


def main(out_dir: str = "tests/fixtures", per_qr: int = 4) -> int:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    batches = [DEMO[i : i + per_qr] for i in range(0, len(DEMO), per_qr)]
    paths = []
    for i, batch in enumerate(batches):
        uri = migration_uri(batch, batch_size=len(batches), batch_index=i,
                            batch_id=987654)
        p = make_png(uri, out / f"ga_export_{i + 1}of{len(batches)}.png")
        paths.append(p)
        print(f"{p}  ({len(batch)} аккаунтов, batch {i + 1}/{len(batches)})")
    (out / "ga_export_uris.txt").write_text(
        "\n".join(migration_uri([e]) for e in DEMO) + "\n", encoding="utf-8")
    print(f"\nГотово: {len(paths)} QR в {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(*sys.argv[1:]))
