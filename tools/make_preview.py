#!/usr/bin/env python3
"""Рисует docs/gui-preview.svg — макет окна GUI с НАСТОЯЩИМИ кодами,
посчитанными на момент запуска (демонстрационные секреты из тестов)."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gauth import totp as T
from gauth.migration import Entry
from gauth.tui import split_code

ROWS = [
    ("Amazon AWS", "admin@corp.example", "MFRGGZDFMZTWQ2LK", "SHA256", 8, 30, "totp"),
    ("GitHub", "octocat", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "SHA1", 6, 30, "totp"),
    ("GitLab", "devops", "MFRGGZDFMZTWQ2LKMN2HE2LO", "SHA1", 6, 30, "totp"),
    ("Google", "ivan.petrov@gmail.com", "JBSWY3DPEHPK3PXP", "SHA1", 6, 30, "totp"),
    ("Steam", "player_one", "JBSWY3DPEHPK3PXP", "SHA1", 6, 30, "totp"),
    ("VK", "user@mail.ru", "ORSXG5BAOVQWK4TBNRWS6", "SHA1", 6, 30, "totp"),
    ("Cloudflare", "extra@mail.com", "MFRGGZDFMZTWQ2LK", "SHA256", 8, 60, "totp"),
    ("YubiKey", "yubikey-1", "JBSWY3DPEHPK3PXP", "SHA1", 6, 30, "hotp"),
]
SELECTED = 3

W, H = 820, 676
BG, CARD, ROW = "#16181d", "#1e2128", "#1a1d23"
FG, DIM = "#e6e8ec", "#9aa3af"
GREEN, YEL, RED, ACC = "#3ddc84", "#ffc94d", "#ff6b6b", "#4f9dff"
MONO = "Consolas, Menlo, monospace"


def color_for(rem, per):
    if rem is None:
        return ACC
    return GREEN if rem > per * 0.66 else YEL if rem > 5 else RED


def main() -> int:
    # сдвигаем «момент снимка» так, чтобы строки получились разного цвета
    # (иначе все коды обновляются синхронно и превью выглядит плоским)
    now = time.time()
    offsets = [41, 19, 8, 27, 52, 3, 0]
    data = []
    for issuer, name, secret, algo, digits, period, kind in ROWS:
        e = Entry(name=name, issuer=issuer, secret=secret, algo=algo,
                  digits=digits, period=period, kind=kind, counter=42)
        off = offsets[len(data)] if kind != "hotp" else 0
        c = T.entry_code(e, when=now + off)
        rem = None if c.remaining == float("inf") else c.remaining
        data.append((f"{issuer}: {name}", split_code(c.value), rem, period, c.counter))

    o = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
         f'viewBox="0 0 {W} {H}" font-family="Segoe UI, Helvetica, Arial, sans-serif">',
         f'<rect width="{W}" height="{H}" fill="{BG}"/>',
         f'<rect width="{W}" height="34" fill="#101216"/>',
         f'<text x="16" y="22" font-size="13" fill="{DIM}">gauth-pc — коды 2FA</text>']
    for i, c in enumerate(["#3b4048", "#3b4048", "#c0483f"]):
        o.append(f'<rect x="{W - 88 + i * 28}" y="11" width="12" height="12" rx="2" fill="{c}"/>')

    y = 52
    o.append(f'<text x="16" y="{y + 16}" font-size="13" fill="{DIM}">Поиск</text>')
    o.append(f'<rect x="70" y="{y}" width="190" height="30" rx="4" fill="{CARD}"/>')
    o.append(f'<text x="82" y="{y + 20}" font-size="13" fill="#5d6672">|</text>')
    bx = 276
    for t, w in (("📷  Импорт QR…", 124), ("➕  Добавить…", 112),
                 ("📋  Копировать", 118), ("⏱  Сверить с телефоном", 184)):
        o.append(f'<rect x="{bx}" y="{y}" width="{w}" height="30" rx="4" fill="{CARD}"/>')
        o.append(f'<text x="{bx + 12}" y="{y + 20}" font-size="12.5" fill="{FG}">{t}</text>')
        bx += w + 8

    ty = y + 46
    o.append(f'<rect x="10" y="{ty}" width="{W - 20}" height="26" fill="{CARD}"/>')
    o.append(f'<text x="26" y="{ty + 18}" font-size="11.5" fill="{DIM}">АККАУНТ</text>')
    o.append(f'<text x="400" y="{ty + 18}" font-size="11.5" fill="{DIM}">КОД</text>')
    o.append(f'<text x="{W - 40}" y="{ty + 18}" font-size="11.5" fill="{DIM}" '
             f'text-anchor="end">ОБНОВЛЕНИЕ</text>')
    ty += 26
    rh = 34
    for i, (label, code, rem, per, counter) in enumerate(data):
        fill = "#22304a" if i == SELECTED else (ROW if i % 2 == 0 else "#20242b")
        o.append(f'<rect x="10" y="{ty}" width="{W - 20}" height="{rh}" fill="{fill}"/>')
        o.append(f'<text x="26" y="{ty + 22}" font-size="13.5" fill="{FG}">{label}</text>')
        col = color_for(rem, per)
        o.append(f'<text x="400" y="{ty + 22}" font-size="15" font-family="{MONO}" '
                 f'font-weight="bold" fill="{col}">{code}</text>')
        if rem is None:
            o.append(f'<text x="{W - 40}" y="{ty + 22}" font-size="12" fill="{DIM}" '
                     f'text-anchor="end">счётчик {counter}</text>')
        else:
            bw, frac = 90, max(0.0, min(1.0, 1 - rem / per))
            x0 = W - 40 - bw - 42
            o.append(f'<rect x="{x0}" y="{ty + 13}" width="{bw}" height="7" rx="3" fill="#0f1115"/>')
            o.append(f'<rect x="{x0}" y="{ty + 13}" width="{int(bw * frac)}" height="7" '
                     f'rx="3" fill="{col}"/>')
            o.append(f'<text x="{W - 40}" y="{ty + 22}" font-size="12" fill="{DIM}" '
                     f'text-anchor="end">{int(rem):02d}с</text>')
        ty += rh

    cy = ty + 12
    o.append(f'<rect x="10" y="{cy}" width="{W - 20}" height="150" rx="6" fill="{CARD}"/>')
    label, code, rem, per, _ = data[SELECTED]
    col = color_for(rem, per)
    o.append(f'<text x="28" y="{cy + 30}" font-size="14" fill="{DIM}">{label}</text>')
    o.append(f'<text x="24" y="{cy + 104}" font-size="60" font-family="{MONO}" '
             f'font-weight="bold" fill="{col}">{code}</text>')
    frac = 0.0 if rem is None else max(0.0, min(1.0, 1 - rem / per))
    o.append(f'<rect x="28" y="{cy + 126}" width="{W - 76}" height="6" rx="3" fill="#0f1115"/>')
    o.append(f'<rect x="28" y="{cy + 126}" width="{int((W - 76) * frac)}" height="6" '
             f'rx="3" fill="{col}"/>')

    sy = cy + 166
    o.append(f'<text x="16" y="{sy + 14}" font-size="12" fill="{DIM}">'
             f'{len(data)} записей   •   Ctrl+C — копировать код, Ctrl+F — поиск, '
             f'Del — удалить</text>')
    o.append(f'<text x="{W - 16}" y="{sy + 14}" font-size="11" fill="#5c6470" '
             f'text-anchor="end">%APPDATA%\\gauth-pc\\vault.enc.json</text>')
    o.append('</svg>')

    out = Path(__file__).resolve().parent.parent / "docs" / "gui-preview.svg"
    out.parent.mkdir(exist_ok=True)
    out.write_text("\n".join(o), encoding="utf-8")
    print(f"сохранено: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
