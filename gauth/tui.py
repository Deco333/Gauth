"""Отрисовка в терминале: живая таблица кодов с таймером и прогресс-баром."""

from __future__ import annotations

import os
import shutil
import sys
import time

from . import totp as t
from .migration import Entry

_RESET = "\033[0m"


def supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return sys.stdout.isatty()


def _c(code: str, s: str, color: bool) -> str:
    return f"\033[{code}m{s}{_RESET}" if color else s


def bold(s: str, color: bool) -> str:
    return _c("1", s, color)


def dim(s: str, color: bool) -> str:
    return _c("2", s, color)


def green(s: str, color: bool) -> str:
    return _c("32", s, color)


def yellow(s: str, color: bool) -> str:
    return _c("33", s, color)


def red(s: str, color: bool) -> str:
    return _c("31", s, color)


def cyan(s: str, color: bool) -> str:
    return _c("36", s, color)


def _bar(frac: float, width: int = 14) -> str:
    width = max(4, width)
    filled = int(round(frac * width))
    return "█" * filled + "░" * (width - filled)


def split_code(code: str) -> str:
    """123456 -> '123 456' (легче диктовать/вводить)."""
    if len(code) == 6:
        return f"{code[:3]} {code[3:]}"
    if len(code) == 8:
        return f"{code[:4]} {code[4:]}"
    return code


def visible_width(s: str) -> int:
    import re
    return len(re.sub(r"\033\[[0-9;]*m", "", s))


def pad(s: str, width: int) -> str:
    return s + " " * max(0, width - visible_width(s))


def code_cell(e: Entry, now: float | None = None) -> tuple[str, float, int]:
    """Возвращает (текст кода, секунд до смены, период). HOTP -> inf."""
    c = t.entry_code(e, when=now)
    return c.value, c.remaining, c.period


def render_table(entries: list[Entry], *, color: bool | None = None,
                 width: int | None = None, show_secret: bool = False,
                 countdown: bool = True) -> str:
    color = supports_color() if color is None else color
    term_w = width or shutil.get_terminal_size((100, 24)).columns
    now = time.time()

    rows = []
    for e in entries:
        val, rem, period = code_cell(e, now)
        disp = split_code(val)
        if color:
            if rem == float("inf"):
                disp_c = cyan(disp, True)
            elif rem > period * 0.5:
                disp_c = green(bold(disp, True), True)
            elif rem > 5:
                disp_c = yellow(bold(disp, True), True)
            else:
                disp_c = red(bold(disp, True), True)
        else:
            disp_c = disp
        rows.append((e, disp, disp_c, rem, period, val))

    w_name = max([visible_width(_label(e)) for e, *_ in rows] + [4])
    w_name = min(w_name, max(12, term_w - 34))
    w_code = max(max([visible_width(d) for _, d, *_ in rows] + [6]), 7)

    lines = []
    header = pad(bold(_label_head(), color), w_name) + "  " + pad(bold("КОД", color), w_code)
    if countdown:
        header += "  " + bold("ОБНОВЛЕНИЕ", color)
    lines.append(dim(header, color))
    lines.append(dim("─" * min(max(20, term_w - 1), max(20, visible_width(header))),
                   color))

    for e, disp, disp_c, rem, period, raw in rows:
        line = pad(_label(e), w_name) + "  " + pad(disp_c, w_code)
        if countdown:
            if rem == float("inf"):
                line += "  " + dim(f"счётчик {e.counter}", color)
            else:
                frac = 1.0 - rem / period if period else 0
                bar = _bar(frac)
                if color:
                    col = green(bar, True) if rem > period * 0.5 else (
                        yellow(bar, True) if rem > 5 else red(bar, True))
                else:
                    col = bar
                line += "  " + col + " " + dim(f"{int(rem):02d}с", color)
        if show_secret:
            line += "  " + dim(e.secret, color)
        lines.append(line)
    return "\n".join(lines)


def _label(e: Entry) -> str:
    if e.issuer:
        return f"{e.issuer}: {e.name}" if e.name else e.issuer
    return e.name or "(без имени)"


def _label_head() -> str:
    return "АККАУНТ"


def render_live(entries: list[Entry], *, interval: float = 0.5,
                on_quit_msg: str = "Ctrl+C — выход", show_secret: bool = False,
                width: int | None = None) -> None:
    """Живой режим: коды обновляются, экран перерисовывается на месте."""
    color = supports_color()
    first = True
    last_lines = 0
    try:
        while True:
            text = render_table(entries, color=color, width=width,
                                show_secret=show_secret)
            if not first:
                sys.stdout.write(f"\033[{last_lines}A\033[J")
            first = False
            block = text + "\n" + dim(on_quit_msg, color) + "\n"
            last_lines = block.count("\n")
            sys.stdout.write(block)
            sys.stdout.flush()
            time.sleep(interval)
    except KeyboardInterrupt:
        sys.stdout.write("\n")
        sys.stdout.flush()


def render_single_big(entry: Entry, *, color: bool | None = None) -> str:
    """Крупный вывод одного кода — удобно вставить в скрипт/показать коллеге."""
    color = supports_color() if color is None else color
    c = t.entry_code(entry)
    label = _label(entry)
    if entry.kind == "hotp":
        tail = dim(f"hotp, счётчик {entry.counter}", color)
    else:
        bar = _bar(1.0 - c.remaining / c.period, 20)
        tail = f"{bar} {int(c.remaining):02d}с"
        if color:
            tail = (green(bar, True) if c.remaining > c.period * .5 else
                    yellow(bar, True) if c.remaining > 5 else red(bar, True)) + \
                   dim(f" {int(c.remaining):02d}с", color)
    big = bold(split_code(c.value), color)
    return f"{dim(label, color)}\n{big}\n{tail}"
