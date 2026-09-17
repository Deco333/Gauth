"""Копирование в буфер обмена и (опционально) автоочистка через N секунд.

Бэкенды по платформам:
  Windows — clip / pyperclip / PowerShell
  macOS   — pbcopy
  Linux   — wl-copy (Wayland) → xclip → xsel → pyperclip
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import threading
import time


class ClipboardError(Exception):
    pass


def _run(cmd: list[str], data: str) -> bool:
    try:
        p = subprocess.run(cmd, input=data.encode("utf-8"),
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           check=False, timeout=8)
        return p.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def copy(text: str) -> str:
    """Копирует текст. Возвращает имя использованного бэкенда."""
    if sys.platform.startswith("win"):
        if shutil.which("clip"):
            # clip.exe добавляет \r\n и ломает UTF-8 -> предпочитаем PowerShell
            if _run(["powershell", "-NoProfile", "-Command",
                     "Set-Clipboard -Value ([Console]::In.ReadToEnd())"], text):
                return "powershell"
            if _run(["clip"], text):
                return "clip"
        try:
            import pyperclip  # type: ignore

            pyperclip.copy(text)
            return "pyperclip"
        except Exception:
            pass
        raise ClipboardError("Не удалось скопировать в буфер обмена (Windows).")

    if sys.platform == "darwin":
        if _run(["pbcopy"], text):
            return "pbcopy"
        raise ClipboardError("pbcopy не сработал.")

    for cmd in (["wl-copy"], ["xclip", "-selection", "clipboard"],
                ["xsel", "--clipboard", "--input"]):
        if shutil.which(cmd[0]) and _run(cmd, text):
            return cmd[0]
    try:
        import pyperclip  # type: ignore

        pyperclip.copy(text)
        return "pyperclip"
    except Exception:
        pass
    raise ClipboardError(
        "Не найден инструмент буфера обмена. Установите один из:\n"
        "  Linux (X11):   sudo apt install xclip\n"
        "  Linux (Wayland): sudo apt install wl-clipboard\n"
        "  Кроссплатформенно: pip install pyperclip"
    )


def copy_and_wipe(text: str, ttl: int = 25) -> str:
    """Копирует и стирает буфер через ttl секунд (в отдельном потоке)."""
    backend = copy(text)
    if ttl > 0:
        def _wipe():
            time.sleep(ttl)
            try:
                cur = read()
            except Exception:
                cur = None
            if cur == text:          # не затираем то, что скопировал пользователь
                try:
                    copy("")
                except Exception:
                    pass

        t = threading.Thread(target=_wipe, daemon=True)
        t.start()
    return backend


def read() -> str | None:
    try:
        if sys.platform.startswith("win"):
            p = subprocess.run(["powershell", "-NoProfile", "-Command", "Get-Clipboard"],
                               capture_output=True, text=True, timeout=8, check=False)
            return p.stdout.strip("\r\n") if p.returncode == 0 else None
        if sys.platform == "darwin":
            p = subprocess.run(["pbpaste"], capture_output=True, text=True, timeout=8,
                               check=False)
            return p.stdout if p.returncode == 0 else None
        for cmd in (["wl-paste", "--no-newline"], ["xclip", "-selection", "clipboard", "-o"],
                    ["xsel", "--clipboard", "--output"]):
            if shutil.which(cmd[0]):
                p = subprocess.run(cmd, capture_output=True, text=True, timeout=8,
                                   check=False)
                if p.returncode == 0:
                    return p.stdout
    except Exception:
        return None
    return None
