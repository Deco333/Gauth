"""Хранилище секретов (vault) в виде простого JSON-файла.

Формат файла (JSON):
{
  "app": "gauth-pc", "v": 1,
  "entries": [{secret, name, issuer, algo, digits, period, kind, counter,
               steam, note, source, created, updated}]
}

Файл создаётся с правами 0600 (на Windows — наследование ACL пользователя).
Секреты никогда не пишутся в логи и не передаются в сеть: всё считается локально.

ПРИМЕЧАНИЕ: Шифрование отключено для удобства использования.
Файл хранится в открытом виде, но с ограниченным доступом (0600).
"""

from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import asdict
from pathlib import Path

from .migration import Entry

APP_NAME = "gauth-pc"
SCHEMA_VERSION = 1


class VaultError(Exception):
    pass


# --------------------------------------------------------------------------
# расположение файла
# --------------------------------------------------------------------------
def default_vault_path() -> Path:
    env = os.environ.get("GAUTH_VAULT")
    if env:
        return Path(env).expanduser()
    if sys.platform.startswith("win"):
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
    elif sys.platform == "darwin":
        base = str(Path.home() / "Library" / "Application Support")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / APP_NAME / "vault.json"


def _chmod_private(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


# --------------------------------------------------------------------------
# сериализация
# --------------------------------------------------------------------------
def _serialize(entries: list[Entry]) -> dict:
    now = time.time()
    out = []
    for e in entries:
        d = asdict(e)
        d.setdefault("created", now)
        d["updated"] = now
        out.append(d)
    return {"entries": out, "schema": SCHEMA_VERSION}


def _deserialize(body: dict) -> list[Entry]:
    entries = []
    for raw in body.get("entries", []):
        known = {f for f in Entry.__dataclass_fields__}  # type: ignore[attr-defined]
        meta = {k: v for k, v in raw.items() if k not in known and k not in
                ("created", "updated", "meta")}
        kwargs = {k: v for k, v in raw.items() if k in known}
        merged_meta = dict(raw.get("meta") or {})
        merged_meta.update(meta)
        for drop in ("created", "updated"):
            merged_meta.pop(drop, None)
        if "created" in raw:
            merged_meta["created"] = raw["created"]
        if "updated" in raw:
            merged_meta["updated"] = raw["updated"]
        kwargs["meta"] = merged_meta
        entries.append(Entry(**kwargs))
    return entries


class Vault:
    def __init__(self, path: Path | str | None = None, *,
                 entries: list[Entry] | None = None):
        self.path = Path(path) if path else default_vault_path()
        self.entries: list[Entry] = entries or []
        self.dirty = False

    # ---- состояние -------------------------------------------------------
    @property
    def locked(self) -> bool:
        return False  # хранилище всегда разблокировано

    def exists(self) -> bool:
        return self.path.is_file()

    # ---- открытие --------------------------------------------------------
    @classmethod
    def open(cls, path: Path | str | None = None, **kwargs) -> "Vault":
        """Открывает хранилище. Параметры password/prompt/use_cache игнорируются."""
        p = Path(path) if path else default_vault_path()
        if not p.is_file():
            raise VaultError(
                f"Хранилище не найдено: {p}\nСоздайте его командой: gauth init"
            )
        data = json.loads(p.read_text(encoding="utf-8"))
        v = cls(p, entries=_deserialize(data))
        return v

    # ---- сохранение ------------------------------------------------------
    def save(self, **kwargs) -> None:
        """Сохраняет хранилище. Параметр remember игнорируется."""
        data = json.dumps(_serialize(self.entries), ensure_ascii=False, indent=2)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(data, encoding="utf-8")
        _chmod_private(tmp)
        os.replace(tmp, self.path)
        _chmod_private(self.path)
        self.dirty = False

    # ---- операции с записями --------------------------------------------
    def add(self, e: Entry, *, replace: bool = False) -> Entry:
        idx = self.find_index(e.name, e.issuer)
        if idx is not None:
            if not replace:
                raise VaultError(
                    f"Запись уже существует: {e.issuer + ': ' if e.issuer else ''}{e.name}\n"
                    "Используйте --force, чтобы перезаписать."
                )
            keep = self.entries[idx].meta.get("created", time.time())
            e.meta["created"] = keep
            self.entries[idx] = e
        else:
            e.meta.setdefault("created", time.time())
            self.entries.append(e)
        self.dirty = True
        return e

    def add_many(self, items: list[Entry], *, replace: bool = False) -> tuple[int, int]:
        added = skipped = 0
        for e in items:
            try:
                self.add(e, replace=replace)
                added += 1
            except VaultError:
                skipped += 1
        return added, skipped

    def remove(self, index: int) -> Entry:
        e = self.entries.pop(index)
        self.dirty = True
        return e

    def find_index(self, name: str, issuer: str = "") -> int | None:
        for i, e in enumerate(self.entries):
            if e.name == name and (not issuer or e.issuer == issuer):
                return i
        return None

    # ---- поиск -----------------------------------------------------------
    def search(self, query: str = "") -> list[Entry]:
        q = (query or "").strip().lower()
        if not q:
            return sorted(self.entries, key=lambda e: ((e.issuer or "zzz").lower(),
                                                       e.name.lower()))
        terms = [t for t in q.split() if t]
        scored: list[tuple[float, int, Entry]] = []
        for i, e in enumerate(self.entries):
            name = (e.name or "").lower()
            issuer = (e.issuer or "").lower()
            note = (e.note or "").lower()
            full = f"{issuer} {name}".strip()
            score = 0.0
            for t in terms:
                if t == name or t == full:
                    score += 100
                elif t == issuer:
                    score += 80
                elif name.startswith(t) or issuer.startswith(t):
                    score += 50
                elif t in name:
                    score += 30
                elif t in issuer:
                    score += 25
                elif t in note:
                    score += 10
                elif _fuzzy(t, full):
                    score += 5
                else:
                    score = -1
                    break
            if score > 0:
                scored.append((-score, i, e))
        scored.sort()
        return [e for _, _, e in scored]

    # ---- смена пароля ----------------------------------------------------
    def rekey(self, new_password: str, *, kdf: dict | None = None) -> None:
        """Метод устарел: шифрование отключено."""
        pass  # ничего не делаем


def _fuzzy(needle: str, hay: str) -> bool:
    """Простая проверка «буквы по порядку» (ggl -> google)."""
    it = iter(hay)
    return all(any(ch == c for c in it) for ch in needle)
