"""Зашифрованное хранилище секретов (vault) на базе Fernet + scrypt.

Формат файла (JSON):
{
  "app": "gauth-pc", "v": 1,
  "kdf": {"name": "scrypt", "n": 32768, "r": 8, "p": 1, "salt": "<b64>", "dklen": 32},
  "key_id": "<b64 sha256(master_key)[:8]>",
  "token": "<fernet token с JSON-телом>"
}

Тело (внутри шифра):
{"entries": [{secret, name, issuer, algo, digits, period, kind, counter,
              steam, note, source, created, updated}], "history": []}

Файл создаётся с правами 0600 (на Windows — наследование ACL пользователя).
Секреты никогда не пишутся в логи и не передаются в сеть: всё считается локально.
"""

from __future__ import annotations

import base64
import getpass
import hashlib
import json
import os
import sys
import time
from dataclasses import asdict
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .migration import Entry

APP_NAME = "gauth-pc"
SCHEMA_VERSION = 1
DEFAULT_KDF = {"name": "scrypt", "n": 2**15, "r": 8, "p": 1, "dklen": 32}


class VaultError(Exception):
    pass


class WrongPassword(VaultError):
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
    return Path(base) / APP_NAME / "vault.enc.json"


def _chmod_private(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


# --------------------------------------------------------------------------
# кэш ключа (чтобы не вводить пароль каждые 30 секунд)
# --------------------------------------------------------------------------
class KeyCache:
    """Пробует системный keyring; если его нет — держит ключ только в памяти
    текущего процесса (тогда пароль спрашивается при каждом запуске)."""

    SERVICE = APP_NAME

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self._kr = None
        if enabled:
            try:
                import keyring  # type: ignore

                self._kr = keyring
            except Exception:
                self._kr = None

    def put(self, key_id: str, key: bytes) -> bool:
        if not self._kr:
            return False
        try:
            self._kr.set_password(self.SERVICE, key_id, key.decode())
            return True
        except Exception:
            return False

    def get(self, key_id: str) -> bytes | None:
        if not self._kr:
            return None
        try:
            val = self._kr.get_password(self.SERVICE, key_id)
            return val.encode() if val else None
        except Exception:
            return None

    def forget(self, key_id: str) -> None:
        if not self._kr:
            return
        try:
            self._kr.delete_password(self.SERVICE, key_id)
        except Exception:
            pass


_CACHE = KeyCache()


# --------------------------------------------------------------------------
# крипто
# --------------------------------------------------------------------------
def _derive(password: str, salt: bytes, params: dict) -> bytes:
    kdf = Scrypt(salt=salt, length=int(params.get("dklen", 32)),
                 n=int(params.get("n", 2**15)), r=int(params.get("r", 8)),
                 p=int(params.get("p", 1)))
    return kdf.derive(password.encode("utf-8"))


def _fernet(key: bytes) -> Fernet:
    """Fernet требует 32-байтный ключ в url-safe base64."""
    return Fernet(base64.urlsafe_b64encode(key))


def key_id_of(key: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(key).digest()[:8]).decode().rstrip("=")


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
    def __init__(self, path: Path | str | None = None, *, key: bytes | None = None,
                 entries: list[Entry] | None = None, kdf: dict | None = None,
                 salt: bytes | None = None):
        self.path = Path(path) if path else default_vault_path()
        self._key = key
        self.entries: list[Entry] = entries or []
        self.kdf = dict(kdf or DEFAULT_KDF)
        self.salt = salt or os.urandom(16)
        self.dirty = False

    # ---- состояние -------------------------------------------------------
    @property
    def key_id(self) -> str:
        return key_id_of(self._key) if self._key else ""

    @property
    def locked(self) -> bool:
        return self._key is None

    def exists(self) -> bool:
        return self.path.is_file()

    # ---- открытие --------------------------------------------------------
    @classmethod
    def open(cls, path: Path | str | None = None, *, password: str | None = None,
             prompt: bool = True, use_cache: bool = True,
             key_from_stdin: bool = False) -> "Vault":
        p = Path(path) if path else default_vault_path()
        if not p.is_file():
            raise VaultError(
                f"Хранилище не найдено: {p}\nСоздайте его командой: gauth init"
            )
        head = json.loads(p.read_text(encoding="utf-8"))
        kid = head.get("key_id", "")
        key = None

        if password is not None:
            key = _derive(password, base64.b64decode(head["kdf"]["salt"]), head["kdf"])
        elif key_from_stdin:
            raw = sys.stdin.readline().strip()
            if raw:
                key = raw.encode() if len(raw) >= 32 else _derive(
                    raw, base64.b64decode(head["kdf"]["salt"]), head["kdf"])
        elif use_cache and kid:
            key = _CACHE.get(kid)
        if key is None and prompt:
            for _ in range(3):
                pw = getpass.getpass(f"Пароль хранилища [{p.name}]: ")
                cand = _derive(pw, base64.b64decode(head["kdf"]["salt"]), head["kdf"])
                try:
                    _fernet(cand).decrypt(head["token"].encode())
                except InvalidToken:
                    print("Неверный пароль, попробуйте ещё раз.", file=sys.stderr)
                    continue
                key = cand
                break
            if key is None:
                raise WrongPassword("Три неудачные попытки.")
        if key is None:
            raise VaultError("Нет пароля. Укажите --password/--key-from-stdin "
                             "или запустите интерактивно.")

        try:
            body = json.loads(_fernet(key).decrypt(head["token"].encode()))
        except InvalidToken as exc:
            if use_cache and kid and _CACHE.get(kid):
                _CACHE.forget(kid)  # протухший кэш — чистим
            raise WrongPassword("Неверный пароль (или повреждённый файл).") from exc

        v = cls(p, key=key, entries=_deserialize(body),
                kdf=head["kdf"], salt=base64.b64decode(head["kdf"]["salt"]))
        return v

    # ---- сохранение ------------------------------------------------------
    def save(self, *, remember: bool = False) -> None:
        if self._key is None:
            raise VaultError("Хранилище заблокировано — нечего сохранять.")
        body = json.dumps(_serialize(self.entries), ensure_ascii=False).encode("utf-8")
        token = _fernet(self._key).encrypt(body).decode()
        head = {
            "app": APP_NAME,
            "v": SCHEMA_VERSION,
            "kdf": {**self.kdf, "salt": base64.b64encode(self.salt).decode()},
            "key_id": self.key_id,
            "token": token,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(head), encoding="utf-8")
        _chmod_private(tmp)
        os.replace(tmp, self.path)
        _chmod_private(self.path)
        self.dirty = False
        if remember:
            self._remember_key()

    _warned_no_keyring = False

    def _remember_key(self) -> None:
        """Кэширует ключ в системный keyring, если он доступен.

        Без keyring пароль спрашивается при каждом запуске — это безопасно,
        но неудобно; подсказываем один раз и не мешаем автоматизации.
        """
        if _CACHE.put(self.key_id, self._key):
            return
        if Vault._warned_no_keyring or os.environ.get("GAUTH_QUIET"):
            return
        Vault._warned_no_keyring = True
        print("ℹ keyring не установлен — пароль будет запрашиваться при каждом "
              "запуске.\n  Чтобы не вводить его постоянно: pip install keyring  "
              "(или GAUTH_PASSWORD_FILE=~/путь/к/файлу).", file=sys.stderr)

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
        params = dict(kdf or self.kdf)
        self.salt = os.urandom(16)
        self.kdf = params
        self._key = _derive(new_password, self.salt, params)
        self.dirty = True


def _fuzzy(needle: str, hay: str) -> bool:
    """Простая проверка «буквы по порядку» (ggl -> google)."""
    it = iter(hay)
    return all(any(ch == c for c in it) for ch in needle)
