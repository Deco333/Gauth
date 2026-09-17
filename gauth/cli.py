"""gauth-pc — коды 2FA (TOTP/HOTP) с телефона на компьютере.

Работает с экспортом Google Authenticator (otpauth-migration://), с Aegis /
Raivo / 2FAS / FreeOTP (обычные otpauth:// ссылки) и с ручным вводом секрета.

Все коды считаются локально (RFC 6238), сеть не используется.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import time
from pathlib import Path

from . import base32x, clipboard, migration, qr_display, tui
from . import totp as T
from .migration import Entry
from .vault import Vault, VaultError, default_vault_path

PROG = "gauth"


# --------------------------------------------------------------------------
# утилиты CLI
# --------------------------------------------------------------------------
def eprint(*a, **kw):
    print(*a, file=sys.stderr, **kw)


class NoPassword(Exception):
    pass


def read_secret(prompt: str) -> str:
    """Скрытый ввод пароля; если терминала нет (пайп/CI) — берёт строку из stdin.

    Намеренно НЕ читает GAUTH_PASSWORD_FILE: это делает password_source(),
    иначе при смене пароля старый пароль попал бы в запрос нового.
    """
    if not sys.stdin.isatty() and os.environ.get("GAUTH_PASSWORD_FILE"):
        # автоматизация: файл уже обработан выше, здесь просто ждём строку
        pass
    try:
        return getpass.getpass(prompt)
    except EOFError:
        raise NoPassword("Ввод пароля прерван (нет терминала и пустой stdin).")
    except KeyboardInterrupt:
        raise NoPassword("Отменено.")
    except Exception:
        if not sys.stdin.isatty():
            line = sys.stdin.readline()
            if line:
                return line.rstrip("\n").rstrip("\r")
        raise NoPassword("Не удалось получить пароль: нет ни терминала, ни stdin.")


def password_source(args) -> str | None:
    """--password / $GAUTH_PASSWORD / $GAUTH_PASSWORD_FILE."""
    if getattr(args, "password", None):
        return args.password
    env = os.environ.get("GAUTH_PASSWORD")
    if env:
        return env
    pwfile = os.environ.get("GAUTH_PASSWORD_FILE")
    if pwfile:
        try:
            return Path(pwfile).read_text(encoding="utf-8").splitlines()[0].strip()
        except (OSError, IndexError):
            eprint(f"⚠ Не смог прочитать GAUTH_PASSWORD_FILE={pwfile}")
    return None


def common_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--vault", default=None, help="путь к файлу хранилища "
                   f"(по умолчанию {default_vault_path()})")


def load_vault(args) -> Vault:
    try:
        return Vault.open(args.vault)
    except NoPassword as exc:
        eprint(f"✖ {exc}")
        raise SystemExit(1)


def ask_password(new: bool = False) -> str:
    while True:
        pw = read_secret("Придумайте пароль (секреты шифруются им): " if new
                         else "Пароль: ")
        if not new:
            return pw
        if len(pw) < 6:
            eprint("Минимум 6 символов.")
            continue
        pw2 = read_secret("Повторите пароль: ")
        if pw != pw2:
            eprint("Пароли не совпадают, ещё раз.")
            continue
        return pw


def maybe_save(v: Vault, args) -> None:
    if v.dirty:
        v.save()


# --------------------------------------------------------------------------
# init
# --------------------------------------------------------------------------
def cmd_init(args) -> int:
    path = Path(args.vault) if args.vault else default_vault_path()
    if path.exists() and not args.force:
        eprint(f"Хранилище уже существует: {path}\n(используйте --force, чтобы "
               "создать пустое заново — старое будет перезаписано)")
        return 1
    v = Vault(path)
    v.entries = []
    v.save()
    print(f"✔ Хранилище создано: {path}")
    print("  Дальше:  gauth import ga        (перенос из Google Authenticator)")
    print("           gauth add --name mail  (ручной ввод секрета)")
    return 0


# --------------------------------------------------------------------------
# import
# --------------------------------------------------------------------------
def _finalize(e: Entry) -> Entry:
    """Доводит запись до нормального вида после любого парсера."""
    e.secret = base32x.normalize(e.secret)
    e.name = (e.name or "").strip() or "(без имени)"
    e.name, e.issuer = migration.split_name(e.name, e.issuer)
    if not e.issuer:
        e.issuer = ""
    e.algo = (e.algo or "SHA1").upper()
    if e.algo not in ("SHA1", "SHA256", "SHA512", "MD5"):
        e.algo = "SHA1"
    e.digits = int(e.digits or 6)
    e.period = int(e.period or 30) or 30
    e.kind = "hotp" if str(e.kind).lower() == "hotp" else "totp"
    if e.issuer.lower() == "steam" or e.meta.get("steam"):
        e.steam = True
    return e


def _collect_migration_texts(args) -> list[str]:
    """Собирает otpauth-migration:// строки из QR-файла, текста или stdin."""
    texts: list[str] = []
    if getattr(args, "qr", None):
        paths = args.qr if isinstance(args.qr, list) else [args.qr]
        for p in paths:
            texts.extend(qr_decode_or_die(p))
    if getattr(args, "text", None):
        vals = args.text if isinstance(args.text, list) else [args.text]
        texts.extend(vals)
    if getattr(args, "file", None):
        texts.append(Path(args.file).read_text(encoding="utf-8").strip())
    if not texts and not sys.stdin.isatty():
        data = sys.stdin.read().strip()
        if data:
            texts.extend([ln for ln in data.splitlines() if ln.strip()])
    if not texts:
        eprint("Не получил данных. Варианты:\n"
               "  gauth import ga --qr screenshot.png\n"
               "  gauth import ga --text 'otpauth-migration://offline?data=...'\n"
               "  echo 'otpauth-migration://...' | gauth import ga")
        raise SystemExit(2)
    return texts


def qr_decode_or_die(path: str) -> list[str]:
    try:
        from . import qr as qrmod

        return qrmod.decode_image(path)
    except FileNotFoundError as exc:
        eprint(str(exc))
        raise SystemExit(2)
    except Exception as exc:  # NoQRBackend и прочее
        eprint(f"Не удалось прочитать QR из файла: {exc}")
        raise SystemExit(2)


def cmd_import_ga(args) -> int:
    v = load_vault(args)
    texts = _collect_migration_texts(args)

    entries: list[Entry] = []
    batches: dict[int, migration.MigrationPayload] = {}
    for text in texts:
        try:
            payload = migration.from_migration_uri(text)
        except migration.MigrationError as exc:
            eprint(f"⚠ Пропущено: {exc}")
            continue
        key = (payload.batch_id, payload.batch_index)
        if key in batches:
            eprint(f"⚠ Дубликат части экспорта batch_index={payload.batch_index} "
                   "(тот же QR отсканирован дважды) — пропускаю.")
        else:
            batches[key] = payload
        entries.extend(payload.entries)

    entries = [_finalize(e) for e in entries]

    # дедупликация внутри самого импорта (несколько частей одного батча)
    uniq: dict[tuple[str, str, str], Entry] = {}
    for e in entries:
        uniq.setdefault((e.secret, e.name, e.issuer), e)
    entries = list(uniq.values())

    if not entries:
        eprint("Ни одной записи не распознано.")
        return 2

    if len(batches) > 1 or any(b.batch_size > 1 for b in batches.values()):
        got = sorted(batches.values(), key=lambda b: b.batch_index)
        eprint("Части экспорта: " + ", ".join(
            f"#{b.batch_index + 1}/{b.batch_size}" for b in got))
        # ожидаем полный набор индексов 0..batch_size-1
        declared = max((b.batch_size for b in got), default=1)
        have = {b.batch_index for b in got}
        missing = [i for i in range(declared) if i not in have]
        if missing:
            eprint("⚠ Не хватает частей: " +
                   ", ".join(f"#{i + 1}/{declared}" for i in missing) +
                   ". Google Authenticator показывает QR экспорта по очереди — "
                   "сделайте скриншоты всех экранов и повторите импорт "
                   "(уже добавленные записи не задвоятся).")

    if args.dry_run:
        print(tui.render_table(entries, show_secret=args.show_secret))
        print(f"\nВсего: {len(entries)} записей (ничего не сохранено, --dry-run)")
        return 0

    added, skipped = v.add_many(entries, replace=args.force)
    maybe_save(v, args)
    print(f"✔ Импортировано: {added}, пропущено дубликатов: {skipped}. "
          f"Всего в хранилище: {len(v.entries)}")
    print("  Проверить: gauth codes")
    return 0


def cmd_import_text(args) -> int:
    """Массовый импорт из файла: otpauth:// по строке ИЛИ TSV secret<TAB>name."""
    v = load_vault(args)
    src = Path(args.path).read_text(encoding="utf-8") if args.path != "-" \
        else sys.stdin.read()
    entries: list[Entry] = []
    for lineno, line in enumerate(src.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            if line.lower().startswith("otpauth"):
                e = migration.from_otpauth_uri(line)
            elif "\t" in line or line.count(" ") >= 1:
                parts = [p for p in line.replace("\t", "  ").split("  ") if p.strip()] \
                    if "\t" not in line else [p for p in line.split("\t") if p.strip()]
                if len(parts) < 2:
                    raise ValueError("нужно: secret<TAB>name[<TAB>issuer]")
                e = Entry(secret=parts[0], name=parts[1],
                          issuer=parts[2] if len(parts) > 2 else "",
                          source="text-import")
            else:
                raise ValueError("нужно secret<TAB>name или otpauth://...")
            entries.append(_finalize(e))
        except Exception as exc:  # noqa: BLE001
            eprint(f"⚠ строка {lineno}: {exc}")
    if not entries:
        eprint("Нечего импортировать.")
        return 2
    if args.dry_run:
        print(tui.render_table(entries, show_secret=args.show_secret))
        return 0
    added, skipped = v.add_many(entries, replace=args.force)
    maybe_save(v, args)
    print(f"✔ Импортировано: {added}, пропущено: {skipped}. Всего: {len(v.entries)}")
    return 0


def cmd_import_aegis(args) -> int:
    """Импорт из резервной копии Aegis (JSON, зашифрованной или нет) и 2FAS."""
    v = load_vault(args)
    raw = json.loads(Path(args.path).read_text(encoding="utf-8"))
    db = raw.get("db", raw)

    if db.get("encrypted") or raw.get("header", {}).get("encryption") not in (None, "none"):
        pw = read_secret("Пароль от бэкапа Aegis: ")
        db = _aegis_decrypt(raw, pw)

    entries = []
    for item in db.get("entries", []):
        info = item.get("info", {})
        e = Entry(
            name=item.get("name") or info.get("account") or "",
            issuer=item.get("issuer") or "",
            secret=info.get("secret", ""),
            algo=(info.get("algo") or "SHA1").upper(),
            digits=int(info.get("digits") or 6),
            period=int(info.get("period") or 30),
            kind=str(item.get("type", "totp")).lower(),
            counter=int(info.get("counter") or 0),
            source="aegis",
        )
        entries.append(_finalize(e))
    if not entries:
        eprint("В бэкапе 0 записей.")
        return 2
    if args.dry_run:
        print(tui.render_table(entries, show_secret=args.show_secret))
        return 0
    added, skipped = v.add_many(entries, replace=args.force)
    maybe_save(v, args)
    print(f"✔ Импортировано: {added}, пропущено: {skipped}. Всего: {len(v.entries)}")
    return 0


def _aegis_decrypt(raw: dict, password: str) -> dict:
    """Расшифровка бэкапа Aegis (AES-256-GCM + scrypt)."""
    import base64

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    hdr = raw["header"]["params"]
    kdf = raw["header"]["kdf"]
    if kdf.get("type") != "scrypt":
        raise VaultError(f"Неподдерживаемый KDF Aegis: {kdf.get('type')}")
    p = kdf["params"]
    key = Scrypt(salt=base64.b64decode(p["salt"]), length=p.get("key_size", 32),
                 n=p["n"], r=p["r"], p=p["p"]).derive(password.encode())
    nonce = base64.b64decode(hdr["nonce"])
    ct = base64.b64decode(raw["db"]["data"])
    tag = base64.b64decode(raw["db"]["tag"]) if "tag" in raw["db"] else b""
    plain = AESGCM(key).decrypt(nonce, ct + tag, None)
    return json.loads(plain)


# --------------------------------------------------------------------------
# add / edit / rm
# --------------------------------------------------------------------------
def cmd_add(args) -> int:
    v = load_vault(args)
    name = args.name or input("Название аккаунта (например ivan@gmail.com): ").strip()
    issuer = args.issuer
    if issuer is None:
        issuer = input("Сервис/эмитент (например Google, GitHub) [Enter — пропустить]: ").strip()
    secret = args.secret
    if not secret:
        secret = read_secret("Секретный ключ (base32, из настроек 2FA сервиса): ")
        if not secret.strip():
            eprint("Без секрета нечего добавлять.")
            return 2
    try:
        e = _finalize(Entry(name=name, issuer=issuer or "", secret=secret,
                            kind=args.type, digits=args.digits, period=args.period,
                            counter=args.counter, algo=args.algo, note=args.note or "",
                            steam=args.steam, source="manual"))
    except Exception as exc:  # noqa: BLE001
        eprint(f"Ошибка: {exc}")
        return 2
    try:
        v.add(e, replace=args.force)
    except VaultError as exc:
        eprint(str(exc))
        return 1
    maybe_save(v, args)
    c = T.totp(e.secret, period=e.period, digits=e.digits, algorithm=e.algo, steam=e.steam)
    print(f"✔ Добавлено: {e.issuer + ': ' if e.issuer else ''}{e.name}")
    print(f"  Текущий код: {tui.split_code(c.value)}  ({int(c.remaining)}с до смены)")
    return 0


def cmd_edit(args) -> int:
    v = load_vault(args)
    idx = _pick(v, args.query, args.index, args.yes)
    if idx is None:
        return 1
    e = v.entries[idx]
    changed = []
    for field, val in (("name", args.name), ("issuer", args.issuer),
                       ("note", args.note), ("secret", args.secret)):
        if val is not None:
            setattr(e, field, val)
            changed.append(field)
    if args.period:
        e.period = args.period
        changed.append("period")
    if args.digits:
        e.digits = args.digits
        changed.append("digits")
    if args.counter is not None:
        e.counter = args.counter
        changed.append("counter")
    if args.steam is not None:
        e.steam = args.steam
        changed.append("steam")
    if not changed:
        eprint("Нечего менять. См. gauth edit -h")
        return 1
    try:
        _finalize(e)
    except Exception as exc:  # noqa: BLE001
        eprint(f"Ошибка: {exc}")
        return 2
    v.dirty = True
    maybe_save(v, args)
    print(f"✔ Обновлено: {', '.join(changed)}")
    return 0


def cmd_rm(args) -> int:
    v = load_vault(args)
    idx = _pick(v, args.query, args.index, args.yes)
    if idx is None:
        return 1
    e = v.entries[idx]
    if not args.yes:
        ans = input(f"Удалить «{e.issuer + ': ' if e.issuer else ''}{e.name}»? [y/N] ")
        if ans.strip().lower() not in ("y", "yes", "д", "да"):
            print("Отменено.")
            return 0
    v.remove(idx)
    maybe_save(v, args)
    print(f"✔ Удалено: {e.name}")
    return 0


def _pick(v: Vault, query: str | None, index: int | None, yes: bool) -> int | None:
    """Находит индекс записи: по --index или по запросу (с подтверждением)."""
    if index is not None:
        if 0 <= index < len(v.entries):
            return index
        eprint(f"Индекс {index} вне диапазона 0..{len(v.entries) - 1}")
        return None
    if not query:
        eprint("Укажите --index N или поисковый запрос, например: gauth get google")
        return None
    found = v.search(query)
    if not found:
        eprint(f"Ничего не найдено по запросу «{query}». Список: gauth list")
        return None
    if len(found) == 1:
        return v.entries.index(found[0])
    print("Найдено несколько записей:")
    for i, e in enumerate(found[:10]):
        real = v.entries.index(e)
        print(f"  [{real}] {e.issuer + ': ' if e.issuer else ''}{e.name}")
    if yes:
        return v.entries.index(found[0])
    ans = input("Номер записи (Enter — отмена): ").strip()
    if not ans.isdigit():
        return None
    n = int(ans)
    return n if 0 <= n < len(v.entries) else None


# --------------------------------------------------------------------------
# просмотр / коды
# --------------------------------------------------------------------------
def cmd_codes(args) -> int:
    v = load_vault(args)
    entries = v.search(args.query) if args.query else \
        sorted(v.entries, key=lambda e: ((e.issuer or "zzz").lower(), e.name.lower()))
    if args.index is not None:
        if not (0 <= args.index < len(v.entries)):
            eprint(f"Индекс вне диапазона 0..{len(v.entries) - 1}")
            return 1
        entries = [v.entries[args.index]]
    if not entries:
        eprint("Хранилище пустое. Импорт: gauth import ga")
        return 1
    if args.once or not sys.stdout.isatty():
        print(tui.render_table(entries, show_secret=args.show_secret,
                               color=False if not sys.stdout.isatty() else None))
        return 0
    try:
        tui.render_live(entries, show_secret=args.show_secret)
    except BrokenPipeError:
        pass
    return 0


def cmd_list(args) -> int:
    v = load_vault(args)
    entries = v.search(args.query) if args.query else \
        sorted(v.entries, key=lambda e: ((e.issuer or "zzz").lower(), e.name.lower()))
    if args.json:
        out = []
        for e in entries:
            d = {"name": e.name, "issuer": e.issuer, "type": e.kind, "algo": e.algo,
                 "digits": e.digits, "period": e.period, "counter": e.counter,
                 "steam": e.steam, "note": e.note, "source": e.source,
                 "index": v.entries.index(e)}
            if args.show_secret:
                d["secret"] = e.secret
            out.append(d)
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return 0
    if not entries:
        eprint("Пусто. Импорт: gauth import ga --qr screenshot.png")
        return 0
    w_iss = max([tui.visible_width(e.issuer or "—") for e in entries] + [7])
    w_iss = min(max(w_iss, 7), 28)
    w_name = max([tui.visible_width(e.name) for e in entries] + [7])
    w_name = min(max(w_name, 7), 38)
    head = (f"{'№':>4}  {tui.pad('ЭМИТЕНТ', w_iss)} {tui.pad('АККАУНТ', w_name)} "
            f"{'ТИП':<5} ПАРАМЕТРЫ")
    print(tui.bold(head, tui.supports_color()))
    print("─" * min(100, max(40, tui.visible_width(head))))
    for e in entries:
        i = v.entries.index(e)
        params = f"{e.digits} цифр, {e.period}с, {e.algo}"
        if e.kind == "hotp":
            params = f"hotp, счётчик {e.counter}"
        if e.steam:
            params += ", Steam"
        if e.note:
            params += f"  [{e.note}]"
        print(f"{i:>4}  {tui.pad(e.issuer or '—', w_iss)} "
              f"{tui.pad(e.name, w_name)} {e.kind:<5} {params}")
    print(f"\nВсего: {len(entries)}")
    return 0


def _resolve_entry(v: Vault, args) -> Entry | None:
    if args.index is not None:
        if 0 <= args.index < len(v.entries):
            return v.entries[args.index]
        eprint(f"Индекс вне диапазона 0..{len(v.entries) - 1}")
        return None
    query = args.query
    if not query:
        eprint(f"Укажите запрос: {PROG} get google   (или --index N)")
        return None
    found = v.search(query)
    if not found:
        eprint(f"Ничего не найдено по «{query}». Список: {PROG} list")
        return None
    if len(found) > 1 and not args.force_first:
        eprint(f"По запросу «{query}» найдено {len(found)} записей, беру первую:")
        for e in found[:5]:
            eprint(f"   • {e.issuer + ': ' if e.issuer else ''}{e.name}")
        eprint(f"(уточните запрос или используйте --index; {PROG} list покажет номера)")
    return found[0]


def cmd_get(args) -> int:
    v = load_vault(args)
    e = _resolve_entry(v, args)
    if e is None:
        return 1
    c = T.entry_code(e)
    if e.kind == "hotp" and args.bump:
        c = T.entry_code(e, drift=1)
    if args.wait and c.remaining != float("inf") and c.remaining < args.wait:
        # ждём свежий код, чтобы он не протух, пока вы его вставляете
        time.sleep(c.remaining + 0.15)
        c = T.entry_code(e)
    if args.bare:
        sys.stdout.write(c.value + ("\n" if not args.no_newline else ""))
    else:
        print(tui.render_single_big(e))
    if args.bump and e.kind == "hotp":
        e.counter += 1
        v.dirty = True
        maybe_save(v, args)
        eprint(f"ℹ HOTP-счётчик увеличен до {e.counter}")
    return 0


def cmd_copy(args) -> int:
    v = load_vault(args)
    e = _resolve_entry(v, args)
    if e is None:
        return 1
    c = T.entry_code(e)
    try:
        backend = clipboard.copy_and_wipe(c.value, ttl=0 if args.no_wipe else args.wipe)
    except clipboard.ClipboardError as exc:
        eprint(str(exc))
        return 2
    label = f"{e.issuer}: {e.name}" if e.issuer else e.name
    print(f"✔ {c.value} → буфер обмена ({backend}), {int(c.remaining)}с до смены"
          + ("" if args.no_wipe else f", автоочистка через {args.wipe}с"))
    if args.print_code:
        print(label)
    return 0


def cmd_check(args) -> int:
    """Сверка с телефоном: введите код из Google Authenticator — найдём расхождение.

    Если код не принимается сайтом, почти всегда виноваты часы на ПК.
    """
    v = load_vault(args)
    e = _resolve_entry(v, args)
    if e is None:
        return 1
    label = f"{e.issuer + ': ' if e.issuer else ''}{e.name}"
    if e.kind == "hotp":
        print(f"«{label}» — HOTP, коды не зависят от времени. "
              f"Текущий счётчик: {e.counter}")
        if args.code:
            for d in range(0, 10):
                if T.hotp(base32x.to_bytes(e.secret), e.counter + d,
                          e.digits, e.algo) == args.code.strip():
                    print(f"Совпало при счётчике {e.counter + d} "
                          f"(нужно --bump {d} раз).")
                    return 0
            print("Код не найден среди следующих 10 значений счётчика.")
            return 1
        return 0

    code = (args.code or input(
        f"Введите код, который сейчас показывает телефон для «{label}»: ")).strip()
    mine = T.entry_code(e).value
    print(f"Код телефона: {code}\nКод на ПК:    {mine}")
    if code == mine:
        print("✔ Совпадают. Часы в норме — если сайт не принимает код, "
              "проблема на стороне сервиса или код уже успел истечь.")
        return 0
    drift = T.drift_estimate(e.secret, code, period=e.period, digits=e.digits,
                             algorithm=e.algo, window=40)
    if drift is None:
        print("✖ Код телефона не найден ни в одном соседнем 30-секундном окне. "
              "Возможно, вы ввели код другой записи или секрет импортирован неверно.")
        return 1
    seconds = drift * e.period
    sign = "спешат" if seconds > 0 else "отстают"
    print(f"✖ Часы на ПК {sign} примерно на {abs(seconds)} секунд "
          f"({drift:+d} периодов по {e.period}с).")
    print("  Как исправить:")
    print("   Windows: Параметры → Время и язык → Дата и время → «Синхронизировать»")
    print("            (или в cmd от админа: w32tm /resync)")
    print("   macOS:   Системные настройки → Основные → Дата и время → «Устанавливать автоматически»")
    print("   Linux:   sudo timedatectl set-ntp true  &&  timedatectl")
    print("  Также проверьте, что выбран правильный часовой пояс/UTC и что код "
          "не истёк за время ввода.")
    return 1


def cmd_qr(args) -> int:
    v = load_vault(args)
    e = _resolve_entry(v, args)
    if e is None:
        return 1
    uri = qr_display.otpauth_uri(e)
    if args.save:
        qr_display.save_png(uri, args.save)
        print(f"✔ QR сохранён: {args.save}")
        return 0
    if args.url:
        print(uri)
        return 0
    try:
        print(qr_display.render_terminal(uri))
    except RuntimeError as exc:
        eprint(f"{exc}\nСсылка: {uri}")
        return 2
    print(f"\n{e.issuer + ': ' if e.issuer else ''}{e.name}")
    print("Отсканируйте этот QR в Google Authenticator / Aegis, "
         "чтобы перенести аккаунт на телефон.")
    return 0


# --------------------------------------------------------------------------
# экспорт, диагностика, сервис
# --------------------------------------------------------------------------
def cmd_gen(args) -> int:
    """Сгенерировать новый секрет (когда сервис даёт «ввести ключ вручную»)."""
    secret = T.random_secret(args.bytes)
    issuer = args.issuer or "Service"
    name = args.name or f"user{int(time.time()) % 1000}"
    e = Entry(name=name, issuer=issuer, secret=secret, digits=args.digits,
              period=args.period, algo=args.algo, source="generated")
    print(f"Секрет (base32): {secret}")
    if args.uri:
        print("Ссылка:        " + qr_display.otpauth_uri(e))
    if args.qr:
        try:
            print(qr_display.render_terminal(qr_display.otpauth_uri(e)))
        except RuntimeError as exc:
            eprint(str(exc))
    print("\nЭтот ключ вводится на сайте при включении 2FA («ввести ключ вручную»/"
          "\n«setup key»). После включения добавьте его сюда:")
    print(f"  {PROG} add --name {name} --issuer '{issuer}' --secret {secret}")
    if args.add:
        v = load_vault(args)
        try:
            v.add(_finalize(e), replace=args.force)
        except VaultError as exc:
            eprint(str(exc))
            return 1
        maybe_save(v, args)
        print(f"\n✔ Уже сохранено в хранилище: {issuer}: {name}")
    return 0


def cmd_export(args) -> int:
    v = load_vault(args)
    fmt = args.format
    if fmt == "aegis":
        data = {"version": 2, "header": {"slots": None, "params": None,
                                         "encryption": "none"},
                "db": {"version": 2, "entries": [
                    {"type": e.kind, "uuid": f"ga-{i}", "name": e.name,
                     "issuer": e.issuer, "note": e.note,
                     "info": {"secret": e.secret, "algo": e.algo,
                              "digits": e.digits, "period": e.period,
                              "counter": e.counter}}
                    for i, e in enumerate(v.entries)]}}
    elif fmt == "uris":
        data = [qr_display.otpauth_uri(e) for e in v.entries]
    else:  # json
        data = [{"name": e.name, "issuer": e.issuer, "type": e.kind,
                 "algo": e.algo, "digits": e.digits, "period": e.period,
                 "counter": e.counter, "steam": e.steam, "note": e.note,
                 **({"secret": e.secret} if not args.no_secrets else {})}
                for e in v.entries]
    text = json.dumps(data, ensure_ascii=False, indent=2) if fmt != "uris" \
        else "\n".join(data)
    if args.out and args.out != "-":
        Path(args.out).write_text(text + "\n", encoding="utf-8")
        try:
            os.chmod(args.out, 0o600)
        except OSError:
            pass
        print(f"✔ Экспорт: {args.out}")
        if not args.no_secrets:
            eprint("⚠ Файл содержит секреты в открытом виде. Удалите после "
                   "использования и не храните в облаке/репозитории.")
    else:
        print(text)
        if not args.no_secrets:
            eprint("⚠ Вывод содержит секреты в открытом виде.")
    return 0


def cmd_passwd(args) -> int:
    """Метод устарел: шифрование отключено."""
    eprint("⚠ Шифрование отключено. Хранилище сохраняется в открытом виде\n"
           "  с правами доступа 0600 (только ваш пользователь).")
    return 0
    print("✔ Пароль изменён, хранилище перезашифровано.")
    return 0


def cmd_gui(args) -> int:
    """Графическое окно с кодами (tkinter)."""
    from . import gui

    argv: list[str] = []
    if args.vault:
        argv += ["--vault", args.vault]
    return gui.main(argv)


def cmd_doctor(args) -> int:
    print("gauth-pc — диагностика\n" + "─" * 40)
    path = Path(args.vault) if args.vault else default_vault_path()
    print(f"Хранилище: {path} — {'есть' if path.exists() else 'НЕТ (gauth init)'}")
    if path.exists():
        st = path.stat()
        mode = oct(st.st_mode)[-3:] if hasattr(st, "st_mode") else "?"
        print(f"  размер: {st.st_size} байт, права: {mode}"
              + ("" if mode in ("600", "400") else "  ⚠ лучше chmod 600"))
        try:
            v = load_vault(args)
            print(f"  записей: {len(v.entries)}")
        except Exception as exc:  # noqa: BLE001
            print(f"  ⚠ не открылось: {exc}")
    else:
        v = None

    for mod, hint in (("cryptography", "pip install cryptography"),
                      ("keyring", "pip install keyring (кэш пароля)"),
                      ("pyqrcode", "pip install pyqrcode (QR в терминале)"),
                      ("zxingcpp", "pip install zxing-cpp pillow (чтение QR с картинки)"),
                      ("cv2", "pip install opencv-python (чтение QR)"),
                      ("pyzbar", "pip install pyzbar pillow (чтение QR)"),
                      ("pyperclip", "pip install pyperclip (буфер обмена)")):
        try:
            __import__(mod)
            print(f"  ✔ {mod}")
        except ImportError:
            print(f"  – {mod}: не установлен ({hint})")

    # сверка часов: код не совпадёт, если время на ПК убежало
    if v and v.entries:
        e = v.entries[0]
        c = T.totp(e.secret, period=e.period, digits=e.digits, algorithm=e.algo,
                   steam=e.steam)
        d = T.drift_estimate(e.secret, c.value, period=e.period, digits=e.digits,
                             algorithm=e.algo)
        print(f"\nЛокальное время: {time.strftime('%Y-%m-%d %H:%M:%S')} (UTC{time.strftime('%z')})")
        print(f"Самопроверка TOTP на «{e.name}»: код {c.value}, drift={d} "
              "(0 = часы в норме)")
        print("Если код не принимается сервисом — проверьте время на ПК и телефоне "
              "(должно совпадать, синхронизация по NTP).")
    return 0


def cmd_info(args) -> int:
    v = load_vault(args)
    tot = sum(1 for e in v.entries if e.kind == "totp")
    hot = len(v.entries) - tot
    issuers = sorted({e.issuer for e in v.entries if e.issuer})
    print(f"Хранилище: {v.path}")
    print(f"Записей:   {len(v.entries)} (TOTP: {tot}, HOTP: {hot})")
    print(f"Сервисов:  {len(issuers)}")
    if issuers:
        print("           " + ", ".join(issuers[:12]) +
              ("…" if len(issuers) > 12 else ""))
    print(f"Крипто:    Fernet(AES-128-CBC+HMAC) / scrypt n={v.kdf.get('n')} "
          f"r={v.kdf.get('r')} p={v.kdf.get('p')}")
    return 0


# --------------------------------------------------------------------------
# парсер аргументов
# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=PROG,
        description="Коды 2FA (TOTP/HOTP) на компьютере: импорт из Google "
                    "Authenticator и генерация кодов локально, без сети.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Быстрый старт:
  1) gauth init                                  # создать хранилище
  2) Google Authenticator → ⋮ → «Перенос аккаунтов» → «Экспорт» → скриншот QR
  3) gauth import ga --qr screenshot.png         # или --text 'otpauth-migration://…'
  4) gauth gui                                   # окно с кодами (или gauth codes)
     gauth get google                            # один код (для скриптов: --bare)
     gauth copy github                           # скопировать в буфер

Без распознавания QR: отсканируйте QR любым сканером на телефоне и вставьте
текст ссылки в  gauth import ga --text '…'
""")
    sub = p.add_subparsers(dest="cmd", metavar="КОМАНДА")

    sp = sub.add_parser("init", help="создать хранилище")
    common_args(sp)
    sp.add_argument("--force", action="store_true", help="перезаписать существующее")
    sp.set_defaults(func=cmd_init)

    # --- import ---
    imp = sub.add_parser("import", help="импорт секретов")
    isub = imp.add_subparsers(dest="sub", metavar="ИСТОЧНИК")

    g = isub.add_parser("ga", help="из Google Authenticator (otpauth-migration://)")
    common_args(g)
    g.add_argument("--qr", nargs="+", help="файл(ы) со скриншотом QR-кода экспорта")
    g.add_argument("--text", nargs="+", help="строка otpauth-migration:// напрямую")
    g.add_argument("--file", help="текстовый файл со ссылкой")
    g.add_argument("--force", action="store_true", help="перезаписывать дубликаты")
    g.add_argument("--dry-run", action="store_true", help="показать, но не сохранять")
    g.add_argument("--show-secret", action="store_true", help="показывать секреты")
    g.set_defaults(func=cmd_import_ga, sub="ga")

    tx = isub.add_parser("text", help="из файла: otpauth:// по строке или TSV")
    common_args(tx)
    tx.add_argument("path", help="файл или '-' для stdin")
    tx.add_argument("--force", action="store_true")
    tx.add_argument("--dry-run", action="store_true")
    tx.add_argument("--show-secret", action="store_true")
    tx.set_defaults(func=cmd_import_text, sub="text")

    ag = isub.add_parser("aegis", help="из бэкапа Aegis / 2FAS (JSON)")
    common_args(ag)
    ag.add_argument("path")
    ag.add_argument("--force", action="store_true")
    ag.add_argument("--dry-run", action="store_true")
    ag.add_argument("--show-secret", action="store_true")
    ag.set_defaults(func=cmd_import_aegis, sub="aegis")
    imp.set_defaults(func=lambda a: (eprint("Укажите источник: ga | text | aegis"), 2)[1])

    # --- add / edit / rm ---
    a = sub.add_parser("add", help="добавить секрет вручную")
    common_args(a)
    a.add_argument("--name", help="аккаунт (ivan@gmail.com)")
    a.add_argument("--issuer", help="сервис (Google, GitHub…)")
    a.add_argument("--secret", help="base32-секрет (иначе спросит скрытно)")
    a.add_argument("--type", choices=["totp", "hotp"], default="totp")
    a.add_argument("--digits", type=int, default=6, choices=[6, 8])
    a.add_argument("--period", type=int, default=30)
    a.add_argument("--counter", type=int, default=0)
    a.add_argument("--algo", default="SHA1", choices=["SHA1", "SHA256", "SHA512", "MD5"])
    a.add_argument("--steam", action="store_true", help="формат Steam Guard (5 символов)")
    a.add_argument("--note", default="")
    a.add_argument("--force", action="store_true", help="перезаписать существующую запись")
    a.set_defaults(func=cmd_add)

    ed = sub.add_parser("edit", help="изменить запись")
    common_args(ed)
    ed.add_argument("query", nargs="?", help="поисковый запрос")
    ed.add_argument("--index", type=int)
    ed.add_argument("--name"), ed.add_argument("--issuer"), ed.add_argument("--note")
    ed.add_argument("--secret")
    ed.add_argument("--period", type=int), ed.add_argument("--digits", type=int)
    ed.add_argument("--counter", type=int)
    ed.add_argument("--steam", action="store_true", default=None)
    ed.add_argument("-y", "--yes", action="store_true")
    ed.set_defaults(func=cmd_edit)

    rm = sub.add_parser("rm", help="удалить запись")
    common_args(rm)
    rm.add_argument("query", nargs="?")
    rm.add_argument("--index", type=int)
    rm.add_argument("-y", "--yes", action="store_true")
    rm.set_defaults(func=cmd_rm)

    # --- просмотр ---
    c = sub.add_parser("codes", aliases=["show"], help="живая таблица кодов")
    common_args(c)
    c.add_argument("query", nargs="?", help="фильтр (google, github…)")
    c.add_argument("--index", type=int, help="показать одну запись по номеру")
    c.add_argument("--once", action="store_true", help="без автообновления")
    c.add_argument("--show-secret", action="store_true")
    c.set_defaults(func=cmd_codes)

    ls = sub.add_parser("list", aliases=["ls"], help="список записей без кодов")
    common_args(ls)
    ls.add_argument("query", nargs="?")
    ls.add_argument("--json", action="store_true")
    ls.add_argument("--show-secret", action="store_true")
    ls.set_defaults(func=cmd_list)

    ge = sub.add_parser("get", help="один код (удобно для скриптов)")
    common_args(ge)
    ge.add_argument("query", nargs="?")
    ge.add_argument("--index", type=int)
    ge.add_argument("--bare", action="store_true", help="только цифры, без оформления")
    ge.add_argument("--no-newline", action="store_true")
    ge.add_argument("--wait", type=float, default=0, metavar="SEC",
                    help="если осталось меньше SEC — подождать новый код")
    ge.add_argument("--bump", action="store_true",
                    help="для HOTP: показать код следующего счётчика и сохранить его")
    ge.add_argument("--force-first", action="store_true",
                    help="не выводить предупреждение о нескольких совпадениях")
    ge.set_defaults(func=cmd_get)

    cp = sub.add_parser("copy", help="скопировать код в буфер обмена")
    common_args(cp)
    cp.add_argument("query", nargs="?")
    cp.add_argument("--index", type=int)
    cp.add_argument("--wipe", type=int, default=25, metavar="SEC",
                    help="очистить буфер через N секунд (по умолчанию 25)")
    cp.add_argument("--no-wipe", action="store_true")
    cp.add_argument("--print-code", action="store_true")
    cp.add_argument("--force-first", action="store_true")
    cp.set_defaults(func=cmd_copy)

    ck = sub.add_parser("check", help="сверить код с телефоном и найти рассинхрон часов")
    common_args(ck)
    ck.add_argument("query", nargs="?")
    ck.add_argument("--index", type=int)
    ck.add_argument("--code", help="код с телефона (иначе спросит)")
    ck.add_argument("--force-first", action="store_true")
    ck.set_defaults(func=cmd_check)

    q = sub.add_parser("qr", help="показать QR записи (перенос на телефон)")
    common_args(q)
    q.add_argument("query", nargs="?")
    q.add_argument("--index", type=int)
    q.add_argument("--url", action="store_true", help="напечатать otpauth:// ссылку")
    q.add_argument("--save", help="сохранить QR в PNG-файл")
    q.add_argument("--force-first", action="store_true")
    q.set_defaults(func=cmd_qr)

    # --- сервис ---
    gn = sub.add_parser("gen", help="сгенерировать новый секрет + QR для сайта")
    common_args(gn)
    gn.add_argument("--name", help="имя аккаунта для QR/ссылки")
    gn.add_argument("--issuer", help="название сервиса для QR/ссылки")
    gn.add_argument("--bytes", type=int, default=20, choices=[10, 16, 20, 32, 64],
                    help="длина ключа в байтах (20 = 160 бит, стандарт)")
    gn.add_argument("--digits", type=int, default=6, choices=[6, 8])
    gn.add_argument("--period", type=int, default=30)
    gn.add_argument("--algo", default="SHA1", choices=["SHA1", "SHA256", "SHA512"])
    gn.add_argument("--uri", action="store_true", help="напечатать otpauth:// ссылку")
    gn.add_argument("--qr", action="store_true", help="напечатать QR в терминале")
    gn.add_argument("--add", action="store_true", help="сразу сохранить в хранилище")
    gn.add_argument("--force", action="store_true")
    gn.set_defaults(func=cmd_gen)

    ex = sub.add_parser("export", help="экспорт (json / aegis / uris)")
    common_args(ex)
    ex.add_argument("--format", choices=["json", "aegis", "uris"], default="json")
    ex.add_argument("--out", default="-", help="файл или '-' для stdout")
    ex.add_argument("--no-secrets", action="store_true", help="без секретов (метаданные)")
    ex.set_defaults(func=cmd_export)

    pw = sub.add_parser("passwd", help="сменить пароль хранилища")
    common_args(pw)
    pw.set_defaults(func=cmd_passwd)

    gu = sub.add_parser("gui", help="графическое окно с кодами (tkinter)")
    common_args(gu)
    gu.set_defaults(func=cmd_gui)

    d = sub.add_parser("doctor", help="диагностика: зависимости, часы, vault")
    common_args(d)
    d.set_defaults(func=cmd_doctor)

    i = sub.add_parser("info", help="краткая сводка по хранилищу")
    common_args(i)
    i.set_defaults(func=cmd_info)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    try:
        return args.func(args) or 0
    except NoPassword as exc:
        eprint(f"✖ {exc}")
        return 1
    except VaultError as exc:
        eprint(f"✖ {exc}")
        return 1
    except KeyboardInterrupt:
        eprint("\nПрервано.")
        return 130
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
