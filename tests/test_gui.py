"""Тесты GUI.

tkinter в CI/контейнере обычно отсутствует, поэтому:
  • чистая логика GUI (build_rows / row_state / describe_drift / sort_entries)
    тестируется через подставной модуль tkinter;
  • весь жизненный цикл окна (создание виджетов, открытие хранилища, тикер,
    импорт из фото QR, добавление/удаление записи, смена пароля) прогоняется
    на моке tkinter — это ловит опечатки и AttributeError до запуска у пользователя.

Запуск: python3 tests/test_gui.py   или   python3 -m pytest tests/test_gui.py
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

FIXTURES = ROOT / "tests" / "fixtures"


# ==========================================================================
# мок tkinter
# ==========================================================================
def install_fake_tkinter():
    """Ставит в sys.modules подставной tkinter. Возвращает (tk, log)."""
    log: list[str] = []

    class TclError(Exception):
        pass

    class Widget:
        def __init__(self, *a, **kw):
            self._kw = kw
            self._items: dict[str, dict] = {}
            self._order: list[str] = []
            self._selection: tuple[str, ...] = ()
            self._values: dict[str, object] = {}
            self._after: list = []

        # ---- упаковка/геометрия ----
        def pack(self, **kw):
            return self

        pack_forget = pack
        grid = pack
        place = pack

        def config(self, name=None, **kw):
            if name is not None and not kw:
                return self._values.get(name)
            self._values.update({k: v for k, v in kw.items() if k != "values"})
            return self

        configure = config
        cget = lambda self, k=None: self._values.get(k)

        def bind(self, *a, **kw):
            return self

        def focus_set(self):
            return self

        def focus_force(self):
            return self

        def update_idletasks(self):
            return self

        def destroy(self):
            log.append("destroy")
            return self

        def winfo_width(self):
            return 640

        def winfo_height(self):
            return 40

        def geometry(self, *a):
            return self

        def title(self, *a):
            return self

        def minsize(self, *a):
            return self

        def resizable(self, *a):
            return self

        def protocol(self, *a):
            return self

        def transient(self, *a):
            return self

        def grab_set(self):
            return self

        def iconbitmap(self, *a):
            return self

        def state(self, *a):
            return "normal"

        def after(self, ms, fn=None, *a):
            self._after.append((ms, fn))
            if fn:
                try:
                    fn(*a)
                except Exception as exc:  # noqa: BLE001
                    log.append(f"after-error:{type(exc).__name__}:{exc}")
            return f"after#{len(self._after)}"

        def after_cancel(self, *a):
            return self

        def mainloop(self, *a):
            log.append("mainloop")
            return self

        def columnconfigure(self, *a, **kw):
            return self

        def rowconfigure(self, *a, **kw):
            return self

        def create_rectangle(self, *a, **kw):
            return 1

        def coords(self, *a, **kw):
            return self

        def itemconfigure(self, *a, **kw):
            return self

        # ---- меню ----
        def add_command(self, **kw):
            log.append(f"menu:{kw.get('label')}")
            return self

        def add_cascade(self, **kw):
            log.append(f"cascade:{kw.get('label')}")
            return self

        def add_separator(self, **kw):
            return self

        def add_checkbutton(self, **kw):
            log.append(f"menu-check:{kw.get('label')}")
            return self

        # ---- Treeview ----
        def insert(self, parent, index, *, values=(), tags=(), iid=None):
            key = iid or f"I{len(self._order)}"
            self._items[key] = {"values": tuple(values), "tags": tuple(tags)}
            if index == "end":
                self._order.append(key)
            else:
                self._order.insert(int(index), key)
            return key

        def delete(self, *items):
            for it in items:
                self._items.pop(it, None)
                if it in self._order:
                    self._order.remove(it)
            return self

        def get_children(self, item=None):
            return tuple(self._order)

        def item(self, iid, key=None, **kw):
            rec = self._items.setdefault(iid, {"values": (), "tags": ()})
            if kw:
                rec.update(kw)
                return self
            if key:
                return rec[key]
            return dict(rec)

        def set(self, *a, **kw):
            return self

        def selection_set(self, *iids):
            flat = tuple(i for arg in iids
                         for i in (arg if isinstance(arg, (list, tuple)) else [arg]))
            self._selection = flat
            return self

        def selection(self):
            return self._selection

        def see(self, *a):
            return self

        def tag_configure(self, *a, **kw):
            return self

        def heading(self, *a, **kw):
            return self

        def column(self, *a, **kw):
            return self

        def yview(self, *a):
            return self

    class Var:
        def __init__(self, value="", **kw):
            self._v = value

        def get(self):
            return self._v

        def set(self, v):
            self._v = v

        def trace_add(self, *a, **kw):
            return self

        def __str__(self):
            return str(self._v)

    class BoolVar(Var):
        def __init__(self, value=False, **kw):
            super().__init__(bool(value))

        def get(self):
            return bool(self._v)

    tk = types.ModuleType("tkinter")
    tk.TclError = TclError
    tk.__version__ = "fake"
    for name in ("Tk", "Toplevel", "Frame", "Label", "Button", "Entry",
                 "Checkbutton", "Canvas", "Menu", "LabelFrame", "Scrollbar",
                 "Listbox", "Text", "PanedWindow"):
        setattr(tk, name, Widget)
    tk.StringVar = Var
    tk.BooleanVar = BoolVar
    tk.IntVar = Var
    tk.DoubleVar = Var
    tk.END = "end"
    tk.LEFT = "left"
    tk.RIGHT = "right"
    tk.TOP = "top"
    tk.BOTTOM = "bottom"
    tk.X = "x"
    tk.Y = "y"
    tk.BOTH = "both"
    tk.W = "w"
    tk.E = "e"
    tk.N = "n"
    tk.S = "s"
    tk.CENTER = "center"
    tk.VERTICAL = "vertical"
    tk.HORIZONTAL = "horizontal"
    tk.NORMAL = "normal"
    tk.DISABLED = "disabled"
    tk.SEL = "sel"

    class _Style(Widget):
        def theme_use(self, *a):
            return "clam"

        def map(self, *a, **kw):
            return self

        def layout(self, *a, **kw):
            return self

    ttk = types.ModuleType("tkinter.ttk")
    ttk.Style = _Style
    for name in ("Treeview", "Frame", "Label", "Button", "Entry", "Scrollbar",
                 "Notebook", "Combobox", "Progressbar", "Separator"):
        setattr(ttk, name, Widget)
    tk.ttk = ttk

    fd = types.ModuleType("tkinter.filedialog")
    fd.askopenfilenames = lambda **kw: ()
    fd.askopenfilename = lambda **kw: ""
    fd.asksaveasfilename = lambda **kw: ""
    tk.filedialog = fd

    mb = types.ModuleType("tkinter.messagebox")
    dialogs: list[tuple[str, tuple, dict]] = []
    mb._log = dialogs

    def _rec(kind, answer):
        def f(title="", message="", **kw):
            dialogs.append((kind, (title, message), kw))
            return answer
        return f

    mb.showinfo = _rec("info", True)
    mb.showwarning = _rec("warning", True)
    mb.showerror = _rec("error", True)
    mb.askyesno = _rec("yesno", True)
    mb.askokcancel = _rec("okcancel", True)
    mb.askyesnocancel = _rec("yesnocancel", True)
    tk.messagebox = mb

    tk._mb_log = dialogs
    saved = {k: sys.modules.get(k) for k in
             ("tkinter", "tkinter.ttk", "tkinter.filedialog", "tkinter.messagebox")}
    sys.modules["tkinter"] = tk
    sys.modules["tkinter.ttk"] = ttk
    sys.modules["tkinter.filedialog"] = fd
    sys.modules["tkinter.messagebox"] = mb
    return tk, log, dialogs, saved


def uninstall_fake_tkinter(saved: dict) -> None:
    for k, v in saved.items():
        if v is None:
            sys.modules.pop(k, None)
        else:
            sys.modules[k] = v
    for k in ("gauth.gui", "gauth"):
        sys.modules.pop(k, None)


# ==========================================================================
# тесты
# ==========================================================================
def _gui():
    tk, log, dialogs, saved = install_fake_tkinter()
    try:
        sys.path.insert(0, str(ROOT))
        import importlib

        gui = importlib.import_module("gauth.gui")
        gui._import_tk()      # привязать ленивые tk/ttk/filedialog/messagebox
        return tk, log, dialogs, saved, gui
    except Exception:
        uninstall_fake_tkinter(saved)
        raise


def test_gui_pure_logic():
    tk, log, dialogs, saved, gui = _gui()
    try:
        from gauth.migration import Entry

        rfc_secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"   # ASCII "12345678901234567890"
        entries = [
            Entry(name="octocat", issuer="GitHub", secret=rfc_secret),
            Entry(name="y1", issuer="YubiKey", secret=rfc_secret,
                  kind="hotp", counter=1),
            Entry(name="dev@corp", issuer="Okta", secret="MFRGGZDFMZTWQ2LK",
                  digits=8, period=60),
        ]
        # T=31 -> counter 1 -> код из RFC 4226 (count=1) = 287082, осталось 29 с
        rows = gui.build_rows(entries, now=31.0)
        assert len(rows) == 3
        assert rows[0].label == "GitHub: octocat"
        assert rows[0].code == "287 082" and rows[0].raw == "287082"
        assert rows[0].remaining == 29.0 and rows[0].state == "ok"
        assert rows[0].seconds_text == "29с"
        assert rows[1].state == "counter" and rows[1].seconds_text == "счётчик"
        assert rows[1].raw == "287082"          # HOTP: тот же счётчик 1
        assert abs(rows[0].frac - 1 / 30) < 0.01
        assert rows[2].period == 60 and len(rows[2].raw) == 8

        # состояния по остатку времени
        assert gui.row_state(30.0, 30) == "ok"
        assert gui.row_state(10.0, 30) == "soon"
        assert gui.row_state(3.0, 30) == "critical"
        assert gui.row_state(float("inf"), 30) == "counter"

        # сортировка
        s = gui.sort_entries([Entry(name="b", issuer="Zeta"),
                              Entry(name="a", issuer="Alpha"),
                              Entry(name="c", issuer="")])
        assert [e.issuer for e in s] == ["Alpha", "Zeta", ""]

        # без секретов в строках по умолчанию
        assert all(r.secret == "" for r in gui.build_rows(entries))
        assert gui.build_rows(entries, with_secrets=True)[0].secret

        # диагностика часов
        e = entries[0]
        mine = gui.T.entry_code(e).value
        assert gui.describe_drift(e, mine).startswith("✔")
        assert gui.describe_drift(entries[1], "287082").startswith("Это HOTP")
        nxt = gui.T.entry_code(e, drift=1).value
        assert "спешат" in gui.describe_drift(e, nxt) or "отстают" in gui.describe_drift(e, nxt)
        assert "✖" in gui.describe_drift(e, "000000")
    finally:
        uninstall_fake_tkinter(saved)


def test_gui_app_lifecycle():
    """Полный цикл окна на моке: старт, тикер, импорт, правки, выход."""
    tk, log, dialogs, saved, gui = _gui()
    try:
        from gauth.migration import Entry
        from gauth.vault import Vault

        tmp = Path(tempfile.mkdtemp())
        vault_path = tmp / "vault.enc.json"
        v = Vault(vault_path)
        v.rekey("gui-test-pass")
        v.add(Entry(name="octocat", issuer="GitHub", secret="JBSWY3DPEHPK3PXP"))
        v.add(Entry(name="ivan@gmail.com", issuer="Google", secret="GEZDGNBVGY3TQOJQ"))
        v.add(Entry(name="y1", issuer="YubiKey", secret="JBSWY3DPEHPK3PXP",
                    kind="hotp", counter=5))
        v.save(remember=False)

        # буфер обмена в контейнере недоступен — подменяем, чтобы не мешал
        from gauth import clipboard
        clipboard.copy = lambda text: "fake"          # noqa: E731
        clipboard.copy_and_wipe = lambda text, ttl=25: "fake"  # noqa: E731

        dialogs.clear()
        root = gui.tk.Tk()
        app = gui.App(root, vault_path=str(vault_path), password="gui-test-pass")
        assert app.vault is not None, "хранилище не открылось"
        assert len(app.entries) == 3

        app.refresh_rows()
        children = app.tree.get_children()
        assert len(children) == 3, children
        first = app.tree.item(children[0], "values")
        assert "GitHub" in first[0] and len(first[1]) == 7      # «956 246»

        # выбор строки -> крупный код
        app.tree.selection_set(children[0])
        app.on_select()
        assert app.selected >= 0
        assert app.big_code._values.get("text") not in (None, "— — — — — —")

        # поиск
        app.search_var.set("google")
        app.refresh_rows()
        assert len(app.tree.get_children()) == 1
        app.search_var.set("")
        app.refresh_rows()
        assert len(app.tree.get_children()) == 3

        # копирование
        dialogs.clear()
        app.on_copy()
        assert not [d for d in dialogs if d[0] == "error"], dialogs

        # следующий код / HOTP bump
        app.tree.selection_set(app.tree.get_children()[-1])
        app.on_select()
        entry = app._selected_entry()
        if entry and entry.kind == "hotp":
            before = entry.counter
            app.on_next_code()
            assert app._selected_entry().counter == before + 1

        # тикер не должен падать
        for _ in range(3):
            app._update_codes_in_place()

        dialogs.clear()
        app.on_close()
        assert app._closed

        # --- неверный пароль: спрашивает в окне, а не падает ---
        for var in ("GAUTH_PASSWORD", "GAUTH_PASSWORD_FILE"):
            os.environ.pop(var, None)

        # а) пользователь отменил ввод -> аккуратное закрытие окна, без исключения
        gui.App._ask_password_dialog = lambda self: None
        app2 = gui.App(gui.tk.Tk(), vault_path=str(vault_path),
                       password="definitely-wrong")
        assert app2.vault is None and app2._closed

        # б) ошибся, потом ввёл верно -> хранилище открылось
        gui.App._ask_password_dialog = lambda self: "gui-test-pass"
        app3 = gui.App(gui.tk.Tk(), vault_path=str(vault_path),
                       password="definitely-wrong")
        assert app3.vault is not None and len(app3.entries) == 3
        assert not app3._closed
        app3.on_close()
    finally:
        uninstall_fake_tkinter(saved)


def test_gui_all_handlers_run():
    """«Прокликиваем» все обработчики: ни один не должен упасть."""
    tk, log, dialogs, saved, gui = _gui()
    try:
        from gauth import clipboard
        from gauth.migration import Entry
        from gauth.vault import Vault

        clipboard.copy = lambda text: "fake"                     # noqa: E731
        clipboard.copy_and_wipe = lambda text, ttl=25: "fake"    # noqa: E731

        tmp = Path(tempfile.mkdtemp())
        vault_path = tmp / "vault.enc.json"
        v = Vault(vault_path)
        v.rekey("gui-test-pass")
        v.add(Entry(name="octocat", issuer="GitHub", secret="JBSWY3DPEHPK3PXP"))
        v.add(Entry(name="y1", issuer="YubiKey", secret="JBSWY3DPEHPK3PXP",
                    kind="hotp", counter=2))
        v.save(remember=False)

        app = gui.App(gui.tk.Tk(), vault_path=str(vault_path),
                      password="gui-test-pass")
        assert app.vault is not None
        app.tree.selection_set(app.tree.get_children()[0])
        app.on_select()

        # формы возвращают вменяемые данные; имя каждый раз уникальное,
        # иначе on_add/on_gen спотыкаются о дубликат (и правильно делают)
        counter = {"n": 0}

        def fake_form(title, fields, **kw):
            counter["n"] += 1
            out = {}
            for _label, key, default in fields:
                if key == "digits":
                    out[key] = "6"
                elif key == "period":
                    out[key] = "30"
                elif key == "secret":
                    out[key] = "JBSWY3DPEHPK3PXP"
                elif key == "name":
                    out[key] = f"new-{counter['n']}@mail.com"
                elif key == "issuer":
                    out[key] = f"TestService{counter['n']}"
                elif key in ("old", "new", "again"):
                    out[key] = "gui-test-pass"
                else:
                    out[key] = default
            return out

        app._form_dialog = fake_form
        app._prompt = lambda title, **kw: "123456"
        app._show_qr_for = lambda e, note="": None      # QR-рендер tested elsewhere
        gui.tk.filedialog.asksaveasfilename = lambda **kw: str(tmp / "exp.json")
        gui.tk.filedialog.askopenfilename = lambda **kw: str(
            ROOT / "tests" / "fixtures" / "ga_export_uris.txt")

        dialogs.clear()
        for handler in (app.refresh_rows, app.on_copy, app.on_next_code,
                        app.on_check, app.on_show_qr, app.on_add, app.on_gen,
                        app.on_doctor, app.on_help, app.on_about,
                        app.toggle_secrets, app.on_import_text,
                        lambda: app.on_export(no_secrets=True),
                        lambda: app.on_export(no_secrets=False),
                        app.on_passwd, app.on_delete):
            handler()
            app.refresh_rows()

        errors = [d for d in dialogs if d[0] == "error"]
        assert not errors, [e[1][1][:160] for e in errors]
        assert (tmp / "exp.json").exists(), "экспорт не создал файл"
        app.on_close()
    finally:
        uninstall_fake_tkinter(saved)


def test_gui_import_from_photo():
    """Импорт QR из фото через GUI (поток + очередь задач)."""
    tk, log, dialogs, saved, gui = _gui()
    try:
        import importlib.util
        if importlib.util.find_spec("zxingcpp") is None and \
                importlib.util.find_spec("cv2") is None and \
                importlib.util.find_spec("pyzbar") is None:
            print("  …пропущено: нет бэкенда чтения QR (pip install zxing-cpp pillow)")
            return

        from gauth.vault import Vault

        tmp = Path(tempfile.mkdtemp())
        vault_path = tmp / "vault.enc.json"
        v = Vault(vault_path)
        v.rekey("gui-test-pass")
        v.entries = []
        v.save(remember=False)

        photos = [str(FIXTURES / "phone_photo_typical.jpg"),
                  str(FIXTURES / "phone_rotated_90.png")]
        if not all(Path(p).exists() for p in photos):
            print("  …пропущено: нет фикстур (python3 tests/make_fixtures.py)")
            return

        gui.tk.filedialog.askopenfilenames = lambda **kw: tuple(photos)
        dialogs.clear()
        app = gui.App(gui.tk.Tk(), vault_path=str(vault_path),
                      password="gui-test-pass")
        app.on_import_qr()
        # ждём завершения фонового потока и обрабатываем задачу в тикере
        for _ in range(200):
            if not app._jobs.empty():
                break
            time.sleep(0.05)
        app._tick_once = True
        app._handle_job_from_queue()
        assert len(app.vault.entries) == 2, [e.name for e in app.vault.entries]
        kinds = [d[0] for d in dialogs]
        assert "info" in kinds, dialogs           # показали итог импорта
        assert "warning" in kinds, dialogs        # напомнили удалить фото
        app.on_close()
    finally:
        uninstall_fake_tkinter(saved)


def run_all():
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
    print(f"\n{len(tests) - failed}/{len(tests)} GUI-тестов пройдено")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(run_all())
