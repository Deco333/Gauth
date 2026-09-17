"""Графический интерфейс gauth-pc (tkinter).

Запуск:
    python3 gauth.py gui        # или run.cmd gui / gauth-gui.cmd на Windows
    python3 -m gauth.gui

Дизайн намеренно разделён на два слоя:
  • RowModel / build_rows() — чистая логика (тестируется без tkinter);
  • App — только отрисовка и события.
Вся работа с хранилищем идёт через уже проверенный gauth.vault.
"""

from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from . import clipboard, migration, qr_display, tui
from . import totp as T
from .cli import PROG, _finalize
from .migration import Entry
from .vault import Vault, VaultError, default_vault_path

APP_TITLE = "gauth-pc — коды 2FA"

# tkinter импортируется лениво: без него должны работать --help и диагностика
tk = None
ttk = None
filedialog = None
messagebox = None


def _import_tk() -> None:
    global tk, ttk, filedialog, messagebox
    import tkinter as _tk
    from tkinter import filedialog as _fd, messagebox as _mb, ttk as _ttk

    tk, ttk, filedialog, messagebox = _tk, _ttk, _fd, _mb

# ---------------------------------------------------------------- палитра
BG = "#16181d"
BG_CARD = "#1e2128"
BG_ROW = "#1a1d23"
BG_ALT = "#20242b"
FG = "#e6e8ec"
FG_DIM = "#9aa3af"
ACCENT = "#4f9dff"
GREEN = "#3ddc84"
YELLOW = "#ffc94d"
RED = "#ff6b6b"
SEL_BG = "#2b3444"

IMAGE_HINTS = (("PNG", "*.png"), ("JPEG", "*.jpg *.jpeg"),
               ("Все изображения", "*.png *.jpg *.jpeg *.webp *.bmp"),
               ("Все файлы", "*.*"))


# ==========================================================================
# Слой 1: чистая логика (без tkinter) — тестируется в tests/test_gauth.py
# ==========================================================================
@dataclass
class RowModel:
    """Строка таблицы: всё, что нужно для отрисовки, без виджетов."""

    label: str          # «GitHub: octocat»
    code: str           # «956 246» (с разделителем для читаемости)
    raw: str            # «956246»  (для буфера обмена)
    remaining: float    # секунд до смены; float('inf') для HOTP
    period: int
    frac: float         # 0..1 — доля истёкшего периода
    state: str          # ok | soon | critical | counter
    secret: str = ""
    index: int = -1

    @property
    def seconds_text(self) -> str:
        return "счётчик" if self.remaining == float("inf") else f"{int(self.remaining):02d}с"

    @property
    def color(self) -> str:
        return {"ok": GREEN, "soon": YELLOW, "critical": RED,
                "counter": ACCENT}[self.state]


def row_state(remaining: float, period: int) -> str:
    if remaining == float("inf"):
        return "counter"
    if remaining <= 5:
        return "critical"
    if remaining <= period * 0.34:
        return "soon"
    return "ok"


def build_rows(entries: list[Entry], *, now: float | None = None,
               with_secrets: bool = False) -> list[RowModel]:
    """Список записей -> строки для таблицы. Порядок сохраняется."""
    now = time.time() if now is None else now
    rows: list[RowModel] = []
    for i, e in enumerate(entries):
        c = T.entry_code(e, when=now)
        rows.append(RowModel(
            label=(f"{e.issuer}: {e.name}" if e.issuer else e.name) or "(без имени)",
            code=tui.split_code(c.value),
            raw=c.value,
            remaining=c.remaining,
            period=c.period,
            frac=0.0 if c.remaining == float("inf")
                 else max(0.0, min(1.0, 1.0 - c.remaining / max(1, c.period))),
            state=row_state(c.remaining, c.period),
            secret=e.secret if with_secrets else "",
            index=i,
        ))
    return rows


def sort_entries(entries: list[Entry]) -> list[Entry]:
    """Стабильная сортировка: эмитент, затем имя (пустой эмитент — в конец)."""
    return sorted(entries, key=lambda e: ((e.issuer or "\uffff").lower(), e.name.lower()))


def describe_drift(entry: Entry, phone_code: str) -> str:
    """Человеческое объяснение расхождения часов (для кнопки «Сверить»)."""
    phone_code = (phone_code or "").strip()
    mine = T.entry_code(entry).value
    if not phone_code:
        return "Введите код, который сейчас показывает телефон."
    if entry.kind == "hotp":
        return ("Это HOTP: коды не зависят от времени, они привязаны к счётчику. "
                f"Текущий счётчик: {entry.counter}. Если коды расходятся — "
                "нажмите «Следующий счётчик» столько раз, сколько нужно.")
    if phone_code == mine:
        return ("✔ Коды совпадают — часы в норме. Если сайт всё равно не принимает "
                "код, он, скорее всего, успел истечь: дождитесь нового "
                "(полоска внизу).")
    drift = T.drift_estimate(entry.secret, phone_code, period=entry.period,
                             digits=entry.digits, algorithm=entry.algo, window=40)
    if drift is None:
        return ("✖ Такой код не находится ни в одном соседнем окне. Возможно, это "
                "код другого аккаунта, либо секрет импортирован неверно.")
    seconds = drift * entry.period
    where = "спешат" if seconds > 0 else "отстают"
    fix = {
        "win32": "Параметры → Время и язык → Дата и время → «Синхронизировать сейчас» "
                 "(или в cmd от администратора: w32tm /resync)",
        "darwin": "Системные настройки → Основные → Дата и время → «Устанавливать "
                  "автоматически»",
    }.get(sys.platform, "sudo timedatectl set-ntp true   (проверка: timedatectl)")
    return (f"✖ Часы на компьютере {where} примерно на {abs(seconds)} с "
            f"({drift:+d} × {entry.period} с).\n\nКак исправить:\n{fix}")


def check_tkinter() -> str | None:
    """None — всё хорошо; иначе текст понятной ошибки."""
    import importlib.util

    if importlib.util.find_spec("tkinter") is not None:
        return None
    if True:
        if sys.platform.startswith("win"):
            return ("Не установлен tkinter (графическая библиотека Python).\n\n"
                    "Windows: запустите установщик Python с python.org → "
                    "«Modify» → убедитесь, что отмечен пункт «tcl/tk and IDLE».\n"
                    "Либо пользуйтесь терминальной версией: run.cmd codes")
        if sys.platform == "darwin":
            return ("Не установлен tkinter. Используйте python.org-сборку Python "
                    "(в ней он есть) или: brew install python-tk\n"
                    "Либо терминальная версия: ./run.sh codes")
        return ("Не установлен tkinter: sudo apt install python3-tk "
                "(Fedora: python3-tkinter, Arch: tk)\n"
                "Либо терминальная версия: ./run.sh codes")


# ==========================================================================
# Слой 2: отрисовка
# ==========================================================================
class App:
    REFRESH_MS = 250

    def __init__(self, root: "tk.Tk", *, vault_path: str | None = None):
        self.root = root
        self.vault_path = Path(vault_path) if vault_path else default_vault_path()
        self.vault: Vault | None = None
        self.entries: list[Entry] = []
        self.selected: int = -1          # индекс в self.entries
        self._iid_by_index: dict[int, str] = {}
        self._dirty = False
        self._jobs: "queue.Queue" = queue.Queue()
        self._show_secrets = False
        self._tick_id: str | None = None
        self._closed = False

        self._setup_window()
        self._build_widgets()
        self._bind_keys()

        self.root.after(60, self._startup)
        self._tick()

    # ---------------------------------------------------------------- окно
    def _setup_window(self) -> None:
        if sys.platform.startswith("win"):
            try:  # чёткий текст на экранах с масштабированием
                import ctypes

                ctypes.windll.shcore.SetProcessDpiAwareness(1)
            except Exception:
                pass
        self.root.title(APP_TITLE)
        self.root.configure(bg=BG)
        self.root.geometry("780x560")
        self.root.minsize(560, 400)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.f_title = ("Segoe UI", 10) if sys.platform.startswith("win") \
            else ("Helvetica", 11)
        self.f_small = ("Segoe UI", 9) if sys.platform.startswith("win") \
            else ("Helvetica", 9)
        self.f_label = ("Segoe UI", 11) if sys.platform.startswith("win") \
            else ("Helvetica", 12)
        self.f_code = ("Consolas", 52, "bold") if sys.platform.startswith("win") \
            else ("Menlo", 48, "bold")

    # ------------------------------------------------------------- виджеты
    def _build_widgets(self) -> None:
        # переменные создаём ДО меню: на них ссылается пункт «Показывать секреты»
        self.search_var = tk.StringVar()
        self.secrets_var = tk.BooleanVar(value=False)
        self._build_menu()

        # --- панель инструментов
        bar = tk.Frame(self.root, bg=BG)
        bar.pack(side="top", fill="x", padx=10, pady=(10, 6))

        tk.Label(bar, text="Поиск", bg=BG, fg=FG_DIM,
                 font=self.f_title).pack(side="left")
        self.search_var.trace_add("write", lambda *_: self.refresh_rows())
        ent = tk.Entry(bar, textvariable=self.search_var, bg=BG_CARD, fg=FG,
                       insertbackground=FG, relief="flat", font=self.f_title,
                       width=26)
        ent.pack(side="left", padx=(8, 12), ipady=4)
        self.search_entry = ent

        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        for text, cmd in (("📷  Импорт QR…", self.on_import_qr),
                          ("➕  Добавить…", self.on_add),
                          ("📋  Копировать", self.on_copy),
                          ("⏱  Сверить с телефоном", self.on_check),
                          ("🔄", self.refresh_rows)):
            b = tk.Button(bar, text=text, command=cmd, bg=BG_CARD, fg=FG,
                          activebackground=SEL_BG, activeforeground=FG,
                          relief="flat", font=self.f_small, padx=10, pady=4,
                          cursor="hand2", highlightthickness=0)
            b.pack(side="left", padx=3)

        tk.Checkbutton(bar, text="секреты", variable=self.secrets_var,
                       command=self.toggle_secrets, bg=BG, fg=FG_DIM,
                       selectcolor=BG_CARD, activebackground=BG,
                       activeforeground=FG, font=self.f_small,
                       highlightthickness=0).pack(side="right")

        # --- таблица
        wrap = tk.Frame(self.root, bg=BG)
        wrap.pack(side="top", fill="both", expand=True, padx=10)

        cols = ("account", "code", "left")
        self.tree = ttk.Treeview(wrap, columns=cols, show="headings",
                                 selectmode="browse", style="Gauth.Treeview")
        style.configure("Gauth.Treeview", background=BG_ROW, fieldbackground=BG_ROW,
                        foreground=FG, rowheight=30, font=self.f_title,
                        borderwidth=0)
        style.configure("Gauth.Treeview.Heading", background=BG_CARD, foreground=FG_DIM,
                        font=self.f_small, relief="flat")
        style.map("Gauth.Treeview", background=[("selected", SEL_BG)],
                  foreground=[("selected", FG)])
        self.tree.heading("account", text="АККАУНТ", anchor="w")
        self.tree.heading("code", text="КОД", anchor="w")
        self.tree.heading("left", text="ОБНОВЛЕНИЕ", anchor="e")
        self.tree.column("account", width=290, anchor="w", stretch=True)
        self.tree.column("code", width=150, anchor="w", stretch=False)
        self.tree.column("left", width=90, anchor="e", stretch=False)
        for tag, col in (("ok", GREEN), ("soon", YELLOW),
                         ("critical", RED), ("counter", ACCENT)):
            self.tree.tag_configure(tag, foreground=col)

        vsb = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        self.tree.bind("<Double-1>", lambda _e: self.on_copy())
        self.tree.bind("<Return>", lambda _e: self.on_copy())
        # Контекстное меню для копирования и сохранения QR
        self.context_menu = tk.Menu(self.root, tearoff=0, bg=BG_CARD, fg=FG,
                                    activebackground=SEL_BG, activeforeground=FG)
        self.context_menu.add_command(label="Копировать код", command=self.on_copy)
        self.context_menu.add_command(label="Сохранить QR…", command=self.on_save_qr)
        self.context_menu.add_command(label="Показать QR", command=self.on_show_qr)
        self.tree.bind("<Button-3>", self._show_context_menu)

        # --- крупный код выбранного аккаунта
        card = tk.Frame(self.root, bg=BG_CARD)
        card.pack(side="top", fill="x", padx=10, pady=8)
        self.big_label = tk.Label(card, text="—", bg=BG_CARD, fg=FG_DIM,
                                  font=self.f_label, anchor="w")
        self.big_label.pack(fill="x", padx=14, pady=(10, 0))
        self.big_code = tk.Label(card, text="— — — — — —", bg=BG_CARD, fg=GREEN,
                                 font=self.f_code, anchor="w")
        self.big_code.pack(fill="x", padx=10)
        self.progress = tk.Canvas(card, height=6, bg=BG, highlightthickness=0,
                                  bd=0)
        self.progress.pack(fill="x", padx=14, pady=(0, 12))
        self._bar = self.progress.create_rectangle(0, 0, 0, 6, fill=GREEN, width=0)

        # --- строка состояния
        status = tk.Frame(self.root, bg=BG)
        status.pack(side="bottom", fill="x", padx=10, pady=(0, 8))
        self.status_var = tk.StringVar(value="Загрузка…")
        tk.Label(status, textvariable=self.status_var, bg=BG, fg=FG_DIM,
                 font=self.f_small, anchor="w").pack(side="left", fill="x",
                                                     expand=True)
        tk.Label(status, text=f"{self.vault_path}", bg=BG, fg="#5c6470",
                 font=self.f_small, anchor="e").pack(side="right")

    def _build_menu(self) -> None:
        m = tk.Menu(self.root, bg=BG_CARD, fg=FG, activebackground=SEL_BG,
                    activeforeground=FG, bd=0, tearoff=0)
        file_menu = tk.Menu(m, bg=BG_CARD, fg=FG, activebackground=SEL_BG,
                            activeforeground=FG, tearoff=0)
        file_menu.add_command(label="Импорт QR из Google Authenticator…",
                              command=self.on_import_qr)
        file_menu.add_command(label="Импорт из файла (otpauth:// или TSV)…",
                              command=self.on_import_text)
        file_menu.add_command(label="Импорт из бэкапа Aegis / 2FAS…",
                              command=self.on_import_aegis)
        file_menu.add_separator()
        file_menu.add_command(label="Добавить секрет вручную…", command=self.on_add)
        file_menu.add_command(label="Сгенерировать новый секрет…", command=self.on_gen)
        file_menu.add_command(label="Удалить выбранную запись", command=self.on_delete)
        file_menu.add_separator()
        file_menu.add_command(label="Экспорт (без секретов)…",
                              command=lambda: self.on_export(no_secrets=True))
        file_menu.add_command(label="Экспорт (СЕКРЕТЫ, осторожно!)…",
                              command=lambda: self.on_export(no_secrets=False))
        file_menu.add_separator()
        file_menu.add_command(label="Сменить пароль хранилища…", command=self.on_passwd)
        file_menu.add_command(label="Показать папку с хранилищем",
                              command=self.reveal_vault)
        file_menu.add_separator()
        file_menu.add_command(label="Выход", command=self.on_close)
        m.add_cascade(label="Файл", menu=file_menu)

        view_menu = tk.Menu(m, bg=BG_CARD, fg=FG, activebackground=SEL_BG,
                            activeforeground=FG, tearoff=0)
        view_menu.add_command(label="Копировать код выбранного аккаунта",
                              command=self.on_copy)
        view_menu.add_command(label="Следующий код (если текущий истекает)",
                              command=self.on_next_code)
        view_menu.add_command(label="Показать QR выбранной записи…",
                              command=self.on_show_qr)
        view_menu.add_separator()
        view_menu.add_checkbutton(label="Показывать секреты",
                                  variable=self.secrets_var,
                                  command=self.toggle_secrets)
        m.add_cascade(label="Действия", menu=view_menu)

        help_menu = tk.Menu(m, bg=BG_CARD, fg=FG, activebackground=SEL_BG,
                            activeforeground=FG, tearoff=0)
        help_menu.add_command(label="Как перенести коды с телефона…",
                              command=self.on_help)
        help_menu.add_command(label="Диагностика (часы, зависимости)…",
                              command=self.on_doctor)
        help_menu.add_command(label="О программе", command=self.on_about)
        m.add_cascade(label="Справка", menu=help_menu)
        self.root.config(menu=m)

    def _bind_keys(self) -> None:
        self.root.bind("<Control-c>", lambda _e: self.on_copy_simple())
        self.root.bind("<Control-C>", lambda _e: self.on_copy_simple())
        self.root.bind("<Control-f>", lambda _e: self.search_entry.focus_set())
        self.root.bind("<Control-l>", lambda _e: self.refresh_rows())
        self.root.bind("<Escape>", lambda _e: self.search_var.set(""))
        self.root.bind("<Delete>", lambda _e: self.on_delete())

    # ------------------------------------------------------------ загрузка
    def _startup(self) -> None:
        if not self.vault_path.exists():
            if not messagebox.askyesno(
                    "Хранилище не найдено",
                    f"Файл {self.vault_path} отсутствует.\n\n"
                    "Создать новое зашифрованное хранилище сейчас?\n"
                    "(после этого можно импортировать QR из Google Authenticator)"):
                self.on_close()
                return
            if not self._dialog_init():
                self.on_close()
                return
        try:
            self._open_vault()
        except SystemExit:
            self.on_close()

    def _open_vault(self) -> None:
        """Открывает хранилище без пароля."""
        try:
            self.vault = Vault.open(self.vault_path)
        except VaultError as exc:
            messagebox.showerror("Не удалось открыть хранилище", str(exc))
            raise SystemExit(0)
        
        self.entries = sort_entries(self.vault.entries)
        self.status_var.set(f"Хранилище открыто: {len(self.entries)} записей")
        self.refresh_rows()

    def _ask_password_dialog(self) -> str | None:
        dlg = tk.Toplevel(self.root)
        dlg.title("Пароль хранилища")
        dlg.configure(bg=BG)
        dlg.resizable(False, False)
        dlg.transient(self.root)
        dlg.grab_set()
        tk.Label(dlg, text="Введите пароль хранилища", bg=BG, fg=FG,
                 font=self.f_title).pack(padx=24, pady=(20, 6), anchor="w")
        var = tk.StringVar()
        e = tk.Entry(dlg, textvariable=var, show="●", bg=BG_CARD, fg=FG,
                     insertbackground=FG, relief="flat", font=self.f_title,
                     width=32)
        e.pack(padx=24, ipady=5)
        e.focus_set()
        err = tk.Label(dlg, text="", bg=BG, fg=RED, font=self.f_small)
        err.pack(padx=24, anchor="w")

        def ok(_=None):
            dlg.destroy()

        e.bind("<Return>", ok)
        tk.Button(dlg, text="Открыть", command=ok, bg=ACCENT, fg="#0b0d10",
                  relief="flat", font=self.f_title, padx=16, pady=5,
                  cursor="hand2").pack(pady=(6, 20))
        dlg.wait_window()
        return var.get() or None

    def _dialog_init(self) -> bool:
        """Создание хранилища без пароля."""
        try:
            vault = Vault(self.vault_path)
            vault.entries = []
            vault.save()
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Ошибка", f"Не удалось создать хранилище: {exc}")
            return False
        self.vault = vault
        result = {"ok": True}
        
        if result["ok"]:
            self.entries = []
            self.status_var.set("Хранилище создано. Теперь импортируйте QR.")
            self.refresh_rows()
            messagebox.showinfo(
                "Готово",
                "Хранилище создано.\n\nДальше: на телефоне откройте Google "
                "Authenticator → ⋮ → «Перенос аккаунтов» → «Экспорт аккаунтов», "
                "сфотографируйте QR вторым устройством и нажмите "
                "«📷 Импорт QR…».")
        return result["ok"]

    # -------------------------------------------------------------- таблица
    def _current_entries(self) -> list[Entry]:
        q = self.search_var.get().strip() if hasattr(self, "search_var") else ""
        if not q or not self.vault:
            return self.entries
        found = self.vault.search(q)
        return found

    def refresh_rows(self) -> None:
        if self._closed or self.vault is None or not hasattr(self, "tree"):
            return
        entries = self._current_entries()
        self.tree.delete(*self.tree.get_children())
        self._iid_by_index = {}
        rows = build_rows(entries, with_secrets=self._show_secrets)
        for r, e in zip(rows, entries):
            real = self.entries.index(e) if e in self.entries else r.index
            iid = self.tree.insert(
                "", "end",
                values=(r.label, r.code, r.seconds_text), tags=(r.state,))
            self._iid_by_index[real] = iid
        self._update_selection(entries)
        n = len(rows)
        if n == 0:
            self.status_var.set("Пусто. Нажмите «📷 Импорт QR…» или "
                                "«➕ Добавить…»." if not self.search_var.get()
                                else "Ничего не найдено по этому запросу.")
        else:
            self.status_var.set(f"{n} записей   •   Ctrl+C — копировать код, "
                                f"Ctrl+F — поиск, Del — удалить")
        self._render_big()

    def _update_selection(self, entries: list[Entry]) -> None:
        children = self.tree.get_children()
        if not children:
            self.selected = -1
            return
        if self.selected >= 0:
            iid = self._iid_by_index.get(self.selected)
            if iid and iid in children:
                self.tree.selection_set(iid)
                self.tree.see(iid)
                return
        self.tree.selection_set(children[0])

    def on_select(self, _event=None) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        iid = sel[0]
        for idx, i in self._iid_by_index.items():
            if i == iid:
                self.selected = idx
                break
        self._render_big()

    def _show_context_menu(self, event) -> None:
        """Показывает контекстное меню по правому клику."""
        # Выбираем элемент под курсором
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            # Обновляем selected индекс
            for idx, i in self._iid_by_index.items():
                if i == item:
                    self.selected = idx
                    break
            self._render_big()
        # Показываем меню
        try:
            self.context_menu.post(event.x_root, event.y_root)
        except Exception:
            pass

    def _selected_entry(self) -> Entry | None:
        if self.vault is None or not (0 <= self.selected < len(self.vault.entries)):
            return None
        return self.vault.entries[self.selected]

    def _render_big(self) -> None:
        e = self._selected_entry()
        if e is None:
            self.big_label.config(text="—")
            self.big_code.config(text="— — — — — —", fg=FG_DIM)
            self.progress.coords(self._bar, 0, 0, 0, 6)
            return
        c = T.entry_code(e)
        label = f"{e.issuer}: {e.name}" if e.issuer else e.name
        if self._show_secrets:
            label += f"   ·   {e.secret}"
        self.big_label.config(text=label)
        self.big_code.config(text=tui.split_code(c.value))
        self._bar_state = row_state(c.remaining, c.period)
        color = {"ok": GREEN, "soon": YELLOW, "critical": RED,
                 "counter": ACCENT}[self._bar_state]
        self.big_code.config(fg=color)
        self.progress.itemconfigure(self._bar, fill=color)
        self._big_code_raw = c.value
        self._big_remaining = c.remaining
        self._big_period = c.period
        self._update_progress()

    def _update_progress(self) -> None:
        if not hasattr(self, "progress"):
            return
        try:
            width = max(1, self.progress.winfo_width())
        except tk.TclError:
            width = 1
        rem = getattr(self, "_big_remaining", float("inf"))
        per = getattr(self, "_big_period", 30) or 30
        frac = 0.0 if rem == float("inf") else max(0.0, min(1.0, 1.0 - rem / per))
        self.progress.coords(self._bar, 0, 0, int(width * frac), 6)

    # ------------------------------------------------------------- тикер
    def _tick(self) -> None:
        if self._closed:
            return
        self._handle_job_from_queue()
        self._update_codes_in_place()
        self._tick_id = self.root.after(self.REFRESH_MS, self._tick)

    def _handle_job_from_queue(self) -> None:
        """Разбирает результаты фоновых задач (импорт QR и т.п.)."""
        while True:
            try:
                kind, payload = self._jobs.get_nowait()
            except queue.Empty:
                return
            self._handle_job(kind, payload)

    def _update_codes_in_place(self) -> None:
        """Обновляем только значения, без пересборки таблицы (иначе мигает)."""
        if self.vault is None or self._closed:
            return
        entries = self._current_entries()
        rows = build_rows(entries, with_secrets=self._show_secrets)
        children = self.tree.get_children()
        if len(children) != len(rows):
            self.refresh_rows()
            return
        for iid, r in zip(children, rows):
            vals = self.tree.item(iid, "values")
            new = (r.label, r.code, r.seconds_text)
            if tuple(vals) != new:
                self.tree.item(iid, values=new)
            if self.tree.item(iid, "tags") != (r.state,):
                self.tree.item(iid, tags=(r.state,))
        # крупный код
        e = self._selected_entry()
        if e is not None:
            c = T.entry_code(e)
            if getattr(self, "_big_code_raw", None) != c.value:
                self._render_big()
            else:
                self._big_remaining = c.remaining
                state = row_state(c.remaining, c.period)
                color = {"ok": GREEN, "soon": YELLOW, "critical": RED,
                         "counter": ACCENT}[state]
                self.big_code.config(fg=color)
                self.progress.itemconfigure(self._bar, fill=color)
                self._update_progress()

    # ------------------------------------------------------------- импорт
    def on_import_qr(self) -> None:
        if self.vault is None:
            return
        paths = filedialog.askopenfilenames(
            title="Выберите фото/скриншоты QR из Google Authenticator",
            filetypes=IMAGE_HINTS)
        if not paths:
            return
        self.status_var.set(f"Распознаю {len(paths)} файл(ов)…")
        self.root.update_idletasks()
        threading.Thread(target=self._import_worker, args=(list(paths),),
                         daemon=True).start()

    def _import_worker(self, paths: list[str]) -> None:
        try:
            from . import qr as qrmod

            texts: list[str] = []
            errors: list[str] = []
            for p in paths:
                try:
                    texts.extend(qrmod.decode_image(p))
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"{Path(p).name}: {str(exc).splitlines()[0]}")
            entries: list[Entry] = []
            batches: dict[tuple[int, int], migration.MigrationPayload] = {}
            for text in texts:
                try:
                    payload = migration.from_migration_uri(text)
                except migration.MigrationError as exc:
                    errors.append(str(exc))
                    continue
                batches[(payload.batch_id, payload.batch_index)] = payload
                entries.extend(payload.entries)
            uniq: dict[tuple[str, str, str], Entry] = {}
            for e in entries:
                e = _finalize(e)
                uniq.setdefault((e.secret, e.name, e.issuer), e)
            self._jobs.put(("import", (list(uniq.values()), errors, batches)))
        except Exception as exc:  # noqa: BLE001
            self._jobs.put(("error", f"Импорт не удался: {exc}"))

    def _handle_job(self, kind: str, payload) -> None:
        if kind == "error":
            self.status_var.set("Ошибка")
            messagebox.showerror("gauth-pc", str(payload))
            return
        if kind == "import":
            entries, errors, batches = payload
            if not entries:
                self.status_var.set("Ничего не распознано")
                messagebox.showwarning(
                    "QR не распознан",
                    "Не удалось извлечь ни одной записи.\n\n" +
                    ("\n".join(errors[:5]) if errors else "") +
                    "\n\nЧто делать:\n"
                    "• Переснимите QR крупнее и резче, при хорошем свете;\n"
                    "• Экран экспорта Android запрещает скриншоты — нужно фото "
                    "вторым устройством или вебкой;\n"
                    "• Установите бэкенд распознавания: "
                    "pip install zxing-cpp pillow;\n"
                    "• Либо отсканируйте QR сторонним сканером и вставьте текст "
                    "ссылки: Файл → Импорт из текста.")
                return
            added, skipped = self.vault.add_many(entries, replace=False)
            self._save()
            self.entries = sort_entries(self.vault.entries)
            self.refresh_rows()
            notes = []
            if batches:
                declared = max((b.batch_size for b in batches.values()), default=1)
                have = {b.batch_index for b in batches.values()}
                missing = [i for i in range(declared) if i not in have]
                if missing:
                    notes.append(
                        "⚠ Не хватает частей экспорта: " +
                        ", ".join(f"#{i + 1}/{declared}" for i in missing) +
                        ".\nGoogle Authenticator показывает QR по очереди — "
                        "сфотографируйте остальные и повторите импорт.")
            text = (f"Добавлено записей: {added}\n"
                    f"Пропущено дубликатов: {skipped}\n"
                    f"Всего в хранилище: {len(self.vault.entries)}\n")
            if errors:
                text += "\nПредупреждения:\n" + "\n".join(errors[:5])
            if notes:
                text += "\n" + "\n".join(notes)
            self.status_var.set(f"Импортировано: {added}")
            messagebox.showinfo("Импорт завершён", text)
            self._remind_delete_photos()

    def _remind_delete_photos(self) -> None:
        messagebox.showwarning(
            "Удалите фото QR",
            "QR из Google Authenticator содержит секретные ключи ВСЕХ ваших "
            "аккаунтов.\n\nУдалите фотографии с компьютера, из мессенджера, "
            "почты и с телефона, которым снимали.\n\nКоды уже работают на ПК — "
            "фото больше не нужны.")

    def on_import_text(self) -> None:
        if self.vault is None:
            return
        path = filedialog.askopenfilename(
            title="Файл со ссылками otpauth:// или TSV (secret<TAB>name)",
            filetypes=(("Текст", "*.txt *.csv *.tsv"), ("Все файлы", "*.*")))
        if not path:
            return
        try:
            src = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            messagebox.showerror("Ошибка", str(exc))
            return
        entries, errors = [], []
        for lineno, line in enumerate(src.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                if line.lower().startswith("otpauth"):
                    entries.append(_finalize(migration.from_otpauth_uri(line)))
                else:
                    parts = [p for p in line.split("\t") if p.strip()]
                    if len(parts) < 2:
                        raise ValueError("нужно secret<TAB>name[<TAB>issuer]")
                    entries.append(_finalize(Entry(
                        secret=parts[0], name=parts[1],
                        issuer=parts[2] if len(parts) > 2 else "",
                        source="text-import")))
            except Exception as exc:  # noqa: BLE001
                errors.append(f"строка {lineno}: {exc}")
        if not entries:
            messagebox.showwarning("Пусто", "Не удалось разобрать ни одной строки.\n" +
                                   "\n".join(errors[:5]))
            return
        added, skipped = self.vault.add_many(entries, replace=False)
        self._save()
        self.entries = sort_entries(self.vault.entries)
        self.refresh_rows()
        messagebox.showinfo("Импорт", f"Добавлено: {added}, пропущено: {skipped}\n" +
                            ("\n".join(errors[:5]) if errors else ""))

    def on_import_aegis(self) -> None:
        if self.vault is None:
            return
        path = filedialog.askopenfilename(
            title="Бэкап Aegis / 2FAS (JSON)",
            filetypes=(("JSON", "*.json"), ("Все файлы", "*.*")))
        if not path:
            return
        try:
            from .cli import _aegis_decrypt  # переиспользуем логику CLI

            import json
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
            db = raw.get("db", raw)
            if db.get("encrypted") or raw.get("header", {}).get("encryption") \
                    not in (None, "none"):
                pw = self._prompt("Пароль от бэкапа Aegis", show="●")
                if pw is None:
                    return
                db = _aegis_decrypt(raw, pw)
            entries = [_finalize(Entry(
                name=item.get("name") or item.get("info", {}).get("account") or "",
                issuer=item.get("issuer") or "",
                secret=item.get("info", {}).get("secret", ""),
                algo=(item.get("info", {}).get("algo") or "SHA1").upper(),
                digits=int(item.get("info", {}).get("digits") or 6),
                period=int(item.get("info", {}).get("period") or 30),
                kind=str(item.get("type", "totp")).lower(),
                counter=int(item.get("info", {}).get("counter") or 0),
                source="aegis")) for item in db.get("entries", [])]
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Импорт Aegis", str(exc))
            return
        if not entries:
            messagebox.showwarning("Пусто", "В бэкапе нет записей.")
            return
        added, skipped = self.vault.add_many(entries, replace=False)
        self._save()
        self.entries = sort_entries(self.vault.entries)
        self.refresh_rows()
        messagebox.showinfo("Импорт Aegis", f"Добавлено: {added}, пропущено: {skipped}")

    # ------------------------------------------------------------- записи
    def on_add(self) -> None:
        if self.vault is None:
            return
        values = self._form_dialog(
            "Добавить аккаунт",
            [("Аккаунт (например ivan@gmail.com)", "name", ""),
             ("Сервис (Google, GitHub…)", "issuer", ""),
             ("Секретный ключ (base32)", "secret", ""),
             ("Цифр в коде", "digits", "6"),
             ("Период, секунд", "period", "30"),
             ("Steam Guard (5 символов)", "steam", "")])
        if not values:
            return
        try:
            e = _finalize(Entry(
                name=values["name"] or "(без имени)", issuer=values["issuer"],
                secret=values["secret"], digits=int(values["digits"] or 6),
                period=int(values["period"] or 30),
                steam=str(values.get("steam")) == "True", source="manual"))
            self.vault.add(e, replace=False)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Не добавлено", str(exc))
            return
        self._save()
        self.entries = sort_entries(self.vault.entries)
        self.selected = self.vault.entries.index(e)
        self.refresh_rows()
        self.status_var.set(f"Добавлено: {e.name}")

    def on_gen(self) -> None:
        if self.vault is None:
            return
        secret = T.random_secret(20)
        values = self._form_dialog(
            "Новый секрет для 2FA",
            [("Аккаунт", "name", ""), ("Сервис", "issuer", "Service"),
             ("Секрет (сгенерирован)", "secret", secret),
             ("Цифр в коде", "digits", "6"),
             ("Период, секунд", "period", "30")],
            note="Введите этот ключ на сайте при включении 2FA (пункт «ввести "
                 "ключ вручную») или отсканируйте QR из окна записи.")
        if not values:
            return
        try:
            e = _finalize(Entry(name=values["name"] or "(без имени)",
                                issuer=values["issuer"], secret=values["secret"],
                                digits=int(values["digits"] or 6),
                                period=int(values["period"] or 30),
                                source="generated"))
            self.vault.add(e, replace=False)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Ошибка", str(exc))
            return
        self._save()
        self.entries = sort_entries(self.vault.entries)
        self.refresh_rows()
        self._show_qr_for(e, note="Отсканируйте этот QR на сайте при включении 2FA.")

    def on_delete(self) -> None:
        e = self._selected_entry()
        if e is None or self.vault is None:
            return
        if not messagebox.askyesno(
                "Удалить запись",
                f"Удалить «{(e.issuer + ': ' if e.issuer else '') + e.name}»?\n\n"
                "Коды этого аккаунта исчезнут с компьютера (на телефоне всё "
                "останется, если вы не удаляли их там)."):
            return
        idx = self.vault.entries.index(e)
        self.vault.remove(idx)
        self._save()
        self.entries = sort_entries(self.vault.entries)
        self.selected = min(self.selected, max(0, len(self.entries) - 1))
        self.refresh_rows()
        self.status_var.set("Запись удалена")

    def toggle_secrets(self) -> None:
        self._show_secrets = bool(self.secrets_var.get())
        self.refresh_rows()

    # ------------------------------------------------------------ действия
    def on_copy(self) -> None:
        e = self._selected_entry()
        if e is None:
            self.status_var.set("Выберите аккаунт в списке")
            return
        code = T.entry_code(e).value
        try:
            clipboard.copy_and_wipe(code, ttl=25)
            self.status_var.set(f"Скопировано {code} — буфер очистится через 25 с")
        except clipboard.ClipboardError as exc:
            messagebox.showerror("Буфер обмена", str(exc))

    def on_copy_simple(self, event=None) -> None:
        """Копирует код выделенной записи в буфер обмена (для Ctrl+C)."""
        # Проверяем, есть ли выделение в дереве
        selection = self.tree.selection()
        if not selection:
            return
        # Получаем индекс выбранного элемента
        item = selection[0]
        for idx, iid in self._iid_by_index.items():
            if iid == item:
                e = self.entries[idx]
                code = T.entry_code(e).value
                try:
                    clipboard.copy_and_wipe(code, ttl=25)
                    self.status_var.set(f"Скопировано {code} — буфер очистится через 25 с")
                except clipboard.ClipboardError:
                    pass
                break

    def on_next_code(self) -> None:
        e = self._selected_entry()
        if e is None:
            return
        if e.kind == "hotp":
            e.counter += 1
            self._save()
            self.refresh_rows()
            self.status_var.set(f"HOTP: счётчик увеличен до {e.counter}")
            return
        nxt = T.entry_code(e, drift=1)
        try:
            clipboard.copy_and_wipe(nxt.value, ttl=25)
            self.status_var.set(
                f"Следующий код {nxt.value} скопирован (начнёт действовать через "
                f"{int(nxt.remaining)} с)")
        except clipboard.ClipboardError:
            self.status_var.set(f"Следующий код: {nxt.value}")

    def on_check(self) -> None:
        e = self._selected_entry()
        if e is None:
            messagebox.showinfo("Сверка", "Сначала выберите аккаунт в списке.")
            return
        phone = self._prompt(
            f"Код с телефона для «{(e.issuer + ': ' if e.issuer else '') + e.name}»",
            note="Перепишите сюда код, который сейчас показывает Google "
                 "Authenticator, — программа сравнит его со своим и найдёт "
                 "расхождение часов.")
        if phone is None:
            return
        result = describe_drift(e, phone)
        if result.startswith("✔"):
            messagebox.showinfo("Сверка часов", result)
        else:
            messagebox.showwarning("Сверка часов", result)

    def on_show_qr(self) -> None:
        e = self._selected_entry()
        if e is None:
            return
        self._show_qr_for(e)

    def on_save_qr(self) -> None:
        """Сохраняет QR-код выбранной записи в PNG файл."""
        e = self._selected_entry()
        if e is None:
            self.status_var.set("Выберите аккаунт в списке")
            return
        uri = qr_display.otpauth_uri(e)
        path = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=(("PNG", "*.png"), ("JPEG", "*.jpg *.jpeg")),
            title="Сохранить QR-код")
        if not path:
            return
        try:
            qr_display.save_png(uri, path)
            self.status_var.set(f"QR-код сохранён: {path}")
            messagebox.showinfo("Готово", f"QR-код успешно сохранён:\n{path}")
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Ошибка", f"Не удалось сохранить QR-код:\n{exc}")

    def _show_qr_for(self, e: Entry, note: str = "") -> None:
        uri = qr_display.otpauth_uri(e)
        try:
            art = qr_display.render_terminal(uri)
        except RuntimeError as exc:
            messagebox.showinfo(
                "QR", f"{exc}\n\nСсылка для ручного переноса:\n{uri}")
            return
        win = tk.Toplevel(self.root)
        win.title(f"QR — {(e.issuer + ': ' if e.issuer else '') + e.name}")
        win.configure(bg="white")
        tk.Label(win, text=note or "Отсканируйте этот QR, чтобы перенести запись "
                                   "на телефон или другой компьютер.",
                 bg="white", fg="#333", font=self.f_small, wraplength=420,
                 justify="left").pack(padx=12, pady=(12, 4))
        # Создаём текстовое поле с QR-кодом для возможности копирования
        qr_text = tk.Text(win, bg="white", fg="black",
                          font=("Courier", 5), wrap="none",
                          height=min(30, art.count('\n') + 2),
                          width=min(80, max(len(line) for line in art.split('\n')) + 2))
        qr_text.insert("1.0", art)
        qr_text.config(state="normal")  # Разрешаем выделение для копирования
        qr_text.pack(padx=12)
        btns = tk.Frame(win, bg="white")
        btns.pack(pady=10)

        def save_png():
            path = filedialog.asksaveasfilename(
                defaultextension=".png", filetypes=(("PNG", "*.png"),),
                title="Сохранить QR")
            if not path:
                return
            try:
                qr_display.save_png(uri, path)
                self.status_var.set(f"QR сохранён: {path}")
            except Exception as exc:  # noqa: BLE001
                messagebox.showerror("Ошибка", str(exc))

        def copy_uri():
            try:
                clipboard.copy(uri)
                self.status_var.set("Ссылка otpauth:// скопирована")
            except clipboard.ClipboardError as exc:
                messagebox.showerror("Буфер обмена", str(exc))

        # Добавляем возможность копирования самого QR-кода (текстовой ссылки)
        def copy_code():
            try:
                clipboard.copy(e.secret)
                self.status_var.set("Секрет скопирован в буфер обмена")
            except clipboard.ClipboardError as exc:
                messagebox.showerror("Буфер обмена", str(exc))

        tk.Button(btns, text="Сохранить PNG…", command=save_png, padx=12,
                  pady=4).pack(side="left", padx=4)
        tk.Button(btns, text="Скопировать ссылку", command=copy_uri, padx=12,
                  pady=4).pack(side="left", padx=4)
        tk.Button(btns, text="Скопировать секрет", command=copy_code, padx=12,
                  pady=4).pack(side="left", padx=4)
        tk.Button(btns, text="Закрыть", command=win.destroy, padx=12,
                  pady=4).pack(side="left", padx=4)

    # -------------------------------------------------------------- сервис
    def on_export(self, *, no_secrets: bool) -> None:
        if self.vault is None:
            return
        if not no_secrets and not messagebox.askyesno(
                "Внимание",
                "Экспорт будет содержать СЕКРЕТНЫЕ КЛЮЧИ в открытом виде.\n"
                "Любой, кто получит этот файл, сможет генерировать ваши коды.\n\n"
                "Продолжить?"):
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json", filetypes=(("JSON", "*.json"),),
            title="Экспорт записей")
        if not path:
            return
        import json
        data = [{"name": e.name, "issuer": e.issuer, "type": e.kind,
                 "algo": e.algo, "digits": e.digits, "period": e.period,
                 "counter": e.counter, "steam": e.steam, "note": e.note,
                 **({} if no_secrets else {"secret": e.secret})}
                for e in self.vault.entries]
        try:
            Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2),
                                  encoding="utf-8")
            os.chmod(path, 0o600)
        except OSError as exc:
            messagebox.showerror("Ошибка", str(exc))
            return
        self.status_var.set(f"Экспорт: {path}")
        messagebox.showinfo("Экспорт", f"Сохранено: {path}\n"
                            + ("" if no_secrets else
                               "\n⚠ Файл содержит секреты. Удалите его после "
                               "использования."))

    def on_passwd(self) -> None:
        """Метод устарел: шифрование отключено."""
        messagebox.showinfo("Информация", 
            "Шифрование отключено. Хранилище сохраняется в открытом виде\n"
            "с правами доступа 0600 (только ваш пользователь).")

    def on_doctor(self) -> None:
        lines = [f"Хранилище: {self.vault_path}",
                 f"Записей: {len(self.vault.entries) if self.vault else 0}",
                 f"Локальное время: {time.strftime('%Y-%m-%d %H:%M:%S')} "
                 f"(UTC{time.strftime('%z')})", ""]
        for mod, hint in (("cryptography", "обязателен"),
                          ("keyring", "pip install keyring — не спрашивать пароль"),
                          ("pyqrcode", "pip install pyqrcode — QR в окне записи"),
                          ("zxingcpp", "pip install zxing-cpp pillow — чтение QR"),
                          ("cv2", "pip install opencv-python — чтение QR"),
                          ("pyzbar", "pip install pyzbar pillow — чтение QR"),
                          ("pyperclip", "pip install pyperclip — буфер обмена")):
            try:
                __import__(mod)
                lines.append(f"✔ {mod}")
            except ImportError:
                lines.append(f"– {mod}: не установлен ({hint})")
        e = self._selected_entry()
        if e is not None:
            c = T.entry_code(e)
            d = T.drift_estimate(e.secret, c.value, period=e.period,
                                 digits=e.digits, algorithm=e.algo)
            lines.append(f"\nСамопроверка на «{e.name}»: код {c.value}, drift={d} "
                         "(0 = часы в норме)")
        messagebox.showinfo("Диагностика", "\n".join(lines))

    def on_help(self) -> None:
        messagebox.showinfo(
            "Как перенести коды с телефона",
            "1. На телефоне: Google Authenticator → ⋮ → «Перенос аккаунтов» →\n"
            "   «Экспорт аккаунтов» → пройти проверку.\n"
            "2. Появится QR-код. Если аккаунтов много — несколько QR подряд\n"
            "   («1 из 3», «2 из 3»…). Снимите каждый.\n"
            "3. Скриншот на Android НЕ делается (защита экрана) — фотографируйте\n"
            "   вторым телефоном или вебкой: ровно, при хорошем свете, чтобы QR\n"
            "   занимал почти весь кадр.\n"
            "4. Перекиньте фото на ПК и нажмите «📷 Импорт QR…».\n"
            "5. Удалите фото: в них лежат ключи от всех ваших аккаунтов.\n\n"
            "Если фото не читается: установите pip install zxing-cpp pillow\n"
            "или отсканируйте QR сторонним сканером и вставьте текст ссылки\n"
            "(Файл → Импорт из файла).")

    def on_about(self) -> None:
        messagebox.showinfo(
            "О программе",
            f"{APP_TITLE}\n\n"
            "Коды считаются локально по RFC 6238 (TOTP/HOTP), интернет не\n"
            "используется. Секреты хранятся в одном файле, зашифрованном\n"
            "вашим паролем (scrypt + Fernet/AES).\n\n"
            f"Хранилище: {self.vault_path}\n"
            "Лицензия MIT.")

    def reveal_vault(self) -> None:
        folder = str(self.vault_path.parent)
        try:
            if sys.platform.startswith("win"):
                os.startfile(folder)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", folder])
            else:
                subprocess.Popen(["xdg-open", folder])
        except Exception:
            messagebox.showinfo("Папка", folder)

    # ------------------------------------------------------------- утилиты
    def _prompt(self, title: str, *, show: str | None = None,
                note: str = "") -> str | None:
        dlg = tk.Toplevel(self.root)
        dlg.title(title)
        dlg.configure(bg=BG)
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.resizable(False, False)
        tk.Label(dlg, text=title, bg=BG, fg=FG,
                 font=self.f_title).pack(padx=24, pady=(18, 4), anchor="w")
        if note:
            tk.Label(dlg, text=note, bg=BG, fg=FG_DIM, font=self.f_small,
                     wraplength=360, justify="left").pack(padx=24, anchor="w")
        var = tk.StringVar()
        e = tk.Entry(dlg, textvariable=var, show=show or "", bg=BG_CARD, fg=FG,
                     insertbackground=FG, relief="flat", font=self.f_title,
                     width=34)
        e.pack(padx=24, pady=(10, 6), ipady=5)
        e.focus_set()
        res: dict[str, str | None] = {"v": None}

        def ok(_=None):
            res["v"] = var.get()
            dlg.destroy()

        e.bind("<Return>", ok)
        row = tk.Frame(dlg, bg=BG)
        row.pack(pady=(4, 18))
        tk.Button(row, text="OK", command=ok, bg=ACCENT, fg="#0b0d10",
                  relief="flat", padx=16, pady=4, cursor="hand2").pack(side="left",
                                                                       padx=4)
        tk.Button(row, text="Отмена", command=dlg.destroy, bg=BG_CARD, fg=FG,
                  relief="flat", padx=16, pady=4, cursor="hand2").pack(side="left",
                                                                       padx=4)
        dlg.wait_window()
        return res["v"]

    def _form_dialog(self, title: str, fields: list[tuple[str, str, str]], *,
                     password_fields: tuple[str, ...] = (),
                     note: str = "") -> dict[str, str] | None:
        """Простая форма: [(подпись, ключ, значение_по_умолчанию), …].

        Ключ "steam" автоматически становится чекбоксом; ключи из
        password_fields маскируются точками.
        """
        dlg = tk.Toplevel(self.root)
        dlg.title(title)
        dlg.configure(bg=BG)
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.resizable(False, False)
        tk.Label(dlg, text=title, bg=BG, fg=FG,
                 font=self.f_title).pack(padx=24, pady=(18, 4), anchor="w")
        if note:
            tk.Label(dlg, text=note, bg=BG, fg=FG_DIM, font=self.f_small,
                     wraplength=380, justify="left").pack(padx=24, anchor="w")
        vars_: "dict[str, tk.Variable]" = {}
        for label, key, default in fields:
            if key == "steam":
                var = tk.BooleanVar(value=False)
                tk.Checkbutton(dlg, text=label, variable=var, bg=BG, fg=FG,
                               selectcolor=BG_CARD, activebackground=BG,
                               activeforeground=FG, font=self.f_small,
                               highlightthickness=0).pack(padx=24, anchor="w",
                                                          pady=(6, 0))
                vars_[key] = var
                continue
            tk.Label(dlg, text=label, bg=BG, fg=FG_DIM,
                     font=self.f_small).pack(padx=24, pady=(8, 1), anchor="w")
            var = tk.StringVar(value=default)
            tk.Entry(dlg, textvariable=var, bg=BG_CARD, fg=FG,
                     insertbackground=FG, relief="flat", font=self.f_title,
                     width=38,
                     show="●" if key in password_fields else "").pack(
                         padx=24, ipady=4, anchor="w")
            vars_[key] = var
        res: "dict[str, str] | None" = None

        def ok():
            nonlocal res
            res = {k: (str(v.get()) if isinstance(v, tk.BooleanVar) else v.get())
                   for k, v in vars_.items()}
            dlg.destroy()

        row = tk.Frame(dlg, bg=BG)
        row.pack(pady=16)
        tk.Button(row, text="OK", command=ok, bg=ACCENT, fg="#0b0d10",
                  relief="flat", padx=18, pady=5, cursor="hand2").pack(side="left",
                                                                       padx=4)
        tk.Button(row, text="Отмена", command=dlg.destroy, bg=BG_CARD, fg=FG,
                  relief="flat", padx=18, pady=5, cursor="hand2").pack(side="left",
                                                                        padx=4)
        dlg.wait_window()
        return res

    def _save(self) -> None:
        if self.vault is None:
            return
        try:
            self.vault.save(remember=True)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Не удалось сохранить", str(exc))

    def on_close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._tick_id:
            try:
                self.root.after_cancel(self._tick_id)
            except Exception:
                pass
        try:
            if self.vault is not None and self.vault.dirty:
                self.vault.save(remember=True)
        except Exception:
            pass
        try:
            self.root.destroy()
        except tk.TclError:
            pass


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(prog=f"{PROG} gui",
                                 description="Графический интерфейс gauth-pc")
    ap.add_argument("--vault", default=None, help="путь к файлу хранилища")
    args = ap.parse_args(argv)

    problem = check_tkinter()
    if problem:
        print(problem, file=sys.stderr)
        return 2
    _import_tk()

    try:
        root = tk.Tk()
    except tk.TclError as exc:
        print(f"Не удалось создать окно: {exc}\n{check_tkinter() or ''}",
              file=sys.stderr)
        return 2

    app = App(root, vault_path=args.vault)
    if args.selftest:
        root.after(int(args.selftest * 1000), app.on_close)
    try:
        root.mainloop()
    except KeyboardInterrupt:
        app.on_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
