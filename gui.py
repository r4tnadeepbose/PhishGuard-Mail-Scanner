import datetime
import json
import os
from pathlib import Path
import queue
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog

from phishguard.scanner import scan_email, scan_email_file
from phishguard.parser import parse_email_text
from phishguard.report import (
    result_to_json,
    result_to_html,
    results_batch_to_json,
    results_batch_to_html,
    write_text,
)
from phishguard.investigation import scan_result_to_investigation, case_to_json
from phishguard.whitelist import (
    add_exact_rule,
    validate_whitelist,
    whitelist_summary,
    WhitelistError,
)
from phishguard.integrations.registry import DEFAULT_REGISTRY
from phishguard.integrations.base import IntegrationStatus


APP_TITLE = "PhishGuard Mail Scanner"
# Navy dashboard palette: pale blue canvas, white cards, deep navy sidebar/header,
# navy primary buttons, and amber highlight. Soft, modern dashboard look.
OFFICE_BG = "#EDF2F9"           # pale blue-gray canvas
OFFICE_PANEL = "#FFFFFF"        # white cards
OFFICE_CARD = "#F8FBFF"         # near-white card interior
OFFICE_SIDEBAR = "#0B2545"      # deep navy sidebar
OFFICE_SIDEBAR_SELECT = "#1C4C7E"
OFFICE_SIDEBAR_TEXT = "#EAF2FB"
OFFICE_SIDEBAR_MUTED = "#9FB8D6"
OFFICE_HEADER = "#0B2545"       # navy header bar
OFFICE_HEADER_TEXT = "#FFFFFF"
OFFICE_HEADER_MUTED = "#A9C1DE"
OFFICE_TEXT = "#14213D"         # navy ink
OFFICE_MUTED = "#5B6B85"        # muted blue-gray
OFFICE_ACCENT = "#123C69"       # navy primary
OFFICE_ACCENT_DARK = "#0B2A4A"
OFFICE_ACCENT_SOFT = "#DCE8F6"  # pale blue fill
OFFICE_BORDER = "#D6E2F0"       # hairline blue border
OFFICE_BORDER_DARK = "#B9CCE2"
OFFICE_BORDER_LIGHT = "#FFFFFF"
OFFICE_TAB = "#E4EDF8"
OFFICE_BTN = "#FFFFFF"
OFFICE_BTN_ACTIVE = "#E6EFF9"
OFFICE_BTN_PRESSED = "#D2E1F2"
OFFICE_INPUT = "#FBFDFF"
OFFICE_DARKBAR = "#0B2545"
OFFICE_DARKTEXT = "#EAF2FB"
OFFICE_SELECT = "#DCE8F6"       # selected list rows
OFFICE_AMBER = "#F3B33D"
VERDICT_COLORS = {
    "Low Risk": "#40587A",
    "Suspicious": "#A66A12",
    "Medium Risk": "#A66A12",
    "High Risk": "#B23A2A",
    "Critical": "#8E2318",
    "Critical Risk": "#8E2318",
}


class PhishGuardApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1280x880")
        self.minsize(1040, 700)

        self.last_result = None
        self.last_result_source = ""
        self.current_case = None
        self.history = []  # list of dicts: result, raw source, investigation case
        self.batch_results = []
        self.batch_cases = []
        self.batch_files = []
        self.analysis_log = []
        self.batch_running = False
        self._batch_cancel = threading.Event()
        self._batch_queue = queue.Queue()
        self._batch_worker = None
        self._batch_started = 0
        self._batch_result_objects = {}
        self._batch_case_objects = {}

        self.use_default_whitelist = tk.BooleanVar(value=True)
        self.custom_whitelist_path = tk.StringVar(value="")
        self.ml_enabled = tk.BooleanVar(value=True)
        self.status_var = tk.StringVar(value="Ready. Paste Gmail 'Show original' raw source, or load a file, then scan.")
        self.verdict_var = tk.StringVar(value="Verdict: --")
        self.score_var = tk.StringVar(value="Score: --")
        self.summary_var = tk.StringVar(value="No scan yet.")
        # Dashboard metric cards (Scan & Report)
        self.metric_risk_var = tk.StringVar(value="--")
        self.metric_risk_label_var = tk.StringVar(value="No scan")
        self.metric_findings_var = tk.StringVar(value="--")
        self.metric_urls_var = tk.StringVar(value="--")
        self.metric_auth_var = tk.StringVar(value="--")
        self.session_scans_var = tk.StringVar(value="0 scans")
        # Email header / summary panel
        self.verdict_pill_var = tk.StringVar(value="No scan")
        self.summary_risk_var = tk.StringVar(value="-- / 100")
        self.summary_findings_var = tk.StringVar(value="0")
        self.summary_urls_var = tk.StringVar(value="0")
        self.summary_attach_var = tk.StringVar(value="0")
        self._finding_cards = []
        self._selected_finding_text = ""

        self._configure_style()
        self._build_ui()
        self._refresh_whitelist_status()
        self._bind_shortcuts()

    def _retro_button(self, parent, **kwargs):
        """Flat dashboard button with visible press/click feedback."""
        text = kwargs.pop("text", "")
        command = kwargs.pop("command", None)
        primary = kwargs.pop("primary", False)
        bg = kwargs.pop("bg", OFFICE_ACCENT if primary else OFFICE_BTN)
        fg = kwargs.pop("fg", "#FFFFFF" if primary else OFFICE_ACCENT_DARK)
        btn_font = kwargs.pop("font", ("Segoe UI", 9))
        padx = kwargs.pop("padx", 12)
        pady = kwargs.pop("pady", 6)
        active_bg = OFFICE_ACCENT_DARK if primary else OFFICE_BTN_ACTIVE
        pressed_bg = OFFICE_ACCENT_DARK if primary else OFFICE_BTN_PRESSED
        btn = tk.Button(
            parent,
            text=text,
            command=command,
            bg=bg,
            fg=fg,
            activebackground=active_bg,
            activeforeground=fg,
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground=bg if primary else OFFICE_BORDER,
            highlightcolor=OFFICE_ACCENT,
            padx=padx,
            pady=pady,
            font=btn_font,
            cursor="hand2",
            **kwargs,
        )
        def _on_press(_e):
            try:
                btn.configure(bg=pressed_bg)
            except Exception:
                pass
        def _on_release(_e):
            try:
                btn.configure(bg=bg)
            except Exception:
                pass
        btn.bind("<ButtonPress-1>", _on_press, add="+")
        btn.bind("<ButtonRelease-1>", _on_release, add="+")
        btn.bind("<Leave>", _on_release, add="+")
        return btn

    def _configure_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        try:
            self.configure(bg=OFFICE_BG)
        except Exception:
            pass

        base_font = ("Segoe UI", 9)
        title_font = ("Segoe UI Semibold", 16)
        self.option_add("*Font", base_font)
        self.option_add("*Background", OFFICE_BG)
        self.option_add("*Foreground", OFFICE_TEXT)
        self.option_add("*selectBackground", OFFICE_SELECT)
        self.option_add("*selectForeground", OFFICE_ACCENT_DARK)
        self.option_add("*Text.background", OFFICE_INPUT)
        self.option_add("*Text.foreground", OFFICE_TEXT)
        self.option_add("*Text.insertBackground", OFFICE_TEXT)
        self.option_add("*Listbox.background", OFFICE_INPUT)
        self.option_add("*Listbox.foreground", OFFICE_TEXT)

        style.configure(".", background=OFFICE_BG, foreground=OFFICE_TEXT, font=base_font)
        style.configure("TFrame", background=OFFICE_BG)
        style.configure("HeaderBar.TFrame", background=OFFICE_HEADER)
        style.configure("Toolbar.TFrame", padding=(0, 0), background=OFFICE_BG)
        style.configure("TLabelframe", background=OFFICE_PANEL, bordercolor=OFFICE_BORDER, relief="solid", borderwidth=1)
        style.configure("TLabelframe.Label", background=OFFICE_PANEL, foreground=OFFICE_MUTED, font=("Segoe UI Semibold", 9))
        style.configure("Card.TLabelframe", padding=10, background=OFFICE_PANEL)
        style.configure("TLabel", background=OFFICE_BG, foreground=OFFICE_TEXT)
        style.configure("Header.TLabel", font=title_font, foreground=OFFICE_HEADER_TEXT, background=OFFICE_HEADER)
        style.configure("SubHeader.TLabel", font=("Segoe UI", 9), foreground=OFFICE_HEADER_MUTED, background=OFFICE_HEADER)
        style.configure("HeaderMeta.TLabel", font=("Segoe UI Semibold", 8), foreground=OFFICE_ACCENT_DARK, background=OFFICE_ACCENT_SOFT, padding=(10, 4))
        style.configure("Verdict.TLabel", font=("Segoe UI Semibold", 22), background=OFFICE_PANEL)
        style.configure("Score.TLabel", font=("Segoe UI Semibold", 11), foreground=OFFICE_ACCENT_DARK, background=OFFICE_PANEL)
        style.configure("MetricTitle.TLabel", font=("Segoe UI Semibold", 8), foreground=OFFICE_MUTED, background=OFFICE_PANEL)
        style.configure("MetricValue.TLabel", font=("Segoe UI Semibold", 17), foreground=OFFICE_TEXT, background=OFFICE_PANEL)
        style.configure("MetricHint.TLabel", font=("Segoe UI", 8), foreground=OFFICE_MUTED, background=OFFICE_PANEL)
        style.configure("Badge.TLabel", font=("Segoe UI Semibold", 9), background=OFFICE_ACCENT_SOFT, foreground=OFFICE_ACCENT_DARK, padding=(10, 4))
        style.configure("Status.TLabel", font=("Segoe UI", 9), foreground=OFFICE_DARKTEXT, background=OFFICE_ACCENT_DARK, padding=(14, 7))
        style.configure("StatusBar.TFrame", background=OFFICE_ACCENT_DARK)

        style.configure("TNotebook", background=OFFICE_PANEL, borderwidth=0)
        style.configure("TNotebook.Tab", padding=(14, 7), font=("Segoe UI", 9), background=OFFICE_TAB, foreground=OFFICE_MUTED, borderwidth=0)
        style.map(
            "TNotebook.Tab",
            background=[("selected", OFFICE_PANEL), ("!selected", OFFICE_TAB), ("active", OFFICE_ACCENT_SOFT)],
            foreground=[("selected", OFFICE_ACCENT), ("!selected", OFFICE_MUTED)],
            expand=[("selected", [0, 0, 0, 0])],
        )

        # ttk buttons kept for any fallback; primary buttons use _retro_button
        style.configure("TButton", padding=(10, 5), font=("Segoe UI", 9), background=OFFICE_BTN, foreground=OFFICE_ACCENT_DARK, borderwidth=1, relief="flat")
        style.map(
            "TButton",
            background=[("pressed", OFFICE_BTN_PRESSED), ("active", OFFICE_BTN_ACTIVE), ("!active", OFFICE_BTN)],
            foreground=[("disabled", OFFICE_MUTED), ("!disabled", OFFICE_ACCENT_DARK)],
            relief=[("pressed", "flat"), ("!pressed", "flat")],
        )
        style.configure("TCheckbutton", background=OFFICE_BG, foreground=OFFICE_TEXT, font=("Segoe UI", 9))
        style.map("TCheckbutton", background=[("active", OFFICE_BG)])
        style.configure("Sidebar.TFrame", background=OFFICE_SIDEBAR)
        style.configure("SidebarTitle.TLabel", background=OFFICE_SIDEBAR, foreground=OFFICE_SIDEBAR_MUTED, font=("Segoe UI Semibold", 8))
        style.configure("SidebarMuted.TLabel", background=OFFICE_SIDEBAR, foreground=OFFICE_SIDEBAR_MUTED, font=("Segoe UI", 8))
        style.configure("Sidebar.TCheckbutton", background=OFFICE_SIDEBAR, foreground=OFFICE_SIDEBAR_TEXT, font=("Segoe UI", 9))
        style.map("Sidebar.TCheckbutton", background=[("active", OFFICE_SIDEBAR)], foreground=[("active", "#FFFFFF")])
        style.configure("Toolbar.TCheckbutton", background=OFFICE_PANEL, foreground=OFFICE_TEXT, font=("Segoe UI", 9))
        style.map("Toolbar.TCheckbutton", background=[("active", OFFICE_PANEL)], foreground=[("active", OFFICE_ACCENT_DARK)])
        style.configure("Brand.TLabel", background=OFFICE_SIDEBAR, foreground="#FFFFFF", font=("Segoe UI Semibold", 14))
        style.configure("BrandSub.TLabel", background=OFFICE_SIDEBAR, foreground=OFFICE_SIDEBAR_MUTED, font=("Segoe UI", 8))
        style.configure("TCombobox", padding=4, fieldbackground=OFFICE_INPUT, background=OFFICE_BTN, bordercolor=OFFICE_BORDER, arrowcolor=OFFICE_ACCENT_DARK)

        style.configure("Treeview", background=OFFICE_INPUT, fieldbackground=OFFICE_INPUT, foreground=OFFICE_TEXT, bordercolor=OFFICE_BORDER, rowheight=26, font=("Segoe UI", 9), borderwidth=0, relief="flat")
        style.configure("Treeview.Heading", background="#EEF3FA", foreground=OFFICE_MUTED, font=("Segoe UI Semibold", 8), relief="flat", borderwidth=0)
        style.map("Treeview", background=[("selected", OFFICE_SELECT)], foreground=[("selected", OFFICE_ACCENT_DARK)])
        style.configure("TSeparator", background=OFFICE_BORDER)
        style.configure("Vertical.TScrollbar", background=OFFICE_ACCENT_SOFT, troughcolor=OFFICE_INPUT, bordercolor=OFFICE_INPUT, arrowcolor=OFFICE_ACCENT_DARK)
        style.configure("Horizontal.TScrollbar", background=OFFICE_ACCENT_SOFT, troughcolor=OFFICE_INPUT, bordercolor=OFFICE_INPUT, arrowcolor=OFFICE_ACCENT_DARK)

    def _build_ui(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        header = ttk.Frame(self, padding=(24, 14, 24, 10), style="HeaderBar.TFrame")
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(0, weight=1)
        title_wrap = tk.Frame(header, bg=OFFICE_HEADER)
        title_wrap.grid(row=0, column=0, sticky="w")
        ttk.Label(title_wrap, text="PhishGuard Mail Scanner", style="Header.TLabel").pack(anchor="w")
        ttk.Label(
            title_wrap,
            text="Local phishing triage for Gmail 'Show original'  •  paste, scan, investigate, export",
            style="SubHeader.TLabel",
        ).pack(anchor="w", pady=(2, 0))
        self.whitelist_status_var = tk.StringVar(value="")
        meta_wrap = tk.Frame(header, bg=OFFICE_HEADER)
        meta_wrap.grid(row=0, column=1, sticky="e")
        tk.Label(meta_wrap, textvariable=self.session_scans_var, bg=OFFICE_ACCENT_SOFT, fg=OFFICE_ACCENT_DARK,
                 font=("Segoe UI Semibold", 9), padx=10, pady=4).pack(side="top", anchor="e")
        ttk.Label(meta_wrap, textvariable=self.whitelist_status_var, style="HeaderMeta.TLabel").pack(side="top", anchor="e", pady=(4, 0))

        toolbar = tk.Frame(self, bg=OFFICE_PANEL, highlightbackground=OFFICE_BORDER, highlightthickness=1, bd=0)
        toolbar.grid(row=1, column=0, sticky="ew", padx=24, pady=(10, 0))
        self._build_toolbar(toolbar)

        body = ttk.Panedwindow(self, orient="horizontal")
        body.grid(row=2, column=0, sticky="nsew", padx=24, pady=(10, 12))

        sidebar = tk.Frame(body, bg=OFFICE_SIDEBAR, highlightbackground=OFFICE_SIDEBAR, highlightthickness=1, bd=0)
        body.add(sidebar, weight=0)
        self._build_sidebar(sidebar)

        main = ttk.Frame(body)
        body.add(main, weight=1)
        main.columnconfigure(0, weight=1)
        main.rowconfigure(0, weight=0)
        main.rowconfigure(1, weight=1)

        # Compact inbox strip (scanned messages)
        mail_panel = ttk.Frame(main)
        mail_panel.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        self._build_message_list(mail_panel)

        # Main notebook workspace (email-scoped tabs live inside Scan & Report)
        self.notebook = ttk.Notebook(main)
        self.notebook.grid(row=1, column=0, sticky="nsew")

        self.tab_scan = ttk.Frame(self.notebook, padding=8)
        self.tab_details = ttk.Frame(self.notebook, padding=10)
        self.tab_log = ttk.Frame(self.notebook, padding=10)
        self.tab_batch = ttk.Frame(self.notebook, padding=10)
        self.tab_reports = ttk.Frame(self.notebook, padding=10)
        self.tab_help = ttk.Frame(self.notebook, padding=10)
        # Email-scoped content frames are created in _build_reading_pane as children of email_notebook
        self.tab_message = None
        self.tab_findings = None
        self.tab_observables = None
        self.tab_source = None

        self.notebook.add(self.tab_scan, text="Scan & Report")
        self.notebook.add(self.tab_details, text="Details & Case")
        self.notebook.add(self.tab_log, text="Activity")
        self.notebook.add(self.tab_batch, text="Batch Scan")
        self.notebook.add(self.tab_reports, text="History & Export")
        self.notebook.add(self.tab_help, text="Help")

        # Build non-scan tabs; scan layout will create email-scoped tabs and populate them
        self._build_details_tab()
        self._build_log_tab()
        self._build_batch_tab()
        self._build_reports_tab()
        self._build_help_tab()
        self._build_scan_tab()

        self.folder_list.bind("<<ListboxSelect>>", self._on_folder_select)
        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)
        self.after(120, lambda: self._safe_sash(body, 220))

        status = ttk.Frame(self, style="StatusBar.TFrame")
        status.grid(row=3, column=0, sticky="ew")
        status.columnconfigure(0, weight=1)
        ttk.Label(status, textvariable=self.status_var, style="Status.TLabel", anchor="w").grid(row=0, column=0, sticky="ew")

        # Realistic loaded state (demo phishing email) so panels show real content
        self.after(250, self._load_demo_state)

    def _safe_sash(self, paned, position):
        try:
            paned.sashpos(0, position)
        except Exception:
            pass

    def _bind_shortcuts(self):
        shortcuts = {
            "<Control-o>": self.open_file,
            "<Control-s>": self.save_input,
            "<Control-Return>": self.scan_current,
            "<Control-Shift-V>": self.paste_and_scan,
            "<Control-e>": self.export_json,
            "<Control-j>": self.export_case,
            "<Control-h>": lambda: self.notebook.select(self.tab_help),
            "<F1>": lambda: self.notebook.select(self.tab_help),
        }
        for sequence, callback in shortcuts.items():
            try:
                self.bind_all(sequence, lambda _e, cb=callback: (cb(), "break")[1])
            except Exception:
                pass

    def _build_sidebar(self, parent):
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(2, weight=1)
        parent.rowconfigure(3, weight=0)

        brand = tk.Frame(parent, bg=OFFICE_SIDEBAR)
        brand.grid(row=0, column=0, sticky="ew", padx=14, pady=(16, 10))
        logo = tk.Canvas(brand, width=36, height=36, bg=OFFICE_SIDEBAR, highlightthickness=0, bd=0)
        logo.create_oval(1, 1, 35, 35, fill=OFFICE_ACCENT_SOFT, outline="")
        logo.create_text(18, 18, text="P", fill=OFFICE_ACCENT_DARK, font=("Segoe UI Semibold", 15))
        logo.grid(row=0, column=0, rowspan=2, sticky="w", padx=(0, 10))
        ttk.Label(brand, text="PhishGuard", style="Brand.TLabel").grid(row=0, column=1, sticky="w")
        ttk.Label(brand, text="Mail Scanner", style="BrandSub.TLabel").grid(row=1, column=1, sticky="w")

        ttk.Label(parent, text="NAVIGATION", style="SidebarTitle.TLabel").grid(row=1, column=0, sticky="w", padx=16, pady=(6, 4))

        self.folder_list = tk.Listbox(
            parent, activestyle="none", exportselection=False,
            font=("Segoe UI", 10), bg=OFFICE_SIDEBAR, fg=OFFICE_SIDEBAR_TEXT,
            selectbackground=OFFICE_ACCENT_SOFT, selectforeground=OFFICE_ACCENT_DARK,
            relief="flat", bd=0, highlightthickness=0,
        )
        self.folder_list.grid(row=2, column=0, sticky="nsew", padx=10, pady=(0, 8))
        nav_items = [
            ("  ◉  Scan & report", "Scan & Report"),
            ("  ▤  Details & case", "Details & Case"),
            ("  ⚠  Findings", "Findings"),
            ("  👁  Observables", "Observables"),
            ("  ⟨⟩  Source", "Source"),
            ("  ↺  History & export", "History & Export"),
            ("  ▥  Batch scan", "Batch Scan"),
        ]
        self._nav_target = {}
        for label, target in nav_items:
            self.folder_list.insert("end", label)
            self._nav_target[label] = target
        self.folder_list.selection_set(0)

        # Bottom-pinned config & safety
        bottom = tk.Frame(parent, bg=OFFICE_SIDEBAR)
        bottom.grid(row=3, column=0, sticky="ew")
        bottom.columnconfigure(0, weight=1)

        wl = tk.Frame(bottom, bg=OFFICE_CARD, highlightbackground=OFFICE_BORDER, highlightthickness=1)
        wl.grid(row=0, column=0, sticky="ew", padx=10, pady=(6, 8))
        wl.columnconfigure(0, weight=1)
        ttk.Label(wl, text="Whitelist", style="MetricTitle.TLabel", background=OFFICE_CARD).grid(row=0, column=0, sticky="w", padx=10, pady=(8, 2))
        ttk.Label(wl, textvariable=self.whitelist_status_var, style="SidebarMuted.TLabel", background=OFFICE_CARD, wraplength=170).grid(row=1, column=0, sticky="w", padx=10)
        ttk.Checkbutton(wl, text="Use whitelist.json", variable=self.use_default_whitelist, command=self._refresh_whitelist_status).grid(row=2, column=0, sticky="w", padx=8, pady=(4,0))
        self._retro_button(wl, text="Choose whitelist", command=self.choose_whitelist, font=("Segoe UI", 8), padx=6, pady=4).grid(row=3, column=0, sticky="ew", padx=10, pady=(6, 10))

        safety = tk.Frame(bottom, bg="#E7F6EE", highlightbackground="#BFE3CF", highlightthickness=1)
        safety.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 12))
        ttk.Label(safety, text="Local only", background="#E7F6EE", foreground="#1F7A4D", font=("Segoe UI Semibold", 9)).grid(row=0, column=0, sticky="w", padx=10, pady=(8, 2))
        tk.Label(safety, text="No links opened. No attachments executed.\nAuth headers are unverified claims.", bg="#E7F6EE", fg="#2F5D46", font=("Segoe UI", 8), justify="left", wraplength=170).grid(row=1, column=0, sticky="w", padx=10, pady=(0, 10))

    def _build_message_list(self, parent):
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=1)
        self.mail_frame = ttk.LabelFrame(parent, text="Scanned Messages (double-click to reopen)", style="Card.TLabelframe", padding=4)
        self.mail_frame.grid(row=0, column=0, sticky="nsew")
        self.mail_frame.columnconfigure(0, weight=1)
        self.mail_frame.rowconfigure(0, weight=1)
        cols = ("time", "from", "subject", "verdict", "score")
        self.mail_tree = ttk.Treeview(self.mail_frame, columns=cols, show="headings", height=4)
        for c, t, w, anchor in [
            ("time", "Time", 70, "w"),
            ("from", "From", 240, "w"),
            ("subject", "Subject", 520, "w"),
            ("verdict", "Verdict", 110, "w"),
            ("score", "Score", 60, "center"),
        ]:
            self.mail_tree.heading(c, text=t)
            self.mail_tree.column(c, width=w, anchor=anchor, stretch=(c in ("from", "subject")))
        y = ttk.Scrollbar(self.mail_frame, orient="vertical", command=self.mail_tree.yview)
        self.mail_tree.configure(yscrollcommand=y.set)
        self.mail_tree.grid(row=0, column=0, sticky="nsew")
        y.grid(row=0, column=1, sticky="ns")
        self.mail_tree.bind("<Double-1>", self._on_mail_double_click)
        self.mail_tree.tag_configure("low", foreground=VERDICT_COLORS["Low Risk"])
        self.mail_tree.tag_configure("suspicious", foreground=VERDICT_COLORS["Suspicious"])
        self.mail_tree.tag_configure("high", foreground=VERDICT_COLORS["High Risk"])
        self.mail_tree.tag_configure("critical", foreground=VERDICT_COLORS["Critical"], font=("Segoe UI Semibold", 9))

    def _auth_state_color(self, label, value):
        v = str(value or "unknown").lower()
        if label in ("SPF", "DKIM", "DMARC"):
            if v in ("pass", "passed"):
                return "#1F7A4D", "#E7F6EE"
            if v in ("fail", "failed", "softfail", "hardfail", "temperror", "permerror"):
                return "#B23A2A", "#FBE7E4"
            if v in ("none", "neutral", "unknown", ""):
                return "#A66A12", "#FCF0D8"
        return OFFICE_MUTED, OFFICE_ACCENT_SOFT

    def _set_auth_badges(self, spf="unknown", dkim="unknown", dmarc="unknown"):
        for label, val, widget in (
            ("SPF", spf, getattr(self, "badge_spf", None)),
            ("DKIM", dkim, getattr(self, "badge_dkim", None)),
            ("DMARC", dmarc, getattr(self, "badge_dmarc", None)),
        ):
            if widget is None:
                continue
            fg, bg = self._auth_state_color(label, val)
            try:
                widget.configure(text=f"{label} {val}", fg=fg, bg=bg)
            except Exception:
                pass

    def _set_verdict_pill(self, verdict=None, score=None):
        pill = getattr(self, "verdict_pill", None)
        if pill is None:
            return
        if not verdict:
            self.verdict_pill_var.set("No scan")
            try:
                pill.configure(bg=OFFICE_ACCENT_SOFT, fg=OFFICE_ACCENT_DARK)
            except Exception:
                pass
            return
        s = "" if score is None else f" · {score}"
        self.verdict_pill_var.set(f"{verdict}{s}")
        color = VERDICT_COLORS.get(str(verdict), OFFICE_ACCENT_DARK)
        try:
            pill.configure(bg=color, fg="#FFFFFF")
        except Exception:
            pass

    def _draw_risk_bar(self, score=None, color=None):
        canvas = getattr(self, "risk_bar_canvas", None)
        if canvas is None:
            return
        try:
            canvas.delete("all")
            w = max(120, int(canvas.winfo_width() or canvas.cget("width") or 260))
            h = max(12, int(canvas.winfo_height() or 14))
        except Exception:
            w, h = 260, 14
        try:
            val = max(0, min(100, int(score))) if score is not None else 0
        except Exception:
            val = 0
        # track
        canvas.create_rectangle(0, 0, w, h, fill="#E6EDF7", outline="")
        fill = color or OFFICE_ACCENT
        if score is not None:
            fw = max(0, int(w * (val / 100.0)))
            if fw > 0:
                canvas.create_rectangle(0, 0, fw, h, fill=fill, outline="")

    def _update_summary_panel(self, result=None):
        urls = list(getattr(result, "urls", []) or []) if result else []
        findings = list(getattr(result, "findings", []) or []) if result else []
        meta = getattr(result, "metadata", {}) or {} if result else {}
        attach = len(meta.get("attachments") or [])
        score = getattr(result, "score", None) if result else None
        verdict = getattr(result, "verdict", None) if result else None
        color = VERDICT_COLORS.get(str(verdict), OFFICE_ACCENT) if verdict else OFFICE_ACCENT
        self.summary_risk_var.set(str(score) if score is not None else "--")
        self.summary_findings_var.set(str(len(findings)))
        self.summary_urls_var.set(str(len(urls)))
        self.summary_attach_var.set(str(attach))
        self._draw_risk_bar(score, color)
        lb = getattr(self, "summary_url_list", None)
        if lb is not None:
            lb.delete(0, "end")
            self._summary_url_items = []
            if urls:
                for u in urls[:12]:
                    # heuristic: mark as suspicious if result is risky or URL contains suspicious tokens
                    ustr = str(u)
                    suspicious = bool(getattr(result, "score", 0) >= 40) or any(x in ustr.lower() for x in ["login", "verify", "secure", "account", "update"])
                    label = f"{ustr}  [{'Suspicious' if suspicious else 'Active'}]"
                    self._summary_url_items.append(ustr)
                    lb.insert("end", label)
                if len(urls) > 12:
                    lb.insert("end", f"(+{len(urls)-12} more)")
            else:
                lb.insert("end", "(no active URLs)")
        lbl = getattr(self, "summary_risk_value_label", None)
        if lbl is not None:
            try:
                lbl.configure(fg=color if score is not None else OFFICE_TEXT)
            except Exception:
                pass

    def _build_reading_pane(self, parent):
        """Build email header card and scoped tabs (Findings, Observables, Source, Message body)."""
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=0)
        parent.rowconfigure(1, weight=1)

        card = tk.Frame(parent, bg=OFFICE_PANEL, bd=0, highlightbackground=OFFICE_BORDER, highlightthickness=1)
        card.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        card.columnconfigure(0, weight=1)

        self.read_subject_var = tk.StringVar(value="(No message loaded)")
        self.read_from_var = tk.StringVar(value="--")
        self.read_to_var = tk.StringVar(value="--")
        self.read_date_var = tk.StringVar(value="--")
        self.read_route_var = tk.StringVar(value="-- → --")
        self.read_auth_var = tk.StringVar(value="SPF --  |  DKIM --  |  DMARC --")
        self.read_attach_var = tk.StringVar(value="None")
        self.stamp_var = tk.StringVar(value="NO SCAN")
        self.banner_var = tk.StringVar(value="Paste a raw email with 'Paste & Scan' or open an .eml file to begin.")
        self.email_risk_text_var = tk.StringVar(value="-- / 100")

        # Header: meta (left) + verdict pill (right)
        head = tk.Frame(card, bg=OFFICE_PANEL)
        head.grid(row=0, column=0, sticky="ew", padx=14, pady=(12, 6))
        head.columnconfigure(0, weight=1)
        meta = tk.Frame(head, bg=OFFICE_PANEL)
        meta.grid(row=0, column=0, sticky="w")
        self.read_route_label = tk.Label(meta, textvariable=self.read_route_var, bg=OFFICE_PANEL, fg=OFFICE_TEXT, font=("Segoe UI Semibold", 12), anchor="w")
        self.read_route_label.pack(anchor="w")
        self.read_subject_label = tk.Label(meta, textvariable=self.read_subject_var, bg=OFFICE_PANEL, fg=OFFICE_MUTED, font=("Segoe UI", 10), anchor="w", justify="left", wraplength=620)
        self.read_subject_label.pack(anchor="w", pady=(1,0))
        tk.Label(meta, textvariable=self.read_date_var, bg=OFFICE_PANEL, fg=OFFICE_MUTED, font=("Segoe UI", 9), anchor="w").pack(anchor="w", pady=(1,0))
        self.verdict_pill = tk.Label(head, textvariable=self.verdict_pill_var, bg=OFFICE_ACCENT_SOFT, fg=OFFICE_ACCENT_DARK, font=("Segoe UI Semibold", 10), padx=12, pady=6)
        self.verdict_pill.grid(row=0, column=1, sticky="ne", padx=(10, 0))
        self.stamp_label = self.verdict_pill

        # Risk score bar (email panel)
        score_row = tk.Frame(card, bg=OFFICE_PANEL)
        score_row.grid(row=1, column=0, sticky="ew", padx=14, pady=(2, 8))
        score_row.columnconfigure(1, weight=1)
        tk.Label(score_row, text="Risk score", bg=OFFICE_PANEL, fg=OFFICE_MUTED, font=("Segoe UI", 9)).grid(row=0, column=0, sticky="w", padx=(0,8))
        self.email_risk_bar = tk.Canvas(score_row, height=8, bg="#E6EDF7", highlightthickness=0, bd=0)
        self.email_risk_bar.grid(row=0, column=1, sticky="ew")
        self.email_risk_bar.bind("<Configure>", lambda e: self._draw_email_risk_bar(getattr(getattr(self,'last_result',None),'score',None), VERDICT_COLORS.get(getattr(getattr(self,'last_result',None),'verdict',None), OFFICE_ACCENT)))
        tk.Label(score_row, textvariable=self.email_risk_text_var, bg=OFFICE_PANEL, fg=OFFICE_MUTED, font=("Segoe UI Semibold", 9)).grid(row=0, column=2, sticky="e", padx=(8,0))

        # Auth + attachment badges
        auth_row = tk.Frame(card, bg=OFFICE_PANEL)
        auth_row.grid(row=2, column=0, sticky="w", padx=14, pady=(0, 8))
        self.badge_spf = tk.Label(auth_row, text="SPF --", bg="#FCF0D8", fg="#A66A12", font=("Segoe UI Semibold", 9), padx=10, pady=3)
        self.badge_spf.pack(side="left", padx=(0, 4))
        self.badge_dkim = tk.Label(auth_row, text="DKIM --", bg="#FCF0D8", fg="#A66A12", font=("Segoe UI Semibold", 9), padx=10, pady=3)
        self.badge_dkim.pack(side="left", padx=4)
        self.badge_dmarc = tk.Label(auth_row, text="DMARC --", bg="#FCF0D8", fg="#A66A12", font=("Segoe UI Semibold", 9), padx=10, pady=3)
        self.badge_dmarc.pack(side="left", padx=4)
        self.badge_attach = tk.Label(auth_row, text="0 attachments", bg=OFFICE_ACCENT_SOFT, fg=OFFICE_ACCENT_DARK, font=("Segoe UI Semibold", 9), padx=10, pady=3)
        self.badge_attach.pack(side="left", padx=4)

        self.banner_label = tk.Label(
            card, textvariable=self.banner_var, bg=OFFICE_ACCENT_SOFT, fg=OFFICE_ACCENT_DARK,
            font=("Segoe UI", 9), anchor="w", justify="left", padx=12, pady=6,
        )
        self.banner_label.grid(row=3, column=0, sticky="ew", padx=14, pady=(0, 10))

        # Scoped tabs under email header
        tabs_wrap = ttk.Frame(parent)
        tabs_wrap.grid(row=1, column=0, sticky="nsew")
        tabs_wrap.columnconfigure(0, weight=1)
        tabs_wrap.rowconfigure(0, weight=1)
        self.email_notebook = ttk.Notebook(tabs_wrap)
        self.email_notebook.grid(row=0, column=0, sticky="nsew")

        # Message body tab
        self.tab_message = ttk.Frame(self.email_notebook, padding=6)
        self.tab_message.columnconfigure(0, weight=1)
        self.tab_message.rowconfigure(0, weight=1)
        body_frame = ttk.Frame(self.tab_message)
        body_frame.grid(row=0, column=0, sticky="nsew")
        body_frame.columnconfigure(0, weight=1)
        body_frame.rowconfigure(0, weight=1)
        self.read_body_text = tk.Text(
            body_frame, wrap="word", font=("Segoe UI", 10), bg=OFFICE_CARD,
            fg=OFFICE_TEXT, relief="flat", bd=0, padx=12, pady=10, state="disabled",
            highlightthickness=1, highlightbackground=OFFICE_BORDER
        )
        by = ttk.Scrollbar(body_frame, orient="vertical", command=self.read_body_text.yview)
        self.read_body_text.configure(yscrollcommand=by.set)
        self.read_body_text.grid(row=0, column=0, sticky="nsew")
        by.grid(row=0, column=1, sticky="ns")

        # Create email-scoped tab frames as notebook children
        self.tab_findings = ttk.Frame(self.email_notebook, padding=6)
        self.tab_observables = ttk.Frame(self.email_notebook, padding=6)
        self.tab_source = ttk.Frame(self.email_notebook, padding=6)

        self.email_notebook.add(self.tab_findings, text="Findings")
        self.email_notebook.add(self.tab_observables, text="Observables")
        self.email_notebook.add(self.tab_source, text="Source")
        self.email_notebook.add(self.tab_message, text="Message body")

        # Populate scoped tab contents
        self._build_findings_tab()
        self._build_observables_tab()
        self._build_source_tab()

    def _header_row(self, parent, row, label, variable):
        tk.Label(parent, text=label, bg=OFFICE_PANEL, fg=OFFICE_MUTED,
                 font=("Segoe UI Semibold", 9), anchor="e", width=6).grid(
            row=row, column=0, sticky="e", padx=(14, 6), pady=1)
        tk.Label(parent, textvariable=variable, bg=OFFICE_PANEL, fg=OFFICE_TEXT,
                 font=("Segoe UI", 9), anchor="w", justify="left", wraplength=700).grid(
            row=row, column=1, columnspan=2, sticky="ew", padx=(0, 14), pady=1)

    def _on_folder_select(self, event=None):
        if not hasattr(self, "folder_list"):
            return
        sel = self.folder_list.curselection()
        if not sel:
            return
        label = self.folder_list.get(sel[0])
        name = getattr(self, "_nav_target", {}).get(label, label.strip())
        # Email-scoped sub-tabs if present
        if name in ("Findings", "Observables", "Source") and hasattr(self, "email_notebook"):
            try:
                self.notebook.select(self.tab_scan)
                sub = {"Findings": self.tab_findings, "Observables": self.tab_observables, "Source": self.tab_source}.get(name)
                if sub is not None:
                    self.email_notebook.select(sub)
                return
            except Exception:
                pass
        if name == "Scan & Report":
            try:
                self.notebook.select(self.tab_scan)
                if hasattr(self, "email_notebook") and hasattr(self, "tab_message"):
                    self.email_notebook.select(self.tab_message)
                return
            except Exception:
                pass
        target = {
            "Details & Case": getattr(self, "tab_details", None),
            "History & Export": getattr(self, "tab_reports", None),
            "Batch Scan": getattr(self, "tab_batch", None),
            "Help": getattr(self, "tab_help", None),
        }.get(name)
        if target is not None:
            try:
                self.notebook.select(target)
            except Exception:
                pass

    def _on_tab_changed(self, event=None):
        try:
            current = str(self.notebook.select())
        except Exception:
            return
        main_map = {
            str(getattr(self, "tab_scan", "")): 0,
            str(getattr(self, "tab_details", "")): 1,
            str(getattr(self, "tab_reports", "")): 5,
            str(getattr(self, "tab_batch", "")): 6,
            str(getattr(self, "tab_log", "")): 1,
        }
        idx = main_map.get(current)
        if idx is None:
            idx = {
                str(getattr(self, "tab_findings", "")): 2,
                str(getattr(self, "tab_observables", "")): 3,
                str(getattr(self, "tab_source", "")): 4,
            }.get(current)
        if idx is not None:
            try:
                self.folder_list.selection_clear(0, "end")
                self.folder_list.selection_set(idx)
            except Exception:
                pass

    def _build_toolbar(self, parent):
        """Compact action bar with primary scan actions and quick utilities."""
        bar = tk.Frame(parent, bg=OFFICE_PANEL)
        bar.pack(fill="x", padx=12, pady=10)
        bar.columnconfigure(1, weight=1)

        primary = tk.Frame(bar, bg=OFFICE_PANEL)
        primary.grid(row=0, column=0, sticky="w")
        self._retro_button(primary, text="Paste & Scan", command=self.paste_and_scan, primary=True).pack(side="left", padx=(0, 4))
        self._retro_button(primary, text="Scan Source", command=self.scan_current, primary=True).pack(side="left", padx=2)
        self._retro_button(primary, text="Open File", command=self.open_file).pack(side="left", padx=2)
        self._retro_button(primary, text="Paste", command=self.paste_clipboard).pack(side="left", padx=2)
        self._retro_button(primary, text="Clear", command=self.clear_input).pack(side="left", padx=2)

        secondary = tk.Frame(bar, bg=OFFICE_PANEL)
        secondary.grid(row=0, column=1, sticky="w", padx=(12, 0))
        tk.Label(secondary, text="Sample:", bg=OFFICE_PANEL, fg=OFFICE_MUTED, font=("Segoe UI", 9)).pack(side="left")
        samples_dir = self._project_root() / "samples"
        sample_names = sorted([p.name for p in samples_dir.iterdir() if p.is_file() and p.suffix.lower() in (".eml", ".txt", ".mail")]) if samples_dir.is_dir() else []
        default_sample = "phishing_with_auth_fail.eml" if "phishing_with_auth_fail.eml" in sample_names else (sample_names[0] if sample_names else "")
        self.sample_var = tk.StringVar(value=default_sample)
        self.sample_combo = ttk.Combobox(secondary, textvariable=self.sample_var, width=28, state="readonly", values=sample_names)
        self.sample_combo.pack(side="left", padx=(6, 4))
        self._retro_button(secondary, text="Load", command=self.load_selected_sample).pack(side="left", padx=2)
        ttk.Separator(secondary, orient="vertical").pack(side="left", fill="y", padx=8)
        ttk.Checkbutton(secondary, text="ML signal", variable=self.ml_enabled, command=self._on_ml_toggle, style="Toolbar.TCheckbutton").pack(side="left")

        actions = tk.Frame(bar, bg=OFFICE_PANEL)
        actions.grid(row=0, column=2, sticky="e")
        self._retro_button(actions, text="Save Case", command=self.export_case).pack(side="left", padx=2)
        self._retro_button(actions, text="Export JSON", command=self.export_json).pack(side="left", padx=2)
        self._retro_button(actions, text="Export HTML", command=self.export_html).pack(side="left", padx=2)
        self._retro_button(actions, text="Copy Summary", command=self.copy_summary).pack(side="left", padx=2)

    def _make_scrollable(self, outer):
        """Return an inner frame wrapped in a vertical scrolling canvas."""
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(0, weight=1)
        canvas = tk.Canvas(outer, bg=OFFICE_BG, highlightthickness=0, bd=0)
        sb = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        canvas.grid(row=0, column=0, sticky="nsew")
        sb.grid(row=0, column=1, sticky="ns")
        inner = ttk.Frame(canvas)
        window_id = canvas.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(window_id, width=e.width))
        self._scroll_canvas = canvas
        return inner

    def _bind_wheel_scroll(self, widget, canvas):
        if isinstance(widget, (tk.Text, tk.Listbox, ttk.Treeview, ttk.Combobox)):
            return
        try:
            widget.bind("<MouseWheel>", lambda e: canvas.yview_scroll(int(-1 * (e.delta / 120)), "units"))
        except Exception:
            pass
        for child in widget.winfo_children():
            self._bind_wheel_scroll(child, canvas)

    def _build_scan_tab(self):
        # Layout: scanned messages strip (top, from _build_ui) + main split (email workspace | persistent summary)
        self.tab_scan.columnconfigure(0, weight=1)
        self.tab_scan.rowconfigure(0, weight=1)

        paned = ttk.Panedwindow(self.tab_scan, orient="horizontal")
        paned.grid(row=0, column=0, sticky="nsew")

        left = ttk.Frame(paned)
        right = ttk.Frame(paned, width=320)
        paned.add(left, weight=3)
        paned.add(right, weight=1)

        left.columnconfigure(0, weight=1)
        left.rowconfigure(0, weight=1)
        # Email header + scoped tabs (Message body, Findings, Observables, Source)
        self._build_reading_pane(left)

        # Persistent summary panel (right)
        self._build_summary_panel(right)

    def _build_summary_panel(self, parent):
        parent.columnconfigure(0, weight=1)
        panel = ttk.LabelFrame(parent, text="Summary", style="Card.TLabelframe", padding=10)
        panel.grid(row=0, column=0, sticky="nsew", padx=(8, 0))
        panel.columnconfigure(0, weight=1)

        # Risk score as visual bar
        tk.Label(panel, text="RISK SCORE", bg=OFFICE_PANEL, fg=OFFICE_MUTED, font=("Segoe UI Semibold", 8)).grid(row=0, column=0, sticky="w")
        self.summary_risk_value_label = tk.Label(panel, textvariable=self.summary_risk_var, bg=OFFICE_PANEL, fg=OFFICE_TEXT, font=("Segoe UI Semibold", 20))
        self.summary_risk_value_label.grid(row=1, column=0, sticky="w", pady=(2, 4))
        self.risk_bar_canvas = tk.Canvas(panel, height=14, bg=OFFICE_PANEL, highlightthickness=0, bd=0)
        self.risk_bar_canvas.grid(row=2, column=0, sticky="ew", pady=(0, 10))
        self.risk_bar_canvas.bind("<Configure>", lambda e: self._draw_risk_bar(getattr(getattr(self,'last_result',None),'score',None), VERDICT_COLORS.get(getattr(getattr(self,'last_result',None),'verdict',None), OFFICE_ACCENT)))

        # Key metrics (4)
        grid = ttk.Frame(panel)
        grid.grid(row=3, column=0, sticky="ew", pady=(0, 10))
        grid.columnconfigure(0, weight=1)
        grid.columnconfigure(1, weight=1)
        def mcard(r,c,title,var, danger=False):
            f = tk.Frame(grid, bg=OFFICE_CARD, highlightbackground=OFFICE_BORDER, highlightthickness=1)
            f.grid(row=r,column=c,sticky="nsew", padx=(0,6) if c==0 else (6,0), pady=4)
            tk.Label(f, text=title, bg=OFFICE_CARD, fg=OFFICE_MUTED, font=("Segoe UI Semibold", 8)).pack(anchor="w", padx=10, pady=(8,0))
            lbl = tk.Label(f, textvariable=var, bg=OFFICE_CARD, fg=("#B23A2A" if danger else OFFICE_TEXT), font=("Segoe UI Semibold", 16))
            lbl.pack(anchor="w", padx=10, pady=(0,8))
            return lbl
        self.summary_risk_card_label = mcard(0,0,"Risk score", self.summary_risk_var, danger=True)
        self.summary_findings_card_label = mcard(0,1,"Findings", self.summary_findings_var, danger=True)
        mcard(1,0,"Active URLs", self.summary_urls_var)
        self.summary_attach_card_label = mcard(1,1,"Attachments", self.summary_attach_var, danger=True)
        self.summary_verdict_mini = tk.StringVar(value="--")

        # URL list
        tk.Label(panel, text="ACTIVE URLS", bg=OFFICE_PANEL, fg=OFFICE_MUTED, font=("Segoe UI Semibold", 8)).grid(row=4, column=0, sticky="w", pady=(4,2))
        url_wrap = ttk.Frame(panel)
        url_wrap.grid(row=5, column=0, sticky="nsew", pady=(0,10))
        url_wrap.columnconfigure(0, weight=1)
        panel.rowconfigure(5, weight=1)
        self.summary_url_list = tk.Listbox(url_wrap, height=8, font=("Segoe UI", 9), bg=OFFICE_INPUT, fg=OFFICE_TEXT,
                                           selectbackground=OFFICE_SELECT, selectforeground=OFFICE_ACCENT_DARK, relief="flat", bd=0,
                                           highlightthickness=1, highlightbackground=OFFICE_BORDER, activestyle="none")
        uy = ttk.Scrollbar(url_wrap, orient="vertical", command=self.summary_url_list.yview)
        self.summary_url_list.configure(yscrollcommand=uy.set)
        self.summary_url_list.grid(row=0, column=0, sticky="nsew")
        uy.grid(row=0, column=1, sticky="ns")
        self.summary_url_list.bind("<Double-1>", lambda e: self.copy_summary_url())

        # Action buttons
        actions = ttk.Frame(panel)
        actions.grid(row=6, column=0, sticky="ew", pady=(4,0))
        actions.columnconfigure(0, weight=1)
        self._retro_button(actions, text="Report as phishing", command=self._action_report_phishing, primary=True).grid(row=0, column=0, sticky="ew", pady=2)
        self._retro_button(actions, text="Add to whitelist", command=self._action_whitelist_summary_url).grid(row=1, column=0, sticky="ew", pady=2)
        self._retro_button(actions, text="Save case", command=self.export_case).grid(row=2, column=0, sticky="ew", pady=2)
        self._retro_button(actions, text="Copy summary", command=self.copy_summary).grid(row=3, column=0, sticky="ew", pady=2)

        # Analysis details (compatibility: quick_text/auth/ml/recs used by render/export helpers)
        tk.Label(panel, text="ANALYSIS DETAILS", bg=OFFICE_PANEL, fg=OFFICE_MUTED, font=("Segoe UI Semibold", 8)).grid(row=7, column=0, sticky="w", pady=(10,2))
        details_wrap = ttk.Frame(panel)
        details_wrap.grid(row=8, column=0, sticky="nsew", pady=(0,2))
        details_wrap.columnconfigure(0, weight=1)
        details_wrap.rowconfigure(0, weight=1)
        panel.rowconfigure(8, weight=0)
        self.quick_text = tk.Text(details_wrap, wrap="word", font=("Segoe UI", 8), height=8, state="disabled", bg=OFFICE_INPUT, fg=OFFICE_TEXT, relief="flat", highlightthickness=1, highlightbackground=OFFICE_BORDER)
        qy = ttk.Scrollbar(details_wrap, orient="vertical", command=self.quick_text.yview)
        self.quick_text.configure(yscrollcommand=qy.set)
        self.quick_text.grid(row=0, column=0, sticky="nsew")
        qy.grid(row=0, column=1, sticky="ns")

        # keep compatibility attributes used elsewhere
        self.verdict_label = self.summary_risk_value_label
        self.score_canvas = self.risk_bar_canvas
        self.auth_var = getattr(self, 'auth_var', tk.StringVar(value="SPF: --  DKIM: --  DMARC: --"))
        self.ml_var = getattr(self, 'ml_var', tk.StringVar(value="ML: --"))
        self.recs_var = getattr(self, 'recs_var', tk.StringVar(value="Scan a message to see context-aware recommended actions."))
        self._draw_score_ring = self._draw_risk_bar_compat

    def _draw_risk_bar_compat(self, score, color=None):
        self._draw_risk_bar(score, color)

    def _metric_card(self, parent, col, title, value_var, hint_var):
        card = tk.Frame(parent, bg=OFFICE_PANEL, highlightbackground=OFFICE_BORDER, highlightthickness=1, bd=0)
        card.grid(row=0, column=col, sticky="nsew", padx=(0 if col == 0 else 6, 0))
        card.columnconfigure(0, weight=1)
        ttk.Label(card, text=title, style="MetricTitle.TLabel").grid(row=0, column=0, sticky="w", padx=12, pady=(10, 0))
        value_label = tk.Label(card, textvariable=value_var, bg=OFFICE_PANEL, fg=OFFICE_TEXT, font=("Segoe UI Semibold", 17), anchor="w")
        value_label.grid(row=1, column=0, sticky="w", padx=12, pady=(2, 0))
        ttk.Label(card, textvariable=hint_var, style="MetricHint.TLabel").grid(row=2, column=0, sticky="w", padx=12, pady=(0, 10))
        return value_label

    def _draw_score_ring(self, score, color=None):
        # Compatibility shim (ring replaced by risk bar in redesigned layout)
        try:
            self._draw_risk_bar(score, color)
        except Exception:
            pass

    def _build_details_tab(self):
        self.tab_details.columnconfigure(0, weight=3)
        self.tab_details.columnconfigure(1, weight=2)
        self.tab_details.rowconfigure(0, weight=1)

        meta_card = ttk.LabelFrame(self.tab_details, text="Message Metadata", style="Card.TLabelframe")
        meta_card.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        meta_card.columnconfigure(0, weight=1)
        meta_card.rowconfigure(0, weight=1)
        cols = ("field", "value")
        self.meta_tree = ttk.Treeview(meta_card, columns=cols, show="headings", height=12)
        self.meta_tree.heading("field", text="Field")
        self.meta_tree.heading("value", text="Value")
        self.meta_tree.column("field", width=150, anchor="w")
        self.meta_tree.column("value", width=460, anchor="w")
        mscroll = ttk.Scrollbar(meta_card, orient="vertical", command=self.meta_tree.yview)
        self.meta_tree.configure(yscrollcommand=mscroll.set)
        self.meta_tree.grid(row=0, column=0, sticky="nsew")
        mscroll.grid(row=0, column=1, sticky="ns")

        case_card = ttk.LabelFrame(self.tab_details, text="Investigation Case", style="Card.TLabelframe")
        case_card.grid(row=0, column=1, sticky="nsew")
        case_card.columnconfigure(1, weight=1)
        case_card.rowconfigure(7, weight=1)

        self.case_id_var = tk.StringVar(value="--")
        self.case_status_var = tk.StringVar(value="--")
        self.case_verdict_var = tk.StringVar(value="--")
        self.case_evidence_var = tk.StringVar(value="--")

        for row, (label, var) in enumerate((
            ("Case ID:", self.case_id_var),
            ("Status:", self.case_status_var),
            ("Verdicts:", self.case_verdict_var),
        )):
            tk.Label(case_card, text=label, bg=OFFICE_PANEL, fg=OFFICE_MUTED,
                     font=("Segoe UI Semibold", 8), anchor="e").grid(row=row, column=0, sticky="e", padx=(6, 4), pady=1)
            tk.Label(case_card, textvariable=var, bg=OFFICE_PANEL, fg=OFFICE_TEXT,
                     font=("Segoe UI", 8), anchor="w", justify="left", wraplength=360).grid(row=row, column=1, sticky="ew", padx=(0, 6), pady=1)
        tk.Label(case_card, text="Evidence:", bg=OFFICE_PANEL, fg=OFFICE_MUTED,
                 font=("Segoe UI Semibold", 8), anchor="ne").grid(row=3, column=0, sticky="ne", padx=(6, 4), pady=1)
        tk.Label(case_card, textvariable=self.case_evidence_var, bg=OFFICE_PANEL, fg=OFFICE_TEXT,
                 font=("Segoe UI", 8), anchor="w", justify="left", wraplength=360).grid(row=3, column=1, sticky="ew", padx=(0, 6), pady=1)

        ttk.Label(case_card, text="Timeline", style="SidebarTitle.TLabel").grid(row=4, column=0, columnspan=2, sticky="w", padx=6, pady=(8, 2))
        self.case_timeline_tree = ttk.Treeview(case_card, columns=("time", "event", "message"), show="headings", height=6)
        for col, title, width in (("time", "Time", 78), ("event", "Event", 120), ("message", "Message", 300)):
            self.case_timeline_tree.heading(col, text=title)
            self.case_timeline_tree.column(col, width=width, anchor="w")
        tscroll = ttk.Scrollbar(case_card, orient="vertical", command=self.case_timeline_tree.yview)
        self.case_timeline_tree.configure(yscrollcommand=tscroll.set)
        self.case_timeline_tree.grid(row=5, column=0, columnspan=2, sticky="nsew", padx=6)
        tscroll.grid(row=5, column=2, sticky="ns")
        case_card.rowconfigure(5, weight=1)

        note_bar = ttk.Frame(case_card)
        note_bar.grid(row=6, column=0, columnspan=3, sticky="ew", padx=6, pady=(6, 0))
        self._retro_button(note_bar, text="Add Note", command=self.case_add_note).pack(side="left", padx=1)

        action_bar = ttk.Frame(case_card)
        action_bar.grid(row=7, column=0, columnspan=3, sticky="ew", padx=6, pady=(6, 4))
        for col in range(2):
            action_bar.columnconfigure(col, weight=1)
        self._retro_button(action_bar, text="Confirm Phishing", command=lambda: self.case_set_verdict("phishing")).grid(row=0, column=0, sticky="ew", padx=1, pady=1)
        self._retro_button(action_bar, text="Mark Benign", command=lambda: self.case_set_verdict("benign")).grid(row=0, column=1, sticky="ew", padx=1, pady=1)
        self._retro_button(action_bar, text="Clear Decision", command=lambda: self.case_set_verdict(None)).grid(row=1, column=0, sticky="ew", padx=1, pady=1)
        self._retro_button(action_bar, text="Save Case JSON", command=self.export_case).grid(row=1, column=1, sticky="ew", padx=1, pady=1)

    def _build_source_tab(self):
        self.tab_source.columnconfigure(0, weight=1)
        self.tab_source.rowconfigure(1, weight=1)

        bar = ttk.Frame(self.tab_source)
        bar.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        ttk.Label(bar, text="Raw message source (Gmail > More > Show original > Copy to clipboard):").pack(side="left")
        self._retro_button(bar, text="Paste & Scan", command=self.paste_and_scan).pack(side="right", padx=2)
        self._retro_button(bar, text="Paste", command=self.paste_clipboard).pack(side="right", padx=2)
        self._retro_button(bar, text="Save Source", command=self.save_input).pack(side="right", padx=2)
        self._retro_button(bar, text="Clear", command=self.clear_input).pack(side="right", padx=2)

        self.input_text = tk.Text(self.tab_source, wrap="none", undo=True, font=("Consolas", 9), bg=OFFICE_INPUT, relief="flat", bd=0, highlightthickness=1, highlightbackground=OFFICE_BORDER)
        y = ttk.Scrollbar(self.tab_source, orient="vertical", command=self.input_text.yview)
        x = ttk.Scrollbar(self.tab_source, orient="horizontal", command=self.input_text.xview)
        self.input_text.configure(yscrollcommand=y.set, xscrollcommand=x.set)
        self.input_text.grid(row=1, column=0, sticky="nsew")
        y.grid(row=1, column=1, sticky="ns")
        x.grid(row=2, column=0, sticky="ew")


    def _build_findings_tab(self):
        self.tab_findings.columnconfigure(0, weight=1)
        self.tab_findings.rowconfigure(0, weight=1)
        outer = ttk.Frame(self.tab_findings)
        outer.grid(row=0, column=0, sticky="nsew")
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(0, weight=1)

        canvas = tk.Canvas(outer, bg=OFFICE_BG, highlightthickness=0, bd=0)
        vs = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        self.findings_cards_frame = tk.Frame(canvas, bg=OFFICE_BG)
        self.findings_cards_frame.columnconfigure(0, weight=1)
        win = canvas.create_window((0, 0), window=self.findings_cards_frame, anchor="nw")
        canvas.configure(yscrollcommand=vs.set)
        canvas.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")
        def _cfg(_e=None):
            try:
                canvas.configure(scrollregion=canvas.bbox("all"))
                canvas.itemconfigure(win, width=canvas.winfo_width())
            except Exception:
                pass
        self.findings_cards_frame.bind("<Configure>", _cfg)
        canvas.bind("<Configure>", _cfg)
        self._findings_canvas = canvas

        # Compatibility: keep findings_tree-like interface minimal (not used for rendering now)
        self.findings_tree = None

        bar = ttk.Frame(self.tab_findings)
        bar.grid(row=1, column=0, sticky="ew", pady=(6, 0))
        self.findings_info_var = tk.StringVar(value="No scan yet.")
        ttk.Label(bar, textvariable=self.findings_info_var).pack(side="left")
        self._retro_button(bar, text="Copy Selected", command=self.copy_selected_finding).pack(side="right", padx=2)
        self._retro_button(bar, text="Copy All Findings", command=self.copy_findings).pack(side="right", padx=2)

    def _clear_finding_cards(self):
        for w in getattr(self, "findings_cards_frame", tk.Frame()).winfo_children():
            try:
                w.destroy()
            except Exception:
                pass
        self._finding_cards = []
        self._selected_finding_text = ""

    def _render_finding_cards(self, findings):
        self._clear_finding_cards()
        frame = getattr(self, "findings_cards_frame", None)
        if frame is None:
            return
        sev_color = {"Critical": "#B23A2A", "High": "#B23A2A", "Medium": "#A66A12", "Suspicious": "#A66A12", "Low": "#40587A"}
        if not findings:
            empty = tk.Frame(frame, bg=OFFICE_CARD, highlightbackground=OFFICE_BORDER, highlightthickness=1)
            empty.grid(row=0, column=0, sticky="ew", pady=4)
            tk.Label(empty, text="No findings detected for this scan.", bg=OFFICE_CARD, fg=OFFICE_MUTED, font=("Segoe UI", 10), padx=12, pady=14).pack(anchor="w")
            return
        for i, f in enumerate(findings):
            sev = str(getattr(f, "severity", "Info"))
            accent = sev_color.get(sev, OFFICE_ACCENT)
            card = tk.Frame(frame, bg=OFFICE_BG)
            card.grid(row=i, column=0, sticky="ew", pady=4)
            card.columnconfigure(1, weight=1)
            stripe = tk.Frame(card, bg=accent, width=5)
            stripe.grid(row=0, column=0, sticky="ns")
            body = tk.Frame(card, bg=OFFICE_CARD, highlightbackground=OFFICE_BORDER, highlightthickness=1)
            body.grid(row=0, column=1, sticky="nsew")
            body.columnconfigure(0, weight=1)
            top = tk.Frame(body, bg=OFFICE_CARD)
            top.grid(row=0, column=0, sticky="ew", padx=12, pady=(10, 2))
            tk.Label(top, text=sev.upper(), bg=accent, fg="#FFFFFF", font=("Segoe UI Semibold", 8), padx=8, pady=2).pack(side="left")
            tk.Label(top, text=f"+{getattr(f,'score',0)}", bg=OFFICE_ACCENT_SOFT, fg=OFFICE_ACCENT_DARK, font=("Segoe UI Semibold", 8), padx=8, pady=2).pack(side="left", padx=(6,0))
            tk.Label(body, text=str(getattr(f,'title','')), bg=OFFICE_CARD, fg=OFFICE_TEXT, font=("Segoe UI Semibold", 10), anchor="w", justify="left", wraplength=760).grid(row=1, column=0, sticky="ew", padx=12)
            tk.Label(body, text=str(getattr(f,'detail','')), bg=OFFICE_CARD, fg=OFFICE_MUTED, font=("Segoe UI", 9), anchor="w", justify="left", wraplength=760).grid(row=2, column=0, sticky="ew", padx=12, pady=(2,10))
            txt = f"[{sev} | +{getattr(f,'score',0)}] {getattr(f,'title','')}\n{getattr(f,'detail','')}"
            def _sel(t=txt, b=body):
                self._selected_finding_text = t
                try:
                    b.configure(highlightbackground=OFFICE_ACCENT, highlightthickness=2)
                except Exception:
                    pass
            for w in (body, top) + list(body.winfo_children()) + list(top.winfo_children()):
                w.bind("<Button-1>", lambda e, t=txt, b=body: _sel(t,b), add="+")
            self._finding_cards.append((txt, body))

    def _build_observables_tab(self):
        self.tab_observables.columnconfigure(0, weight=1)
        self.tab_observables.columnconfigure(1, weight=1)
        self.tab_observables.rowconfigure(0, weight=1)
        self.tab_observables.rowconfigure(1, weight=1)

        self.obs_boxes = {}
        specs = [
            ("urls", "URLs (active / non-whitelisted)", 0, 0),
            ("emails", "Email Addresses", 0, 1),
            ("ips", "IP Addresses", 1, 0),
            ("domains", "Domains", 1, 1),
        ]
        for key, title, r, c in specs:
            lf = ttk.LabelFrame(self.tab_observables, text=title, style="Card.TLabelframe")
            lf.grid(row=r, column=c, sticky="nsew", padx=4, pady=4)
            lf.rowconfigure(0, weight=1)
            lf.columnconfigure(0, weight=1)
            lb = tk.Listbox(lf, font=("Consolas", 9), bg=OFFICE_INPUT, fg=OFFICE_TEXT, selectbackground=OFFICE_SELECT, selectforeground=OFFICE_ACCENT_DARK, relief="flat", bd=0, highlightthickness=0)
            sb = ttk.Scrollbar(lf, orient="vertical", command=lb.yview)
            lb.configure(yscrollcommand=sb.set)
            lb.grid(row=0, column=0, sticky="nsew")
            sb.grid(row=0, column=1, sticky="ns")
            lb.bind("<Double-1>", lambda _e, k=key: self.copy_selected_observable(k))
            self.obs_boxes[key] = lb

        bottom = ttk.Frame(self.tab_observables)
        bottom.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(6, 0))
        bottom.columnconfigure(0, weight=1)
        self.obs_info_var = tk.StringVar(value="No observables yet.")
        ttk.Label(bottom, textvariable=self.obs_info_var).grid(row=0, column=0, sticky="w")
        self._retro_button(bottom, text="Copy Selected", command=self.copy_selected_observable).grid(row=0, column=1, padx=2)
        self._retro_button(bottom, text="Add Selected to Whitelist", command=self.add_selected_observable_to_whitelist).grid(row=0, column=2, padx=2)
        self._retro_button(bottom, text="Rescan", command=self.scan_current).grid(row=0, column=3, padx=2)

    def _build_batch_tab(self):
        self.tab_batch.columnconfigure(0, weight=1)
        self.tab_batch.rowconfigure(2, weight=1)

        top = ttk.Frame(self.tab_batch)
        top.grid(row=0, column=0, sticky="ew", pady=(0, 4))
        self.batch_start_btn = self._retro_button(top, text="Choose Folder & Scan", command=self.batch_scan)
        self.batch_start_btn.pack(side="left")
        self._retro_button(top, text="Export Batch JSON", command=self.export_batch_json).pack(side="left", padx=6)
        self._retro_button(top, text="Export Batch HTML", command=self.export_batch_html).pack(side="left", padx=6)
        self._retro_button(top, text="Export Cases", command=self.export_batch_cases).pack(side="left", padx=6)
        self.batch_cancel_btn = self._retro_button(top, text="Cancel", command=self.cancel_batch_scan)
        self.batch_cancel_btn.pack(side="left", padx=6)
        self.batch_cancel_btn.configure(state="disabled")

        progress_bar = ttk.Frame(self.tab_batch)
        progress_bar.grid(row=1, column=0, sticky="ew", pady=(0, 6))
        progress_bar.columnconfigure(0, weight=1)
        self.batch_info_var = tk.StringVar(value="Scan a folder of .eml/.txt/.mail files. Uses current whitelist and ML settings.")
        ttk.Label(progress_bar, textvariable=self.batch_info_var).grid(row=0, column=0, sticky="w")
        self.batch_progress = ttk.Progressbar(progress_bar, orient="horizontal", mode="determinate")
        self.batch_progress.grid(row=1, column=0, sticky="ew", pady=(4, 0))

        frame = ttk.LabelFrame(self.tab_batch, text="Batch Results", style="Card.TLabelframe")
        frame.grid(row=2, column=0, sticky="nsew")
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        cols = ("file", "verdict", "score", "findings", "urls", "spf", "dkim", "dmarc")
        self.batch_tree = ttk.Treeview(frame, columns=cols, show="headings")
        for c, t, w in [("file", "File", 360), ("verdict", "Verdict", 120), ("score", "Score", 60), ("findings", "Findings", 70), ("urls", "URLs", 60), ("spf", "SPF", 70), ("dkim", "DKIM", 70), ("dmarc", "DMARC", 70)]:
            self.batch_tree.heading(c, text=t)
            self.batch_tree.column(c, width=w, anchor="w")
        y = ttk.Scrollbar(frame, orient="vertical", command=self.batch_tree.yview)
        x = ttk.Scrollbar(frame, orient="horizontal", command=self.batch_tree.xview)
        self.batch_tree.configure(yscrollcommand=y.set, xscrollcommand=x.set)
        self.batch_tree.grid(row=0, column=0, sticky="nsew")
        y.grid(row=0, column=1, sticky="ns")
        x.grid(row=1, column=0, sticky="ew")
        self.batch_tree.bind("<Double-1>", self._on_batch_double_click)

    def _build_reports_tab(self):
        self.tab_reports.columnconfigure(0, weight=1)
        self.tab_reports.rowconfigure(1, weight=1)
        self.tab_reports.rowconfigure(2, weight=1)

        bar = ttk.Frame(self.tab_reports)
        bar.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        self._retro_button(bar, text="Reload Selected", command=self.reload_selected_history).pack(side="left", padx=2)
        self._retro_button(bar, text="Delete Selected", command=self.delete_selected_history).pack(side="left", padx=2)
        self._retro_button(bar, text="Clear History", command=self.clear_history).pack(side="left", padx=2)
        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=8)
        self._retro_button(bar, text="Export JSON", command=self.export_json).pack(side="left", padx=2)
        self._retro_button(bar, text="Export HTML", command=self.export_html).pack(side="left", padx=2)
        self._retro_button(bar, text="Export Case", command=self.export_case).pack(side="left", padx=2)
        self._retro_button(bar, text="Copy Summary", command=self.copy_summary).pack(side="left", padx=2)

        hist_frame = ttk.LabelFrame(self.tab_reports, text="Session History (double-click to reload result view)", style="Card.TLabelframe")
        hist_frame.grid(row=1, column=0, sticky="nsew", pady=(0, 6))
        hist_frame.columnconfigure(0, weight=1)
        hist_frame.rowconfigure(0, weight=1)
        cols = ("time", "source", "verdict", "score", "summary")
        self.history_tree = ttk.Treeview(hist_frame, columns=cols, show="headings")
        for c, t, w in [("time", "Time", 80), ("source", "Source", 350), ("verdict", "Verdict", 120), ("score", "Score", 60), ("summary", "Summary", 500)]:
            self.history_tree.heading(c, text=t)
            self.history_tree.column(c, width=w, anchor="w")
        y = ttk.Scrollbar(hist_frame, orient="vertical", command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=y.set)
        self.history_tree.grid(row=0, column=0, sticky="nsew")
        y.grid(row=0, column=1, sticky="ns")
        self.history_tree.bind("<Double-1>", self._on_history_double_click)
        self.history_tree.bind("<<TreeviewSelect>>", self._on_history_select)

        out_frame = ttk.LabelFrame(self.tab_reports, text="Selected / Last Result JSON Preview", style="Card.TLabelframe")
        out_frame.grid(row=2, column=0, sticky="nsew")
        out_frame.columnconfigure(0, weight=1)
        out_frame.rowconfigure(0, weight=1)
        self.report_text = tk.Text(out_frame, wrap="none", font=("Consolas", 10))
        ry = ttk.Scrollbar(out_frame, orient="vertical", command=self.report_text.yview)
        rx = ttk.Scrollbar(out_frame, orient="horizontal", command=self.report_text.xview)
        self.report_text.configure(yscrollcommand=ry.set, xscrollcommand=rx.set)
        self.report_text.grid(row=0, column=0, sticky="nsew")
        ry.grid(row=0, column=1, sticky="ns")
        rx.grid(row=1, column=0, sticky="ew")

    def _build_log_tab(self):
        self.tab_log.columnconfigure(0, weight=1)
        self.tab_log.rowconfigure(1, weight=1)
        bar = ttk.Frame(self.tab_log)
        bar.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        self._retro_button(bar, text="Copy Log", command=self.copy_log).pack(side="left", padx=2)
        self._retro_button(bar, text="Clear Log", command=self.clear_log).pack(side="left", padx=2)
        ttk.Label(bar, text="Analysis steps are logged as they actually run.").pack(side="left", padx=8)
        frame = ttk.LabelFrame(self.tab_log, text="Analysis Progress & Log", style="Card.TLabelframe")
        frame.grid(row=1, column=0, sticky="nsew")
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        self.log_text = tk.Text(frame, wrap="none", font=("Segoe UI", 9), state="disabled")
        y = ttk.Scrollbar(frame, orient="vertical", command=self.log_text.yview)
        x = ttk.Scrollbar(frame, orient="horizontal", command=self.log_text.xview)
        self.log_text.configure(yscrollcommand=y.set, xscrollcommand=x.set)
        self.log_text.grid(row=0, column=0, sticky="nsew")
        y.grid(row=0, column=1, sticky="ns")
        x.grid(row=1, column=0, sticky="ew")

    def _log(self, message):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] {message}"
        self.analysis_log.append(line)
        try:
            self.log_text.configure(state="normal")
            self.log_text.insert("end", line + "\n")
            self.log_text.see("end")
            self.log_text.configure(state="disabled")
        except Exception:
            pass
        self.status_var.set(message)
        try:
            self.update_idletasks()
        except Exception:
            pass

    def _reset_log(self):
        self.analysis_log = []
        try:
            self.log_text.configure(state="normal")
            self.log_text.delete("1.0", "end")
            self.log_text.configure(state="disabled")
        except Exception:
            pass

    def _build_help_tab(self):
        self.tab_help.columnconfigure(0, weight=1)
        self.tab_help.rowconfigure(0, weight=1)
        txt = tk.Text(self.tab_help, wrap="word", font=("Segoe UI", 9))
        sb = ttk.Scrollbar(self.tab_help, orient="vertical", command=txt.yview)
        txt.configure(yscrollcommand=sb.set)
        txt.grid(row=0, column=0, sticky="nsew")
        sb.grid(row=0, column=1, sticky="ns")
        help_text = (
            "PhishGuard Mail Scanner - Feature Overview\n\n"
            "Inbox & Reading Pane\n"
            "- Scanned messages appear in the Inbox list; double-click a row to reopen it.\n"
            "- The reading pane shows Subject, From, To, Date, Auth, Attachments, verdict stamp, warning banner, and the parsed message body.\n"
            "- Use Paste & Scan for one-click Gmail 'Show original' triage, or Open Email for .eml/.txt/.mail files.\n\n"
            "Report & Details\n"
            "- Report tab shows risk level, score, summary, SPF/DKIM/DMARC auth claims, ML result, recommended actions, and quick analysis text.\n"
            "- Details tab shows full message metadata plus the investigation case (case ID, evidence hash, timeline, analyst decision).\n\n"
            "Findings\n"
            "- Detailed heuristic findings with severity, score contribution, title, and explanation.\n"
            "- Copy selected findings or all findings to the clipboard.\n\n"
            "Observables\n"
            "- Extracted URLs, email addresses, IPs, and domains (ThePhish-inspired IOC view).\n"
            "- Double-click an observable to copy it.\n"
            "- Add Selected to Whitelist writes an exact rule to the active whitelist file, then optionally rescans.\n\n"
            "Investigation Case\n"
            "- Every scan creates a local case with evidence hash, analyzer result, and timeline.\n"
            "- Confirm Phishing / Mark Benign / Clear Decision records an analyst verdict without changing the automated verdict.\n"
            "- Add Note appends an analyst note; Save Case exports the full case through the local export provider.\n\n"
            "Batch Scan\n"
            "- Scan a folder of .eml/.txt/.mail files in the background using current whitelist and ML settings.\n"
            "- Cancel stops the run safely; completed rows remain available.\n"
            "- Export batch JSON, batch HTML, or one case JSON per file.\n\n"
            "Source\n"
            "- Paste, edit, save, or clear the raw Gmail 'Show original' message source.\n"
            "- Scan Now analyzes the current source text.\n\n"
            "Session History\n"
            "- Keeps in-session history with JSON preview; double-click to reload a result.\n"
            "- Reload, delete, or clear history entries; export the selected/last result as JSON, HTML, or case JSON.\n\n"
            "Whitelist\n"
            "- Toggle default project whitelist.json, choose a custom whitelist, reload it, or clear the custom selection.\n"
            "- Supports PhishGuard and ThePhish-compatible schemas (exact/regex/trusted-domain rules).\n"
            "- Invalid whitelist files are reported instead of silently ignored.\n\n"
            "ML signal\n"
            "- The toolbar 'ML signal' checkbox controls the embedded Naive Bayes signal for new scans.\n"
            "- ML is additive context; heuristic findings remain primary.\n\n"
            "Keyboard shortcuts\n"
            "- Ctrl+O open email, Ctrl+S save source, Ctrl+Enter scan, Ctrl+Shift+V paste & scan.\n"
            "- Ctrl+E export JSON, Ctrl+J save case, Ctrl+H / F1 help.\n\n"
            "Detection Areas\n"
            "- Sender/header anomalies (From/Reply-To/Return-Path mismatch, spoofing hints, Received hops)\n"
            "- Authentication header parsing (SPF/DKIM/DMARC from Authentication-Results/Received-SPF)\n"
            "- URL risks (IP hosts, suspicious TLDs, punycode, @ tricks, long/complex hosts, HTTP)\n"
            "- Content lures (urgency, credential/payment requests, generic greeting)\n"
            "- Attachment indicators (risky types, double extensions, text mentions)\n\n"
            "Limitations\n"
            "- Heuristic triage only; may produce false positives/negatives.\n"
            "- Does not perform live DNS validation, mailbox-provider checks, sandboxing, or threat-intel lookups.\n"
            "- Always verify suspicious messages via official channels and security tooling.\n"
        )
        txt.insert("1.0", help_text)
        txt.configure(state="disabled")

    # ---------- utilities ----------
    def _project_root(self):
        return Path(__file__).resolve().parent

    def _refresh_whitelist_status(self):
        custom = self.custom_whitelist_path.get().strip()
        if custom:
            info = whitelist_summary(custom)
            name = Path(custom).name
            if info.get("error"):
                self.whitelist_status_var.set(f"Whitelist: custom {name} (INVALID: {info['error']})")
            else:
                self.whitelist_status_var.set(
                    f"Whitelist: custom {name} ({info['exact']} exact, {info['regex']} regex)"
                )
            return
        default = self._project_root() / "whitelist.json"
        if self.use_default_whitelist.get() and default.is_file():
            info = whitelist_summary(str(default))
            if info.get("error"):
                self.whitelist_status_var.set(f"Whitelist: default whitelist.json (INVALID: {info['error']})")
            else:
                self.whitelist_status_var.set(
                    f"Whitelist: default whitelist.json ({info['exact']} exact, {info['regex']} regex)"
                )
        elif self.use_default_whitelist.get():
            self.whitelist_status_var.set("Whitelist: default enabled (file not found)")
        else:
            self.whitelist_status_var.set("Whitelist: disabled")

    def _whitelist_target_path(self):
        custom = self.custom_whitelist_path.get().strip()
        if custom:
            return custom
        if self.use_default_whitelist.get():
            return str(self._project_root() / "whitelist.json")
        return None

    def _wl_kwargs(self):
        custom = self.custom_whitelist_path.get().strip()
        if custom:
            return {"whitelist_path": custom, "use_default_whitelist": False}
        return {"whitelist_path": None, "use_default_whitelist": bool(self.use_default_whitelist.get())}

    def _set_text(self, widget, content, readonly=True):
        if isinstance(widget, tk.Text):
            widget.configure(state="normal")
            widget.delete("1.0", "end")
            widget.insert("1.0", content)
            widget.configure(state="disabled" if readonly else "normal")

    def _copy_text(self, text, label="Text"):
        try:
            self.clipboard_clear()
            self.clipboard_append(text or "")
            self.status_var.set(f"{label} copied to clipboard.")
            return True
        except Exception as e:
            messagebox.showerror("Clipboard", f"Failed to copy {label.lower()}:\n{e}")
            return False

    def _on_ml_toggle(self):
        state = "enabled" if self.ml_enabled.get() else "disabled"
        self.status_var.set(f"ML signal {state} for new scans. Rescan to apply.")

    def _reset_result_view(self):
        self.last_result = None
        self.last_result_source = ""
        self.current_case = None
        self.verdict_var.set("Verdict: --")
        self.score_var.set("Score: --")
        self.summary_var.set("No scan yet.")
        self.auth_var.set("SPF: --  DKIM: --  DMARC: --")
        self.ml_var.set("ML: --")
        self.recs_var.set("Scan a message to see context-aware recommended actions.")
        self.read_subject_var.set("(No message loaded)")
        self.read_from_var.set("--")
        self.read_to_var.set("--")
        self.read_date_var.set("--")
        self.read_auth_var.set("SPF --  |  DKIM --  |  DMARC --")
        self.read_attach_var.set("None")
        self.stamp_var.set("NO SCAN")
        try:
            self.stamp_label.configure(bg=OFFICE_ACCENT_SOFT, fg=OFFICE_ACCENT_DARK)
        except Exception:
            pass
        self.banner_var.set("Paste a raw email with 'Paste & Scan' or open an .eml file to begin.")
        try:
            self.banner_label.configure(bg=OFFICE_ACCENT_SOFT, fg=OFFICE_ACCENT_DARK)
        except Exception:
            pass
        self._draw_score_ring(None)
        self._set_text(self.read_body_text, "", readonly=True)
        self._set_text(self.quick_text, "", readonly=True)
        self._set_text(self.report_text, "", readonly=True)
        for tree in (getattr(self, "meta_tree", None), getattr(self, "findings_tree", None), getattr(self, "case_timeline_tree", None)):
            if tree is None:
                continue
            try:
                for item in tree.get_children():
                    tree.delete(item)
            except Exception:
                pass
        try:
            self._clear_finding_cards()
        except Exception:
            pass
        try:
            self._set_verdict_pill(None, None)
            self._set_auth_badges("unknown", "unknown", "unknown")
            self._update_summary_panel(None)
            self.summary_verdict_mini.set("--")
        except Exception:
            pass
        for lb in self.obs_boxes.values():
            lb.delete(0, "end")
        self.obs_info_var.set("No observables yet.")
        self.findings_info_var.set("No scan yet.")
        self.case_id_var.set("--")
        self.case_status_var.set("--")
        self.case_verdict_var.set("--")
        self.case_evidence_var.set("--")
        self.metric_risk_var.set("--")
        self.metric_risk_label_var.set("No scan")
        self.metric_findings_var.set("--")
        self.metric_urls_var.set("--")
        self.metric_auth_var.set("--")
        try:
            self.read_route_var.set("-- → --")
            self.email_risk_text_var.set("-- / 100")
            self._draw_email_risk_bar(None)
            self.badge_attach.configure(text="0 attachments", bg=OFFICE_ACCENT_SOFT, fg=OFFICE_ACCENT_DARK)
        except Exception:
            pass
        for lbl in (getattr(self, "metric_risk_value_label", None), getattr(self, "metric_findings_value_label", None),
                    getattr(self, "metric_urls_value_label", None), getattr(self, "metric_auth_value_label", None)):
            try:
                if lbl is not None:
                    lbl.configure(fg=OFFICE_TEXT)
            except Exception:
                pass

    # ---------- toolbar actions ----------
    def open_file(self):
        path = filedialog.askopenfilename(title="Open email file", filetypes=[("Email/Text", "*.eml *.txt *.mail"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            self.input_text.delete("1.0", "end")
            self.input_text.insert("1.0", content)
            self.status_var.set(f"Loaded file: {path}")
            self.scan_path(path)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open file:\n{e}")

    def save_input(self):
        content = self.input_text.get("1.0", "end").strip()
        if not content:
            messagebox.showwarning("No content", "Nothing to save.")
            return
        path = filedialog.asksaveasfilename(title="Save input", defaultextension=".txt", filetypes=[("Text", "*.txt"), ("EML", "*.eml"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            self.status_var.set(f"Saved input to: {path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save file:\n{e}")

    def paste_clipboard(self):
        try:
            text = self.clipboard_get()
        except Exception:
            messagebox.showwarning("Clipboard", "Clipboard is empty or unavailable.")
            return
        self.input_text.delete("1.0", "end")
        self.input_text.insert("1.0", text)
        try:
            self.notebook.select(self.tab_source)
        except Exception:
            pass
        self.status_var.set("Clipboard content pasted into the message source (replaced).")

    def paste_and_scan(self):
        """One-click workflow: copy Gmail 'Show original' -> clipboard, then Paste & Scan."""
        try:
            text = self.clipboard_get()
        except Exception:
            messagebox.showwarning("Clipboard", "Clipboard is empty or unavailable. Copy the email's 'Show original' source first.")
            return
        if not str(text).strip():
            messagebox.showwarning("Clipboard", "Clipboard is empty. Copy the email's 'Show original' source first.")
            return
        self.input_text.delete("1.0", "end")
        self.input_text.insert("1.0", text)
        self.status_var.set("Pasted clipboard content. Scanning...")
        self.scan_current()

    def clear_input(self):
        self.input_text.delete("1.0", "end")
        self._reset_result_view()
        self.status_var.set("Message source and result view cleared. Session history is unchanged.")

    def choose_whitelist(self):
        path = filedialog.askopenfilename(title="Choose whitelist JSON", filetypes=[("JSON", "*.json"), ("All files", "*.*")])
        if not path:
            return
        ok, msg = validate_whitelist(path)
        if not ok:
            messagebox.showerror("Invalid whitelist", msg)
            return
        self.custom_whitelist_path.set(path)
        self.use_default_whitelist.set(False)
        self._refresh_whitelist_status()
        self.status_var.set(f"Using custom whitelist: {path}")

    def reload_whitelist(self):
        path = self._whitelist_target_path()
        if not path:
            messagebox.showwarning("Whitelist", "No whitelist is active. Enable the default whitelist or choose a file first.")
            return
        if not Path(path).is_file() and self.custom_whitelist_path.get().strip():
            messagebox.showerror("Whitelist", f"Whitelist file not found:\n{path}")
            return
        ok, msg = validate_whitelist(path)
        self._refresh_whitelist_status()
        if ok:
            messagebox.showinfo("Whitelist", msg)
            self.status_var.set(msg)
        else:
            messagebox.showerror("Whitelist", msg)
            self.status_var.set(msg)

    def clear_custom_whitelist(self):
        self.custom_whitelist_path.set("")
        self.use_default_whitelist.set(True)
        self._refresh_whitelist_status()
        self.status_var.set("Custom whitelist cleared; default whitelist.json is active if present.")

    def _selected_observable(self):
        for key, lb in self.obs_boxes.items():
            sel = lb.curselection()
            if sel:
                value = lb.get(sel[0])
                if value and not value.startswith("("):
                    return key, value
        return None, None

    def copy_selected_observable(self, key=None):
        if key:
            lb = self.obs_boxes.get(key)
            sel = lb.curselection() if lb is not None else ()
            value = lb.get(sel[0]) if sel else None
        else:
            _key, value = self._selected_observable()
        if not value or str(value).startswith("("):
            messagebox.showwarning("Observable", "Select an observable first.")
            return
        self._copy_text(str(value), "Observable")

    def add_selected_observable_to_whitelist(self):
        key, value = self._selected_observable()
        if not value:
            messagebox.showwarning("Whitelist", "Select an observable in the Observables tab first.")
            return
        path = self._whitelist_target_path()
        if not path:
            messagebox.showwarning("Whitelist", "Enable the default whitelist or choose a whitelist file first.")
            return
        kind = {"urls": "url", "emails": "email", "ips": "ip", "domains": "domain"}.get(key, "")
        if not kind:
            messagebox.showerror("Whitelist", f"Unsupported observable type: {key}")
            return
        try:
            added = add_exact_rule(path, kind, value)
        except WhitelistError as e:
            messagebox.showerror("Whitelist", str(e))
            return
        self._refresh_whitelist_status()
        if added:
            self.status_var.set(f"Added exact {kind} whitelist rule: {value}")
            if messagebox.askyesno("Whitelist updated", f"Added {kind} rule:\n{value}\n\nRescan the current message with the updated whitelist?"):
                self.scan_current()
        else:
            self.status_var.set(f"Whitelist rule already exists: {value}")

    def load_selected_sample(self):
        rel = self.sample_var.get()
        path = self._project_root() / "samples" / rel
        if not path.is_file():
            messagebox.showerror("Sample not found", f"Could not find sample: {path}")
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            self.input_text.delete("1.0", "end")
            self.input_text.insert("1.0", content)
            self.status_var.set(f"Loaded sample: {path.name}")
            self.scan_path(str(path))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load sample:\n{e}")

    # ---------- scanning ----------
    def _scanning_blocked(self):
        if self.batch_running:
            messagebox.showwarning("Batch scan running", "Wait for the batch scan to finish or cancel it first.")
            return True
        return False

    def scan_current(self):
        if self._scanning_blocked():
            return
        content = self.input_text.get("1.0", "end").strip()
        if not content:
            messagebox.showwarning("No content", "Please paste email content or open a file first.")
            return
        try:
            self._reset_log()
            self.notebook.select(self.tab_log)
            self._log("Starting analysis for pasted email content...")
            self._log(f"Whitelist: {self.whitelist_status_var.get()} | ML signal: {'on' if self.ml_enabled.get() else 'off'}")
            self._log("Parsing headers/body and extracting metadata...")
            self._log("Extracting observables (URLs, emails, IPs, domains) and applying whitelist...")
            self._log("Analyzing authentication header claims (SPF/DKIM/DMARC - unverified), URLs, content, and attachments...")
            result = scan_email(content, enable_ml=self.ml_enabled.get(), **self._wl_kwargs())
            case = scan_result_to_investigation(result, raw_email_text=content, source="pasted content")
            self.last_result = result
            self.last_result_source = "pasted content"
            self._log(f"Analysis complete: Verdict={result.verdict} Score={result.score} Findings={len(getattr(result,'findings',[]) or [])}")
            self._log(f"Investigation case created: {case.case_id} | evidence sha256={case.evidence[0].sha256[:16]}..." if case.evidence else f"Investigation case created: {case.case_id}")
            self._render_result(result, source="pasted content", raw=content, case=case)
            self._add_history(result, "pasted content", content, case)
            self.status_var.set("Scan completed for pasted content.")
            self.notebook.select(self.tab_scan)
        except Exception as e:
            self._log(f"ERROR: Scan failed - {e}")
            messagebox.showerror("Scan error", f"Failed to scan content:\n{e}")
            self.status_var.set("Scan failed.")

    def scan_path(self, path):
        if self._scanning_blocked():
            return
        try:
            self._reset_log()
            self.notebook.select(self.tab_log)
            self._log(f"Loading email: {path}")
            self._log(f"Whitelist: {self.whitelist_status_var.get()} | ML signal: {'on' if self.ml_enabled.get() else 'off'}")
            self._log("Parsing headers/body and extracting metadata...")
            self._log("Extracting observables (URLs, emails, IPs, domains) and applying whitelist...")
            self._log("Analyzing authentication header claims (SPF/DKIM/DMARC - unverified), URLs, content, and attachments...")
            result = scan_email_file(path, enable_ml=self.ml_enabled.get(), **self._wl_kwargs())
            self.last_result = result
            self.last_result_source = path
            raw = ""
            try:
                raw = Path(path).read_text(encoding="utf-8", errors="replace")
            except Exception:
                raw = self.input_text.get("1.0", "end")
            case = scan_result_to_investigation(result, raw_email_text=raw, source=str(path))
            self._log(f"Analysis complete: Verdict={result.verdict} Score={result.score} Findings={len(getattr(result,'findings',[]) or [])}")
            self._render_result(result, source=path, raw=raw, case=case)
            self._add_history(result, path, raw, case)
            self.status_var.set(f"Scan completed: {path}")
            self.notebook.select(self.tab_scan)
        except Exception as e:
            self._log(f"ERROR: Scan failed - {e}")
            messagebox.showerror("Scan error", f"Failed to scan file:\n{e}")

    def _read_raw_source(self, source):
        raw = ""
        if source and source != "pasted content":
            try:
                p = Path(str(source))
                if p.is_file():
                    raw = p.read_text(encoding="utf-8", errors="replace")
            except Exception:
                raw = ""
        if not raw:
            try:
                raw = self.input_text.get("1.0", "end")
            except Exception:
                raw = ""
        return raw

    def _render_result(self, result, source=None, raw=None, case=None):
        self.verdict_var.set(f"Verdict: {result.verdict}")
        self.score_var.set(f"Score: {result.score}")
        self.summary_var.set(result.summary or "")
        color = VERDICT_COLORS.get(result.verdict, OFFICE_TEXT)
        try:
            # verdict_label may be ttk.Label (foreground) or tk.Label (fg) in redesigned layout
            try:
                self.verdict_label.configure(foreground=color)
            except Exception:
                self.verdict_label.configure(fg=color)
        except Exception:
            pass
        self._draw_score_ring(result.score, color)
        auth = getattr(result, "auth_analysis", {}) or {}
        self.auth_var.set(f"SPF: {auth.get('spf','unknown')}   DKIM: {auth.get('dkim','unknown')}   DMARC: {auth.get('dmarc','unknown')} (header claims, unverified)")
        ml = getattr(result, "ml_analysis", {}) or {}
        if ml and ml.get("label") == "disabled":
            self.ml_var.set("ML: disabled for this scan (enable 'ML signal' in the toolbar).")
        elif ml:
            p = int(round(float(ml.get('phishing_probability', 0)) * 100))
            self.ml_var.set(f"ML: {ml.get('label','unknown')} - {p}% phishing likelihood - confidence {int(round(float(ml.get('confidence',0))*100))}%")
        else:
            self.ml_var.set("ML: --")
        recs = list(getattr(result, "recommendations", []) or [])
        if recs:
            self.recs_var.set("\n".join(f"• {r}" for r in recs))
        else:
            self.recs_var.set("No recommendations available for this result.")

        # Dashboard metrics
        try:
            findings_n = len(getattr(result, "findings", []) or [])
            urls_n = len(getattr(result, "urls", []) or [])
            self.metric_risk_var.set(f"{getattr(result,'score',0)}/100")
            self.metric_risk_label_var.set(str(getattr(result, "verdict", "Unknown")))
            self.metric_findings_var.set(str(findings_n))
            self.metric_urls_var.set(str(urls_n))
            auth_short = f"SPF {auth.get('spf','?')}  DKIM {auth.get('dkim','?')}  DMARC {auth.get('dmarc','?')}"
            ml_short = "ML off"
            if ml and ml.get("label") == "disabled":
                ml_short = "ML off"
            elif ml:
                ml_short = f"ML {ml.get('label','?')}"
            self.metric_auth_var.set(f"{auth_short} • {ml_short}")
            for lbl in (getattr(self, "metric_findings_value_label", None), getattr(self, "metric_urls_value_label", None), getattr(self, "metric_auth_value_label", None)):
                try:
                    if lbl is not None:
                        lbl.configure(fg=OFFICE_TEXT)
                except Exception:
                    pass
            try:
                if getattr(self, "metric_risk_value_label", None) is not None:
                    self.metric_risk_value_label.configure(fg=color)
            except Exception:
                pass
        except Exception:
            pass

        meta = getattr(result, "metadata", {}) or {}

        # --- email reading pane: header, verdict stamp, warning banner, body ---
        if raw is None:
            raw = self._read_raw_source(source)
        parsed = None
        if raw:
            try:
                parsed = parse_email_text(raw)
            except Exception:
                parsed = None

        subject = meta.get("subject") or (parsed.subject if parsed else "") or "(no subject)"
        sender = meta.get("from") or (parsed.sender if parsed else "") or "(unknown sender)"
        recipient = meta.get("to") or (parsed.to if parsed else "") or "(unknown recipient)"
        msg_date = meta.get("date") or (parsed.date if parsed else "") or "(no date)"
        self.read_subject_var.set(subject)
        self.read_from_var.set(sender)
        self.read_to_var.set(recipient)
        self.read_date_var.set(msg_date)
        try:
            self.read_route_var.set(f"{sender} → {recipient}")
        except Exception:
            pass
        self.read_auth_var.set(
            f"SPF {auth.get('spf','unknown')}  |  DKIM {auth.get('dkim','unknown')}  |  "
            f"DMARC {auth.get('dmarc','unknown')}  (unverified header claims)"
        )
        atts = meta.get("attachments") or []
        self.read_attach_var.set(", ".join(atts) if atts else "None")
        try:
            self.email_risk_text_var.set(f"{result.score} / 100")
            self._draw_email_risk_bar(result.score, color)
        except Exception:
            pass
        try:
            n_att = len(atts)
            self.badge_attach.configure(
                text=f"{n_att} attachment{'s' if n_att != 1 else ''}",
                bg=("#FBE7E4" if n_att > 0 else OFFICE_ACCENT_SOFT),
                fg=("#B23A2A" if n_att > 0 else OFFICE_ACCENT_DARK),
            )
        except Exception:
            pass

        verdict_text = str(result.verdict or "Unknown")
        self.stamp_var.set(f"{verdict_text.upper()}  {result.score}")
        try:
            self._set_verdict_pill(verdict_text, result.score)
        except Exception:
            try:
                self.stamp_label.configure(bg=color, fg="#FFFFFF")
            except Exception:
                pass
        try:
            self._set_auth_badges(auth.get("spf", "unknown"), auth.get("dkim", "unknown"), auth.get("dmarc", "unknown"))
        except Exception:
            pass
        try:
            self.summary_verdict_mini.set(verdict_text)
        except Exception:
            pass
        try:
            self._update_summary_panel(result)
        except Exception:
            pass

        if verdict_text in ("High Risk", "Critical", "Critical Risk"):
            self.banner_var.set("WARNING: This message shows strong phishing indicators. Do not click links, open attachments, or reply.")
            self.banner_label.configure(bg="#FBE4DF", fg="#9E2B1C")
        elif verdict_text in ("Suspicious", "Medium Risk"):
            self.banner_var.set("Caution: Suspicious signals were found. Verify the sender through an official channel before acting.")
            self.banner_label.configure(bg="#FCF0D8", fg="#8A5E13")
        elif verdict_text == "Low Risk":
            self.banner_var.set("No strong phishing indicators found. Stay cautious with unexpected links and attachments.")
            self.banner_label.configure(bg=OFFICE_ACCENT_SOFT, fg=OFFICE_ACCENT_DARK)
        else:
            self.banner_var.set("Review the findings below before acting on this message.")
            self.banner_label.configure(bg=OFFICE_ACCENT_SOFT, fg=OFFICE_MUTED)

        body = ""
        if parsed is not None:
            body = (parsed.body or "").strip()
        if not body:
            body = "(No readable text body found in this message.)"
        if len(body) > 20000:
            body = body[:20000] + "\n\n[...body truncated for display...]"
        self._set_text(self.read_body_text, body, readonly=True)

        # metadata
        for i in self.meta_tree.get_children():
            self.meta_tree.delete(i)

        fields = [
            ("Source", source or getattr(result, "source", "")),
            ("Subject", meta.get("subject", "")),
            ("From", meta.get("from", "")),
            ("Reply-To", meta.get("reply_to", "")),
            ("Return-Path", meta.get("return_path", "")),
            ("To", meta.get("to", "")),
            ("Date", meta.get("date", "")),
            ("Message-ID", meta.get("message_id", "")),
            ("Received hops", str(meta.get("received_count", 0))),
            ("Attachments", str(meta.get("attachment_count", 0))),
            ("Attachment names", ", ".join(meta.get("attachments", []) or [])),
            ("URLs (active)", str(meta.get("url_count", len(getattr(result, "urls", []) or [])))),
            ("URLs (all extracted)", str(meta.get("all_url_count", meta.get("url_count", 0)))),
            ("Whitelist applied", str(getattr(result, "whitelist_applied", False))),
            ("Whitelist path", str(meta.get("whitelist_path", "") or "(none)")),
            ("ML enabled", str(meta.get("ml_enabled", True))),
            ("Recommendations", str(len(recs))),
        ]
        for k, v in fields:
            self.meta_tree.insert("", "end", values=(k, v))

        # findings (severity-accent cards)
        findings = list(getattr(result, "findings", []) or [])
        if hasattr(self, "_render_finding_cards"):
            self._render_finding_cards(findings)
        elif getattr(self, "findings_tree", None):
            for i in self.findings_tree.get_children():
                self.findings_tree.delete(i)
            severity_tag = {"High": "high", "Medium": "medium", "Low": "low", "Critical": "high"}
            for f in findings:
                tag = severity_tag.get(str(f.severity), "")
                self.findings_tree.insert("", "end", values=(f.severity, f"+{f.score}", f.title, f.detail), tags=(tag,) if tag else ())
        cats = getattr(result, "category_scores", {}) or {}
        counts = {"high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = str(getattr(f, "severity", "")).lower()
            if sev in ("critical", "high"):
                counts["high"] += 1
            elif sev in ("medium", "suspicious"):
                counts["medium"] += 1
            elif sev == "low":
                counts["low"] += 1
        parts = []
        if counts["high"]: parts.append(f"{counts['high']} high")
        if counts["medium"]: parts.append(f"{counts['medium']} medium")
        if counts["low"]: parts.append(f"{counts['low']} low")
        breakdown = f" — {', '.join(parts)}" if parts else ""
        self.findings_info_var.set(f"⚠  {len(findings)} finding{'s' if len(findings)!=1 else ''}{breakdown}")
        # update summary card colors
        try:
            score = getattr(result, "score", 0) or 0
            self.summary_risk_card_label.configure(fg=("#B23A2A" if score >= 40 else OFFICE_TEXT))
            self.summary_findings_card_label.configure(fg=("#B23A2A" if len(findings) > 0 else OFFICE_TEXT))
            attn = len((getattr(result, "metadata", {}) or {}).get("attachments") or [])
            self.summary_attach_card_label.configure(fg=("#B23A2A" if attn > 0 else OFFICE_TEXT))
        except Exception:
            pass

        # quick text
        lines = []
        ml = getattr(result, "ml_analysis", {}) or {}
        cats = getattr(result, "category_scores", {}) or {}
        if ml and ml.get("label") == "disabled":
            lines.append("ML analysis: disabled for this scan.")
            lines.append("")
        elif ml:
            p = int(round(float(ml.get('phishing_probability', 0)) * 100))
            lines.append(f"ML analysis: {ml.get('label','unknown')} ({p}% phishing likelihood, confidence {int(round(float(ml.get('confidence',0))*100))}%)")
            if ml.get('top_indicators'):
                lines.append(f"  Indicators: {', '.join(ml.get('top_indicators', [])[:10])}")
            lines.append("")
        if cats:
            parts = [f"{k.replace('_',' ')}={v}" for k, v in cats.items() if v]
            if parts:
                lines.append("Category risk points: " + ", ".join(parts))
                lines.append("")
        sec = getattr(result, "security_assessment", {}) or {}
        cvss = sec.get("cvss_estimate", {}) or {}
        mitre = sec.get("mitre_attack", []) or []
        cwes = sec.get("cwe", []) or []
        if cvss or mitre or cwes:
            lines.append("Security assessment:")
            if cvss:
                lines.append(f"  CVSS triage: {cvss.get('base_score','-')} ({cvss.get('severity','Unknown')})  {cvss.get('vector','')}")
            if mitre:
                lines.append("  MITRE ATT&CK: " + ", ".join(f"{m.get('id','')}" for m in mitre))
            if cwes:
                lines.append("  CWE: " + ", ".join(f"{c.get('id','')}" for c in cwes))
            if not (sec.get("cve_references") or []):
                lines.append("  CVE: none auto-attributed (product/version-specific)")
            lines.append("")
        if recs:
            lines.append("Recommended actions:")
            for r in recs:
                lines.append(f"  - {r}")
            lines.append("")
        if result.urls:
            lines.append("Active URLs:")
            for u in result.urls:
                lines.append(f"  - {u}")
            lines.append("")
        if getattr(result, "findings", None):
            lines.append("Top findings:")
            for f in result.findings[:10]:
                lines.append(f"  [{f.severity} | +{f.score}] {f.title}")
        else:
            lines.append("No phishing indicators detected by current heuristics.")
        self._set_text(self.quick_text, "\n".join(lines), readonly=True)

        # observables
        obs = getattr(result, "observables", {}) or {}
        wl = obs.get("whitelisted", {}) or {}
        for key, lb in self.obs_boxes.items():
            lb.delete(0, "end")
            for item in obs.get(key, []) or []:
                lb.insert("end", item)
            if not (obs.get(key) or []):
                lb.insert("end", "(none)")
        self.obs_info_var.set(
            f"Active: urls={len(obs.get('urls',[]))} emails={len(obs.get('emails',[]))} ips={len(obs.get('ips',[]))} domains={len(obs.get('domains',[]))} | "
            f"Whitelisted: urls={len(wl.get('urls',[]))} emails={len(wl.get('emails',[]))} ips={len(wl.get('ips',[]))} domains={len(wl.get('domains',[]))}"
        )

        # report preview
        try:
            preview = result_to_json(result)
        except Exception:
            preview = json.dumps(getattr(result, "to_dict", lambda: {})(), indent=2, ensure_ascii=False)
        self._set_text(self.report_text, preview, readonly=True)

        # investigation case
        if case is None:
            try:
                case = scan_result_to_investigation(
                    result,
                    raw_email_text=raw or "",
                    source=str(source or getattr(result, "source", "") or "input"),
                )
            except Exception:
                case = None
        self.current_case = case
        self._render_case(case)

    def _render_case(self, case):
        if case is None:
            self.case_id_var.set("--")
            self.case_status_var.set("--")
            self.case_verdict_var.set("--")
            self.case_evidence_var.set("--")
            for item in self.case_timeline_tree.get_children():
                self.case_timeline_tree.delete(item)
            return
        self.case_id_var.set(case.case_id)
        self.case_status_var.set(f"{case.status} | created {str(case.created_at).replace('T', ' ')[:19]}")
        self.case_verdict_var.set(
            f"automated: {case.automated_verdict} ({case.risk_score}/100) | "
            f"analyst: {case.analyst_verdict or '(none)'}"
        )
        if case.evidence:
            ev = case.evidence[0]
            self.case_evidence_var.set(
                f"{ev.kind}: {ev.name}\nsha256: {ev.sha256}\nsize: {ev.size if ev.size is not None else '-'} bytes"
            )
        else:
            self.case_evidence_var.set("(no evidence item)")
        for item in self.case_timeline_tree.get_children():
            self.case_timeline_tree.delete(item)
        for event in case.timeline:
            when = str(event.timestamp).replace("T", " ")
            if len(when) >= 19:
                when = when[11:19]
            self.case_timeline_tree.insert("", "end", values=(when, event.event_type, event.message))
        for analyzer in case.analyzer_results:
            self.case_timeline_tree.insert(
                "", "end",
                values=("--", "analyzer", f"{analyzer.name}: {analyzer.status} / {analyzer.severity}"),
            )
        children = self.case_timeline_tree.get_children()
        if children:
            self.case_timeline_tree.see(children[-1])

    def case_set_verdict(self, verdict):
        if not self.current_case:
            messagebox.showwarning("Case", "Scan a message first to create an investigation case.")
            return
        self.current_case.set_analyst_verdict(verdict)
        self._render_case(self.current_case)
        self.status_var.set(f"Analyst verdict: {verdict or 'cleared'} (case {self.current_case.case_id}). Save Case JSON to persist.")

    def case_add_note(self):
        if not self.current_case:
            messagebox.showwarning("Case", "Scan a message first to create an investigation case.")
            return
        note = simpledialog.askstring("Add case note", "Analyst note:", parent=self)
        if not note:
            return
        try:
            self.current_case.add_note(note)
        except ValueError as e:
            messagebox.showwarning("Case", str(e))
            return
        self._render_case(self.current_case)
        self.status_var.set(f"Note added to case {self.current_case.case_id}. Save Case JSON to persist.")

    # ---------- history / exports ----------
    def _add_history(self, result, source, raw=None, case=None):
        if raw is None:
            raw = self._read_raw_source(source)
        if case is None:
            try:
                case = scan_result_to_investigation(result, raw_email_text=raw or "", source=str(source))
            except Exception:
                case = None
        item = {
            "time": datetime.datetime.now().strftime("%H:%M:%S"),
            "source": str(source),
            "raw": raw,
            "result": result,
            "case": case,
        }
        self.history.insert(0, item)
        self._rebuild_history_views(select_index=0)

    def _rebuild_history_views(self, select_index=0):
        try:
            n = len(self.history)
            self.session_scans_var.set(f"{n} scan{'s' if n != 1 else ''}")
        except Exception:
            pass
        for tree in (self.history_tree, self.mail_tree):
            for item in tree.get_children():
                tree.delete(item)
        severity_tag = {
            "Low Risk": "low",
            "Suspicious": "suspicious",
            "Medium Risk": "suspicious",
            "High Risk": "high",
            "Critical": "critical",
            "Critical Risk": "critical",
        }
        for item in self.history:
            result = item["result"]
            self.history_tree.insert(
                "", "end",
                values=(item["time"], item["source"], result.verdict, result.score, (result.summary or "")[:120]),
            )
            meta = getattr(result, "metadata", {}) or {}
            sender = meta.get("from", "") or "(unknown sender)"
            sender_display = sender.split("<")[0].strip().strip('"') or sender
            subject = meta.get("subject", "") or "(no subject)"
            self.mail_tree.insert(
                "", "end",
                values=(item["time"], sender_display, subject, result.verdict, result.score),
                tags=(severity_tag.get(str(result.verdict), ""),),
            )
        self.mail_frame.configure(text=f"Inbox - Scanned Messages ({len(self.history)})")
        if self.history:
            idx = max(0, min(select_index, len(self.history) - 1))
            for tree in (self.history_tree, self.mail_tree):
                children = tree.get_children()
                if idx < len(children):
                    tree.selection_set(children[idx])
                    tree.focus(children[idx])
        else:
            self._set_text(self.report_text, "", readonly=True)

    def _on_history_select(self, event=None):
        sel = self.history_tree.selection()
        if not sel:
            return
        idx = self.history_tree.index(sel[0])
        if 0 <= idx < len(self.history):
            try:
                self._set_text(self.report_text, result_to_json(self.history[idx]["result"]), readonly=True)
            except Exception:
                pass

    def reload_selected_history(self):
        sel = self.history_tree.selection()
        if not sel:
            messagebox.showwarning("History", "Select a history entry first.")
            return
        self._load_history_item(self.history_tree.index(sel[0]))

    def delete_selected_history(self):
        sel = self.history_tree.selection()
        if not sel:
            messagebox.showwarning("History", "Select a history entry first.")
            return
        idx = self.history_tree.index(sel[0])
        if 0 <= idx < len(self.history):
            removed = self.history.pop(idx)
            self._rebuild_history_views(select_index=idx)
            self.status_var.set(f"Removed history entry: {removed.get('source')}")

    def clear_history(self):
        if not self.history:
            messagebox.showinfo("History", "Session history is already empty.")
            return
        if not messagebox.askyesno("Clear history", "Clear all in-session scan history? This cannot be undone."):
            return
        self.history = []
        self._rebuild_history_views()
        self.status_var.set("Session history cleared.")

    def export_json(self):
        if not self.last_result:
            messagebox.showwarning("No result", "Scan an email or reload a history entry first.")
            return
        path = filedialog.asksaveasfilename(title="Export JSON report", defaultextension=".json", filetypes=[("JSON", "*.json")])
        if not path:
            return
        try:
            write_text(path, result_to_json(self.last_result))
            self.status_var.set(f"JSON report exported: {path}")
        except Exception as e:
            messagebox.showerror("Export error", f"Failed to export JSON:\n{e}")

    def export_html(self):
        if not self.last_result:
            messagebox.showwarning("No result", "Scan an email or reload a history entry first.")
            return
        path = filedialog.asksaveasfilename(title="Export HTML report", defaultextension=".html", filetypes=[("HTML", "*.html;*.htm")])
        if not path:
            return
        try:
            write_text(path, result_to_html(self.last_result))
            self.status_var.set(f"HTML report exported: {path}")
        except Exception as e:
            messagebox.showerror("Export error", f"Failed to export HTML:\n{e}")

    def export_case(self):
        case = self.current_case
        if case is None and self.last_result is not None:
            raw = self.input_text.get("1.0", "end")
            case = scan_result_to_investigation(self.last_result, raw_email_text=raw, source=self.last_result_source or "input")
            self.current_case = case
        if case is None:
            messagebox.showwarning("No case", "Scan an email first to create an investigation case.")
            return
        path = filedialog.asksaveasfilename(
            title="Save investigation case",
            defaultextension=".case.json",
            filetypes=[("Case JSON", "*.case.json"), ("JSON", "*.json")],
        )
        if not path:
            return
        case.add_event("case_exported", f"Case exported to {path}")
        result = DEFAULT_REGISTRY.export_case(case.to_dict(), path)
        self._render_case(case)
        if result.status == IntegrationStatus.SUCCEEDED:
            self.status_var.set(f"Investigation case saved: {path}")
        else:
            messagebox.showerror("Case export", f"{result.summary}\n" + "\n".join(result.errors))

    def copy_summary(self):
        if not self.last_result:
            messagebox.showwarning("No result", "Scan an email first.")
            return
        r = self.last_result
        lines = [f"Verdict: {r.verdict} (Score: {r.score})", r.summary or ""]
        recs = list(getattr(r, "recommendations", []) or [])
        if recs:
            lines.append("")
            lines.append("Recommended actions:")
            lines.extend(f"- {x}" for x in recs)
        if getattr(r, "findings", None):
            lines.append("")
            lines.append("Top findings:")
            lines.extend(f"- [{f.severity} | +{f.score}] {f.title}" for f in r.findings[:5])
        if self.current_case is not None:
            lines.append("")
            lines.append(f"Case: {self.current_case.case_id} | analyst verdict: {self.current_case.analyst_verdict or '(none)'}")
        self._copy_text("\n".join(lines), "Summary")

    def copy_findings(self):
        if not self.last_result or not getattr(self.last_result, "findings", None):
            messagebox.showwarning("Findings", "No findings to copy.")
            return
        text = "\n".join(
            f"[{f.severity} | +{f.score}] {f.title}: {f.detail}"
            for f in self.last_result.findings
        )
        self._copy_text(text, "Findings")

    def copy_selected_finding(self):
        text = getattr(self, "_selected_finding_text", "")
        if not text and getattr(self, "findings_tree", None):
            try:
                sel = self.findings_tree.selection()
                if sel:
                    vals = self.findings_tree.item(sel[0], "values")
                    if vals:
                        text = f"[{vals[0]} | {vals[1]}] {vals[2]}: {vals[3]}"
            except Exception:
                pass
        if not text:
            messagebox.showwarning("Findings", "Select a finding card first.")
            return
        self._copy_text(text, "Finding")

    def copy_log(self):
        if not self.analysis_log:
            messagebox.showwarning("Activity", "The activity log is empty.")
            return
        self._copy_text("\n".join(self.analysis_log), "Activity log")

    def clear_log(self):
        self._reset_log()
        self.status_var.set("Activity log cleared.")

    # ---------- summary panel actions / demo ----------
    def copy_summary_url(self):
        lb = getattr(self, "summary_url_list", None)
        if lb is None:
            return
        sel = lb.curselection()
        if not sel:
            messagebox.showwarning("URL", "Select a URL from the summary list first.")
            return
        idx = sel[0]
        val = None
        items = getattr(self, "_summary_url_items", [])
        if idx < len(items):
            val = items[idx]
        else:
            raw = str(lb.get(idx))
            val = raw.split("  [")[0] if "  [" in raw else raw
        if not val or str(val).startswith("("):
            return
        self._copy_text(str(val), "URL")

    def _action_whitelist_summary_url(self):
        lb = getattr(self, "summary_url_list", None)
        if lb is None:
            return
        sel = lb.curselection()
        if not sel:
            messagebox.showwarning("Whitelist", "Select a URL in the summary panel first.")
            return
        idx = sel[0]
        val = None
        items = getattr(self, "_summary_url_items", [])
        if idx < len(items):
            val = items[idx]
        else:
            raw = str(lb.get(idx))
            val = raw.split("  [")[0] if "  [" in raw else raw
        if not val or str(val).startswith("("):
            return
        # select in observables if present, else add directly
        try:
            if "urls" in getattr(self, "obs_boxes", {}):
                lb2 = self.obs_boxes["urls"]
                lb2.selection_clear(0, "end")
                for i in range(lb2.size()):
                    if lb2.get(i) == val:
                        lb2.selection_set(i)
                        lb2.activate(i)
                        break
        except Exception:
            pass
        target = self._whitelist_target_path()
        if not target:
            target = str(self._project_root() / "whitelist.json")
        try:
            changed, msg = add_exact_rule(target, "urls", str(val))
            self._refresh_whitelist_status()
            if changed:
                if messagebox.askyesno("Whitelist updated", f"{msg}\n\nRescan current message now?"):
                    self.rescan_current()
            else:
                messagebox.showinfo("Whitelist", msg)
        except Exception as e:
            messagebox.showerror("Whitelist", f"Failed to update whitelist:\n{e}")

    def _action_report_phishing(self):
        if not self.current_case:
            messagebox.showwarning("Case", "Scan a message first to report it.")
            return
        self.case_set_verdict("confirmed_phishing")
        try:
            self.status_var.set("Marked as phishing (analyst verdict). Use Save case to persist.")
        except Exception:
            pass

    def _load_demo_state(self):
        """Populate UI with a realistic phishing example for an informative loaded state."""
        if self.history or self.last_result:
            return
        sample = self._project_root() / "samples" / "phishing_with_auth_fail.eml"
        try:
            if sample.is_file():
                content = sample.read_text(encoding="utf-8", errors="replace")
                self.input_text.delete("1.0", "end")
                self.input_text.insert("1.0", content)
                result = scan_email(content, enable_ml=self.ml_enabled.get(), **self._wl_kwargs())
                case = scan_result_to_investigation(result, raw_email_text=content, source=str(sample))
                self.last_result = result
                self.last_result_source = str(sample)
                self._render_result(result, source=str(sample), raw=content, case=case)
                self._add_history(result, str(sample), content, case)
                self.status_var.set("Loaded demo phishing scan (samples/phishing_with_auth_fail.eml). Paste your own email to scan.")
                try:
                    self.notebook.select(self.tab_scan)
                except Exception:
                    pass
        except Exception:
            # keep default empty state if demo load fails
            pass

    # ---------- batch ----------
    def _set_batch_running(self, running):
        self.batch_running = bool(running)
        try:
            self.batch_start_btn.configure(state="disabled" if running else "normal")
            self.batch_cancel_btn.configure(state="normal" if running else "disabled")
        except Exception:
            pass

    def batch_scan(self):
        if self.batch_running:
            messagebox.showwarning("Batch scan", "A batch scan is already running. Cancel it before starting another.")
            return
        folder = filedialog.askdirectory(title="Choose folder containing .eml/.txt/.mail files")
        if not folder:
            return
        d = Path(folder)
        try:
            files = sorted([p for p in d.iterdir() if p.is_file() and p.suffix.lower() in (".eml", ".txt", ".mail")])
        except Exception as e:
            messagebox.showerror("Batch scan", f"Could not read the selected folder:\n{e}")
            return
        if not files:
            messagebox.showwarning("No files", "No .eml/.txt/.mail files found in the selected folder.")
            return
        for i in self.batch_tree.get_children():
            self.batch_tree.delete(i)
        self.batch_results = []
        self.batch_cases = []
        self.batch_files = [str(p) for p in files]
        self._batch_result_objects = {}
        self._batch_case_objects = {}
        self._batch_started = len(files)
        self._batch_cancel.clear()
        while not self._batch_queue.empty():
            try:
                self._batch_queue.get_nowait()
            except queue.Empty:
                break
        self._set_batch_running(True)
        try:
            self.batch_progress.configure(maximum=len(files), value=0)
        except Exception:
            pass
        self.batch_info_var.set(f"Scanning {len(files)} file(s) in {folder} ...")
        self.status_var.set(f"Batch scan started: {len(files)} file(s).")
        self.notebook.select(self.tab_batch)
        self._log(f"Batch scan started: {len(files)} file(s) in {folder}")
        wl = self._wl_kwargs()
        enable_ml = bool(self.ml_enabled.get())
        self._batch_worker = threading.Thread(
            target=self._batch_worker_run,
            args=([str(p) for p in files], wl, enable_ml),
            daemon=True,
        )
        self._batch_worker.start()
        self.after(120, self._poll_batch_queue)

    def _batch_worker_run(self, files, wl, enable_ml):
        total = len(files)
        for idx, path in enumerate(files, start=1):
            if self._batch_cancel.is_set():
                self._batch_queue.put(("cancelled", idx - 1, total))
                return
            self._batch_queue.put(("start", idx, total, Path(path).name))
            try:
                result = scan_email_file(path, enable_ml=enable_ml, **wl)
                result.source = path
                try:
                    raw = Path(path).read_text(encoding="utf-8", errors="replace")
                except Exception:
                    raw = ""
                case = scan_result_to_investigation(result, raw_email_text=raw, source=path)
                self._batch_queue.put(("result", idx, total, path, result, case))
            except Exception as e:
                self._batch_queue.put(("error", idx, total, path, str(e)))
        if self._batch_cancel.is_set():
            self._batch_queue.put(("cancelled", total, total))
        else:
            self._batch_queue.put(("done", total, total))

    def _poll_batch_queue(self):
        finished = False
        try:
            while True:
                msg = self._batch_queue.get_nowait()
                kind = msg[0]
                if kind == "start":
                    _, idx, total, name = msg
                    self.batch_info_var.set(f"Scanning {idx}/{total}: {name}")
                elif kind == "result":
                    _, idx, total, path, result, case = msg
                    rd = result.to_dict()
                    self.batch_results.append(rd)
                    self.batch_cases.append((path, case))
                    self._batch_result_objects[path] = result
                    self._batch_case_objects[path] = case
                    auth = rd.get("auth_analysis", {}) or {}
                    self.batch_tree.insert(
                        "", "end",
                        values=(Path(path).name, rd.get("verdict"), rd.get("score"),
                                len(rd.get("findings", []) or []), len(rd.get("urls", []) or []),
                                auth.get("spf", "unknown"), auth.get("dkim", "unknown"), auth.get("dmarc", "unknown")),
                    )
                    try:
                        self.batch_progress.configure(value=idx)
                    except Exception:
                        pass
                elif kind == "error":
                    _, idx, total, path, err = msg
                    self.batch_results.append({"source": path, "error": err})
                    self.batch_tree.insert("", "end", values=(Path(path).name, "ERROR", "-", "-", "-", "-", "-", "-"))
                    try:
                        self.batch_progress.configure(value=idx)
                    except Exception:
                        pass
                    self._log(f"Batch error on {Path(path).name}: {err}")
                elif kind == "cancelled":
                    _, done, total = msg
                    self._finish_batch(
                        f"Cancelled after {done}/{total} file(s). Completed rows were kept.",
                        cancelled=True,
                    )
                    finished = True
                    break
                elif kind == "done":
                    _, done, total = msg
                    errors = sum(1 for r in self.batch_results if r.get("error"))
                    self._finish_batch(
                        f"Scanned {done} file(s) | errors: {errors} | whitelist: {self.whitelist_status_var.get()} | ML: {'on' if self.ml_enabled.get() else 'off'}"
                    )
                    finished = True
                    break
        except queue.Empty:
            pass
        if not finished and self.batch_running:
            self.after(120, self._poll_batch_queue)

    def _finish_batch(self, message, cancelled=False):
        self._set_batch_running(False)
        self._batch_worker = None
        self.batch_info_var.set(message)
        self.status_var.set("Batch scan cancelled." if cancelled else "Batch scan complete.")
        self._log(message)
        try:
            self.notebook.select(self.tab_batch)
        except Exception:
            pass

    def cancel_batch_scan(self):
        if not self.batch_running:
            return
        self._batch_cancel.set()
        self.batch_info_var.set("Cancelling... waiting for the current file to finish.")
        self.status_var.set("Batch scan cancellation requested.")

    def export_batch_json(self):
        if not self.batch_results:
            messagebox.showwarning("No batch results", "Run a batch scan first.")
            return
        path = filedialog.asksaveasfilename(title="Export batch JSON report", defaultextension=".json", filetypes=[("JSON", "*.json")])
        if not path:
            return
        try:
            write_text(path, results_batch_to_json(self.batch_results))
            self.status_var.set(f"Batch JSON exported: {path}")
        except Exception as e:
            messagebox.showerror("Export error", f"Failed to export batch JSON:\n{e}")

    def export_batch_html(self):
        if not self.batch_results:
            messagebox.showwarning("No batch results", "Run a batch scan first.")
            return
        path = filedialog.asksaveasfilename(title="Export batch HTML report", defaultextension=".html", filetypes=[("HTML", "*.html;*.htm")])
        if not path:
            return
        try:
            write_text(path, results_batch_to_html(self.batch_results))
            self.status_var.set(f"Batch HTML exported: {path}")
        except Exception as e:
            messagebox.showerror("Export error", f"Failed to export batch HTML:\n{e}")

    def export_batch_cases(self):
        if not self.batch_cases:
            messagebox.showwarning("No batch cases", "Run a batch scan first (cases are created per scanned file).")
            return
        out_dir = filedialog.askdirectory(title="Choose output folder for investigation cases")
        if not out_dir:
            return
        out = Path(out_dir)
        try:
            out.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            messagebox.showerror("Case export", f"Could not create output folder:\n{e}")
            return
        written = 0
        failures = []
        for i, (src, case) in enumerate(self.batch_cases, start=1):
            stem = Path(src).stem or f"case_{i}"
            target = out / f"{stem}.case.json"
            n = 2
            while target.exists():
                target = out / f"{stem}_{n}.case.json"
                n += 1
            result = DEFAULT_REGISTRY.export_case(case.to_dict(), str(target))
            if result.status == IntegrationStatus.SUCCEEDED:
                written += 1
            else:
                failures.append(f"{target.name}: {result.summary}")
        if written:
            self.status_var.set(f"Investigation cases written: {written} -> {out}")
        if failures:
            messagebox.showwarning(
                "Case export",
                f"Wrote {written} case(s) to {out}.\n\nFailures:\n" + "\n".join(failures[:10]),
            )

    def _on_batch_double_click(self, event):
        sel = self.batch_tree.selection()
        if not sel:
            return
        vals = self.batch_tree.item(sel[0], "values")
        if not vals:
            return
        fname = vals[0]
        target = None
        for rd in self.batch_results:
            src = str(rd.get("source", ""))
            if Path(src).name == fname or src.endswith(fname):
                target = src
                break
        if not target:
            return
        result = self._batch_result_objects.get(target)
        if result is None:
            messagebox.showwarning("Batch item", "This row did not produce a scan result (it may have errored).")
            return
        case = self._batch_case_objects.get(target)
        try:
            content = Path(target).read_text(encoding="utf-8", errors="replace")
        except Exception:
            content = self.input_text.get("1.0", "end")
        self.input_text.delete("1.0", "end")
        self.input_text.insert("1.0", content)
        self.last_result = result
        self.last_result_source = target
        self._render_result(result, source=target, raw=content, case=case)
        self._add_history(result, target, content, case)
        self.status_var.set(f"Loaded batch result: {fname}")
        self.notebook.select(self.tab_scan)

    def _on_history_double_click(self, event):
        sel = self.history_tree.selection()
        if not sel:
            return
        self._load_history_item(self.history_tree.index(sel[0]))

    def _on_mail_double_click(self, event):
        sel = self.mail_tree.selection()
        if not sel:
            return
        self._load_history_item(self.mail_tree.index(sel[0]))

    def _load_history_item(self, index):
        if index < 0 or index >= len(self.history):
            return
        item = self.history[index]
        self.last_result = item["result"]
        self.last_result_source = item["source"]
        self._render_result(item["result"], source=item["source"], raw=item.get("raw"), case=item.get("case"))
        self.status_var.set(f"Reloaded message: {item['source']}")
        try:
            children = self.mail_tree.get_children()
            if 0 <= index < len(children):
                self.mail_tree.selection_set(children[index])
                self.mail_tree.focus(children[index])
        except Exception:
            pass
        self.notebook.select(self.tab_scan)


def main():
    app = PhishGuardApp()
    app.mainloop()


if __name__ == "__main__":
    main()




