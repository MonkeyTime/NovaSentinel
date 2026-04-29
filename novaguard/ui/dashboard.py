from __future__ import annotations

import re
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk

from novaguard import APP_NAME, APP_VERSION
from novaguard.attack import build_incident_graph, correlate_incident, correlate_scan_result, explain_incident, explain_scan_result
from novaguard.bootstrap import ensure_icon_assets
from novaguard.i18n import LANGUAGES, normalize_language, tr, trust_center_summary
from novaguard.models import AppSettings
from novaguard.research import research_summary


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")


DEFAULT_WINDOW_GEOMETRY = "1180x720"
MIN_WINDOW_SIZE = (1040, 640)


class NovaSentinelWindow(ctk.CTk):
    def __init__(self, engine) -> None:
        super().__init__()
        self.engine = engine
        self.title(f"{APP_NAME} {APP_VERSION}")
        settings: AppSettings = self.engine.get_snapshot()["settings"]
        self.language = normalize_language(settings.language)
        initial_geometry = settings.window_geometry or DEFAULT_WINDOW_GEOMETRY
        self.geometry(initial_geometry)
        self.minsize(*MIN_WINDOW_SIZE)
        self.last_window_geometry = initial_geometry
        self.protocol("WM_DELETE_WINDOW", self.hide_to_tray)
        self.bind("<Unmap>", self._handle_unmap)
        self.bind("<Configure>", self._track_window_geometry)

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.sidebar = ctk.CTkFrame(self, width=240, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.content = ctk.CTkFrame(self, corner_radius=18)
        self.content.grid(row=0, column=1, sticky="nsew", padx=18, pady=18)
        self.content.grid_rowconfigure(0, weight=1)
        self.content.grid_columnconfigure(0, weight=1)

        self.frames: dict[str, ctk.CTkFrame] = {}
        self.status_var = tk.StringVar(value=self.t("status.active"))
        self.scan_var = tk.StringVar(value="No scan yet")
        self.quick_summary_var = tk.StringVar(value=self.t("scan.counter", threats=0, files=0))
        self.scan_status_var = tk.StringVar(value=self.t("scan.ready"))
        self.settings_vars: dict[str, tk.Variable] = {}
        self.language_var = tk.StringVar(value=LANGUAGES[self.language])
        self.language_by_label = {label: code for code, label in LANGUAGES.items()}

        self.target_entry: ctk.CTkEntry | None = None
        self.progress_bar: ctk.CTkProgressBar | None = None
        self.scan_action_buttons: list[ctk.CTkButton] = []
        self.stop_scan_button: ctk.CTkButton | None = None
        self.result_tree: ttk.Treeview | None = None
        self.event_tree: ttk.Treeview | None = None
        self.forensic_tree: ttk.Treeview | None = None
        self.quarantine_tree: ttk.Treeview | None = None
        self.incident_tree: ttk.Treeview | None = None
        self.forensic_detail_text: ctk.CTkTextbox | None = None
        self.forensic_detail_by_key: dict[tuple[str, ...], str] = {}
        self.forensic_detail_signature: tuple[tuple[str, ...], str] | None = None
        self.incident_detail_text: ctk.CTkTextbox | None = None
        self.incident_detail_by_key: dict[tuple[str, ...], str] = {}
        self.incident_detail_signature: tuple[tuple[str, ...], str] | None = None
        self.scan_threat_tree: ttk.Treeview | None = None
        self.trust_text: ctk.CTkTextbox | None = None
        self.scan_threat_count_var = tk.StringVar(value=self.t("scan.threat_count", count=0))
        self.scan_threat_signature: tuple[tuple, ...] = ()
        self.trust_signature = ""
        self.tree_signatures: dict[int, tuple[tuple, ...]] = {}
        self.tree_columns: dict[int, tuple[str, ...]] = {}
        self.tree_headings: dict[int, dict[str, str]] = {}
        self.tree_sort_state: dict[int, tuple[str, bool]] = {}
        self.notifier = None
        self.language_change_callback = None
        self.previous_scan_in_progress = False
        self.last_notified_summary = ""
        self.window_icon = None
        self.hiding_to_tray = False
        self.current_view = "Dashboard"

        self._apply_window_icon()
        self._configure_tree_style()

        self._build_sidebar()
        self._build_views()
        self.show_view("Dashboard")
        self.after(1200, self.refresh_view)

    def _apply_window_icon(self) -> None:
        png_path, ico_path = ensure_icon_assets()
        try:
            self.iconbitmap(default=str(ico_path))
        except Exception:
            pass
        try:
            self.window_icon = tk.PhotoImage(file=str(png_path))
            self.iconphoto(True, self.window_icon)
        except Exception:
            self.window_icon = None

    def _build_sidebar(self) -> None:
        title = ctk.CTkLabel(self.sidebar, text="NovaSentinel", font=ctk.CTkFont(size=28, weight="bold"))
        title.pack(padx=24, pady=(28, 6), anchor="w")
        subtitle = ctk.CTkLabel(
            self.sidebar,
            text=self.t("subtitle"),
            text_color="#9ac8ba",
            justify="left",
        )
        subtitle.pack(padx=24, pady=(0, 18), anchor="w")
        for name, text_key in [
            ("Dashboard", "nav.dashboard"),
            ("Scan Center", "nav.scan"),
            ("Ransomware", "nav.ransomware"),
            ("Forensics", "nav.forensics"),
            ("Quarantine", "nav.quarantine"),
            ("Events", "nav.events"),
            ("Settings", "nav.settings"),
            ("Trust Center", "nav.trust"),
            ("Research", "nav.research"),
        ]:
            ctk.CTkButton(
                self.sidebar,
                text=self.t(text_key),
                anchor="w",
                fg_color="transparent",
                hover_color="#1f3c35",
                command=lambda value=name: self.show_view(value),
            ).pack(fill="x", padx=18, pady=6)
        status_box = ctk.CTkFrame(self.sidebar, fg_color="#102a25")
        status_box.pack(side="bottom", fill="x", padx=18, pady=18)
        ctk.CTkLabel(status_box, text=self.t("background_status"), font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=14, pady=(14, 4))
        ctk.CTkLabel(status_box, textvariable=self.status_var, wraplength=180, justify="left").pack(anchor="w", padx=14, pady=(0, 14))

    def _build_views(self) -> None:
        self.frames["Dashboard"] = self._dashboard_view()
        self.frames["Scan Center"] = self._scan_view()
        self.frames["Ransomware"] = self._ransomware_view()
        self.frames["Forensics"] = self._forensics_view()
        self.frames["Quarantine"] = self._quarantine_view()
        self.frames["Events"] = self._events_view()
        self.frames["Settings"] = self._settings_view()
        self.frames["Trust Center"] = self._trust_center_view()
        self.frames["Research"] = self._research_view()

    def _dashboard_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.content)
        frame.grid_columnconfigure((0, 1, 2), weight=1)
        frame.grid_rowconfigure(2, weight=1)

        hero = ctk.CTkFrame(frame, fg_color="#0f231f")
        hero.grid(row=0, column=0, columnspan=3, sticky="ew", padx=18, pady=18)
        ctk.CTkLabel(hero, text=self.t("dashboard.title"), font=ctk.CTkFont(size=30, weight="bold")).pack(anchor="w", padx=20, pady=(18, 4))
        ctk.CTkLabel(hero, textvariable=self.scan_var, text_color="#a8d5c4", wraplength=980, justify="left").pack(anchor="w", padx=20, pady=(0, 18))

        self._metric_card(frame, 1, 0, self.t("card.realtime.title"), self.t("card.realtime.body"))
        self._metric_card(frame, 1, 1, self.t("card.ransomware.title"), self.t("card.ransomware.body"))
        self._metric_card(frame, 1, 2, self.t("card.trust.title"), self.t("card.trust.body"))

        table_card = ctk.CTkFrame(frame)
        table_card.grid(row=2, column=0, columnspan=3, sticky="nsew", padx=18, pady=(0, 18))
        ctk.CTkLabel(table_card, text=self.t("dashboard.recent"), font=ctk.CTkFont(size=20, weight="bold")).pack(anchor="w", padx=18, pady=(18, 10))
        self.result_tree = self._make_tree(
            table_card,
            columns=("time", "severity", "score", "attack", "path", "action"),
            headings=(self.t("heading.time"), self.t("heading.severity"), self.t("heading.score"), self.t("heading.attack"), self.t("heading.path"), self.t("heading.action")),
            height=18,
        )
        self.result_tree.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        return frame

    def _metric_card(self, parent: ctk.CTkFrame, row: int, column: int, title: str, body: str) -> None:
        card = ctk.CTkFrame(parent, fg_color="#142d27")
        card.grid(row=row, column=column, sticky="nsew", padx=18, pady=(0, 18))
        ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=20, weight="bold")).pack(anchor="w", padx=18, pady=(18, 8))
        ctk.CTkLabel(card, text=body, wraplength=260, justify="left", text_color="#add8ca").pack(anchor="w", padx=18, pady=(0, 18))

    def _scan_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.content)
        frame.pack_propagate(False)
        header = ctk.CTkFrame(frame, fg_color="#102823")
        header.pack(fill="x", padx=18, pady=18)
        ctk.CTkLabel(header, text=self.t("scan.title"), font=ctk.CTkFont(size=28, weight="bold")).pack(anchor="w", padx=18, pady=(18, 4))
        ctk.CTkLabel(header, textvariable=self.quick_summary_var, text_color="#a0cebf").pack(anchor="w", padx=18, pady=(0, 18))

        actions = ctk.CTkFrame(frame)
        actions.pack(fill="x", padx=18, pady=(0, 18))
        quick_button = ctk.CTkButton(actions, text=self.t("scan.quick"), command=self.engine.quick_scan)
        quick_button.pack(side="left", padx=10, pady=14)
        full_button = ctk.CTkButton(actions, text=self.t("scan.full"), command=self.engine.full_scan)
        full_button.pack(side="left", padx=10, pady=14)
        pick_button = ctk.CTkButton(actions, text=self.t("scan.pick"), command=self.pick_custom_target)
        pick_button.pack(side="left", padx=10, pady=14)
        target_button = ctk.CTkButton(actions, text=self.t("scan.target"), command=self.scan_custom_target)
        target_button.pack(side="left", padx=10, pady=14)
        self.stop_scan_button = ctk.CTkButton(actions, text=self.t("scan.stop"), command=self.stop_scan, fg_color="#8f2b2b", hover_color="#6f2020", state="disabled")
        self.stop_scan_button.pack(side="left", padx=10, pady=14)
        self.scan_action_buttons = [quick_button, full_button, pick_button, target_button]
        self.target_entry = ctk.CTkEntry(actions, placeholder_text=self.t("scan.placeholder"))
        self.target_entry.pack(side="left", fill="x", expand=True, padx=10, pady=14)

        progress = ctk.CTkFrame(frame)
        progress.pack(fill="x", padx=18, pady=(0, 18))
        ctk.CTkLabel(progress, text=self.t("scan.progress"), font=ctk.CTkFont(size=18, weight="bold")).pack(anchor="w", padx=18, pady=(18, 8))
        ctk.CTkLabel(progress, textvariable=self.scan_status_var, text_color="#a0cebf", wraplength=980, justify="left").pack(anchor="w", padx=18, pady=(0, 8))
        self.progress_bar = ctk.CTkProgressBar(progress)
        self.progress_bar.pack(fill="x", padx=18, pady=(0, 18))
        self.progress_bar.set(0)

        threats_card = ctk.CTkFrame(frame)
        threats_card.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        ctk.CTkLabel(threats_card, text=self.t("scan.threats"), font=ctk.CTkFont(size=20, weight="bold")).pack(anchor="w", padx=18, pady=(18, 4))
        ctk.CTkLabel(threats_card, textvariable=self.scan_threat_count_var, text_color="#a0cebf").pack(anchor="w", padx=18, pady=(0, 10))
        self.scan_threat_tree = self._make_tree(
            threats_card,
            columns=("time", "severity", "score", "file", "detail", "evidence", "status"),
            headings=(self.t("heading.time"), self.t("heading.severity"), self.t("heading.score"), self.t("heading.file"), self.t("heading.detail"), self.t("heading.evidence"), self.t("heading.status")),
            height=12,
        )
        self.scan_threat_tree.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        self.scan_threat_tree.column("time", width=140, anchor="w")
        self.scan_threat_tree.column("severity", width=90, anchor="w")
        self.scan_threat_tree.column("score", width=70, anchor="w")
        self.scan_threat_tree.column("file", width=220, anchor="w")
        self.scan_threat_tree.column("detail", width=320, anchor="w")
        self.scan_threat_tree.column("evidence", width=220, anchor="w")
        self.scan_threat_tree.column("status", width=100, anchor="w")
        return frame

    def _ransomware_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.content)
        ctk.CTkLabel(frame, text=self.t("ransomware.title"), font=ctk.CTkFont(size=28, weight="bold")).pack(anchor="w", padx=18, pady=(18, 8))
        header = ctk.CTkFrame(frame, fg_color="#102823")
        header.pack(fill="x", padx=18, pady=(0, 12))
        ctk.CTkLabel(
            header,
            text=self.t("ransomware.body"),
            text_color="#a0cebf",
            wraplength=940,
            justify="left",
        ).pack(side="left", fill="x", expand=True, padx=18, pady=14)
        ctk.CTkButton(header, text=self.t("ransomware.panic"), command=self._confirm_panic_mode).pack(side="right", padx=18, pady=14)

        self.incident_tree = self._make_tree(
            frame,
            columns=("time", "severity", "score", "confidence", "attack", "reason", "status", "files", "recovery", "tags", "trigger"),
            headings=(self.t("heading.time"), self.t("heading.severity"), self.t("heading.score"), self.t("heading.confidence"), self.t("heading.attack"), self.t("heading.reason"), self.t("heading.status"), self.t("heading.files"), self.t("heading.recovery"), self.t("heading.tags"), self.t("heading.trigger")),
            height=18,
        )
        self.incident_tree.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        self.incident_tree.column("time", width=145, anchor="w")
        self.incident_tree.column("severity", width=90, anchor="w")
        self.incident_tree.column("score", width=70, anchor="w")
        self.incident_tree.column("confidence", width=90, anchor="w")
        self.incident_tree.column("attack", width=190, anchor="w")
        self.incident_tree.column("reason", width=145, anchor="w")
        self.incident_tree.column("status", width=95, anchor="w")
        self.incident_tree.column("files", width=70, anchor="w")
        self.incident_tree.column("recovery", width=80, anchor="w")
        self.incident_tree.column("tags", width=230, anchor="w")
        self.incident_tree.column("trigger", width=260, anchor="w")
        self.incident_tree.bind("<<TreeviewSelect>>", lambda _event: self._refresh_selected_incident_detail())
        detail_card = ctk.CTkFrame(frame, fg_color="#102823")
        detail_card.pack(fill="x", padx=18, pady=(0, 18))
        ctk.CTkLabel(detail_card, text="Incident detail", font=ctk.CTkFont(size=18, weight="bold")).pack(anchor="w", padx=18, pady=(12, 4))
        self.incident_detail_text = ctk.CTkTextbox(detail_card, height=130)
        self.incident_detail_text.pack(fill="x", padx=18, pady=(0, 14))
        self.incident_detail_text.insert("1.0", "Select an incident to inspect its behavior score, timeline, evidence and recovery coverage.")
        self.incident_detail_text.configure(state="disabled")
        return frame

    def _forensics_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.content)
        ctk.CTkLabel(frame, text=self.t("forensics.title"), font=ctk.CTkFont(size=28, weight="bold")).pack(anchor="w", padx=18, pady=(18, 8))
        header = ctk.CTkFrame(frame, fg_color="#102823")
        header.pack(fill="x", padx=18, pady=(0, 12))
        ctk.CTkLabel(
            header,
            text=self.t("forensics.body"),
            text_color="#a0cebf",
            wraplength=940,
            justify="left",
        ).pack(anchor="w", fill="x", padx=18, pady=14)

        self.forensic_tree = self._make_tree(
            frame,
            columns=("time", "severity", "score", "file", "processes", "modules", "files", "connections"),
            headings=(
                self.t("heading.time"),
                self.t("heading.severity"),
                self.t("heading.score"),
                self.t("heading.file"),
                self.t("heading.processes"),
                self.t("heading.modules"),
                self.t("heading.files"),
                self.t("heading.connections"),
            ),
            height=12,
        )
        self.forensic_tree.pack(fill="both", expand=True, padx=18, pady=(0, 12))
        self.forensic_tree.column("time", width=145, anchor="w")
        self.forensic_tree.column("severity", width=90, anchor="w")
        self.forensic_tree.column("score", width=70, anchor="w")
        self.forensic_tree.column("file", width=240, anchor="w")
        self.forensic_tree.column("processes", width=90, anchor="w")
        self.forensic_tree.column("modules", width=90, anchor="w")
        self.forensic_tree.column("files", width=90, anchor="w")
        self.forensic_tree.column("connections", width=110, anchor="w")
        self.forensic_tree.bind("<<TreeviewSelect>>", lambda _event: self._refresh_selected_forensic_detail())

        detail_card = ctk.CTkFrame(frame, fg_color="#102823")
        detail_card.pack(fill="both", padx=18, pady=(0, 18))
        ctk.CTkLabel(detail_card, text=self.t("forensics.detail"), font=ctk.CTkFont(size=18, weight="bold")).pack(anchor="w", padx=18, pady=(12, 4))
        self.forensic_detail_text = ctk.CTkTextbox(detail_card, height=230)
        self.forensic_detail_text.pack(fill="both", expand=True, padx=18, pady=(0, 14))
        self.forensic_detail_text.insert("1.0", self.t("forensics.empty"))
        self.forensic_detail_text.configure(state="disabled")
        return frame

    def _confirm_panic_mode(self) -> None:
        confirmed = messagebox.askyesno(
            self.t("ransomware.panic.confirm_title"),
            self.t("ransomware.panic.confirm_body"),
            parent=self,
        )
        if not confirmed:
            return
        self.engine.panic_mode()
        self.status_var.set(self.t("ransomware.panic.started"))

    def _quarantine_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.content)
        ctk.CTkLabel(frame, text=self.t("quarantine.title"), font=ctk.CTkFont(size=28, weight="bold")).pack(anchor="w", padx=18, pady=(18, 8))
        toolbar = ctk.CTkFrame(frame)
        toolbar.pack(fill="x", padx=18, pady=(0, 12))
        ctk.CTkButton(toolbar, text=self.t("quarantine.restore"), command=self.restore_selected).pack(side="left", padx=10, pady=12)
        ctk.CTkButton(toolbar, text=self.t("quarantine.delete"), command=self.delete_selected).pack(side="left", padx=10, pady=12)
        self.quarantine_tree = self._make_tree(
            frame,
            columns=("id", "name", "score", "reason", "time"),
            headings=(self.t("heading.id"), self.t("heading.name"), self.t("heading.score"), self.t("heading.reason"), self.t("heading.time")),
            height=18,
        )
        self.quarantine_tree.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        return frame

    def _events_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.content)
        ctk.CTkLabel(frame, text=self.t("events.title"), font=ctk.CTkFont(size=28, weight="bold")).pack(anchor="w", padx=18, pady=(18, 8))
        self.event_tree = self._make_tree(
            frame,
            columns=("time", "level", "title", "description"),
            headings=(self.t("heading.time"), self.t("heading.level"), self.t("heading.title"), self.t("heading.description")),
            height=20,
        )
        self.event_tree.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        return frame

    def _settings_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.content)
        ctk.CTkLabel(frame, text=self.t("settings.title"), font=ctk.CTkFont(size=28, weight="bold")).pack(anchor="w", padx=18, pady=(18, 8))
        form = ctk.CTkFrame(frame, fg_color="#132b26")
        form.pack(fill="x", padx=18, pady=(0, 18))

        settings: AppSettings = self.engine.get_snapshot()["settings"]
        self.settings_vars = {
            "realtime_enabled": tk.BooleanVar(value=settings.realtime_enabled),
            "process_guard_enabled": tk.BooleanVar(value=settings.process_guard_enabled),
            "ransomware_guard_enabled": tk.BooleanVar(value=settings.ransomware_guard_enabled),
            "automatic_quarantine": tk.BooleanVar(value=settings.automatic_quarantine),
        }
        for key, label in [
            ("realtime_enabled", self.t("settings.realtime")),
            ("process_guard_enabled", self.t("settings.process")),
            ("ransomware_guard_enabled", self.t("settings.ransomware")),
            ("automatic_quarantine", self.t("settings.auto_quarantine")),
        ]:
            ctk.CTkSwitch(form, text=label, variable=self.settings_vars[key], onvalue=True, offvalue=False).pack(anchor="w", padx=18, pady=10)

        language_row = ctk.CTkFrame(form, fg_color="transparent")
        language_row.pack(fill="x", padx=18, pady=(10, 0))
        ctk.CTkLabel(language_row, text=self.t("settings.language"), font=ctk.CTkFont(weight="bold")).pack(side="left", padx=(0, 12))
        self.language_var = tk.StringVar(value=LANGUAGES[self.language])
        ctk.CTkOptionMenu(language_row, values=list(LANGUAGES.values()), variable=self.language_var).pack(side="left")

        self.paths_box = ctk.CTkTextbox(form, height=160)
        self.paths_box.pack(fill="x", padx=18, pady=(10, 18))
        self.paths_box.insert("1.0", "\n".join(settings.scan_roots))

        controls = ctk.CTkFrame(frame)
        controls.pack(fill="x", padx=18)
        ctk.CTkButton(controls, text=self.t("settings.save"), command=self.save_settings).pack(side="left", padx=10, pady=14)
        return frame

    def _trust_center_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.content)
        ctk.CTkLabel(frame, text=self.t("trust.title"), font=ctk.CTkFont(size=28, weight="bold")).pack(anchor="w", padx=18, pady=(18, 8))
        self.trust_text = ctk.CTkTextbox(frame)
        self.trust_text.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        self.trust_text.insert("1.0", self._trust_center_text({}))
        self.trust_text.configure(state="disabled")
        return frame

    def _research_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.content)
        ctk.CTkLabel(frame, text=self.t("research.title"), font=ctk.CTkFont(size=28, weight="bold")).pack(anchor="w", padx=18, pady=(18, 8))
        text = ctk.CTkTextbox(frame)
        text.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        text.insert("1.0", research_summary(self.language))
        text.configure(state="disabled")
        return frame

    def _make_tree(self, parent, columns, headings, height=16) -> ttk.Treeview:
        tree = ttk.Treeview(parent, columns=columns, show="headings", height=height, style="Nova.Treeview")
        tree_key = id(tree)
        self.tree_columns[tree_key] = tuple(columns)
        self.tree_headings[tree_key] = dict(zip(columns, headings))
        for column, heading in zip(columns, headings):
            tree.heading(column, text=heading, command=lambda current=column, widget=tree: self._toggle_tree_sort(widget, current))
            tree.column(column, width=self._column_width(column), anchor="w", stretch=column not in {"score", "severity", "id"})
        self._configure_tree_tags(tree)
        return tree

    def _configure_tree_style(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(
            "Nova.Treeview",
            background="#0f211d",
            foreground="#d8eee5",
            fieldbackground="#0f211d",
            borderwidth=0,
            rowheight=30,
            font=("Segoe UI", 10),
        )
        style.configure(
            "Nova.Treeview.Heading",
            background="#173a32",
            foreground="#e5fff4",
            relief="flat",
            font=("Segoe UI", 10, "bold"),
            padding=(8, 6),
        )
        style.map(
            "Nova.Treeview",
            background=[("selected", "#246b59")],
            foreground=[("selected", "#ffffff")],
        )
        style.map("Nova.Treeview.Heading", background=[("active", "#215447")])

    def _configure_tree_tags(self, tree: ttk.Treeview) -> None:
        tree.tag_configure("row_even", background="#0f211d")
        tree.tag_configure("row_odd", background="#142a25")
        tree.tag_configure("severity_critical", foreground="#ff8b8b")
        tree.tag_configure("severity_high", foreground="#ffbf6b")
        tree.tag_configure("severity_medium", foreground="#f4d35e")
        tree.tag_configure("severity_low", foreground="#8fd8ff")
        tree.tag_configure("severity_info", foreground="#b9d8ce")
        tree.tag_configure("status_quarantined", foreground="#ff8b8b")
        tree.tag_configure("status_contained", foreground="#ffbf6b")
        tree.tag_configure("status_observed", foreground="#8fd8ff")
        tree.tag_configure("trusted", foreground="#7ee7b7")

    def _column_width(self, column: str) -> int:
        return {
            "id": 150,
            "time": 145,
            "severity": 92,
            "score": 72,
            "confidence": 96,
            "attack": 210,
            "path": 420,
            "file": 230,
            "detail": 360,
            "evidence": 280,
            "description": 560,
            "trigger": 300,
            "tags": 250,
            "status": 105,
            "action": 105,
            "processes": 92,
            "modules": 92,
            "connections": 120,
        }.get(column, 155)

    def show_view(self, name: str) -> None:
        for frame in self.frames.values():
            frame.grid_forget()
        self.frames[name].grid(row=0, column=0, sticky="nsew")
        self.current_view = name

    def t(self, key: str, **kwargs) -> str:
        return tr(self.language, key, **kwargs)

    def _rebuild_interface(self) -> None:
        view = self.current_view if self.current_view in self.frames else "Dashboard"
        self.sidebar.destroy()
        self.content.destroy()

        self.sidebar = ctk.CTkFrame(self, width=240, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.content = ctk.CTkFrame(self, corner_radius=18)
        self.content.grid(row=0, column=1, sticky="nsew", padx=18, pady=18)
        self.content.grid_rowconfigure(0, weight=1)
        self.content.grid_columnconfigure(0, weight=1)

        self.frames = {}
        self.target_entry = None
        self.progress_bar = None
        self.scan_action_buttons = []
        self.stop_scan_button = None
        self.result_tree = None
        self.event_tree = None
        self.forensic_tree = None
        self.quarantine_tree = None
        self.incident_tree = None
        self.forensic_detail_text = None
        self.forensic_detail_by_key = {}
        self.forensic_detail_signature = None
        self.incident_detail_text = None
        self.incident_detail_by_key = {}
        self.incident_detail_signature = None
        self.scan_threat_tree = None
        self.trust_text = None
        self.tree_signatures.clear()
        self.tree_columns.clear()
        self.tree_headings.clear()
        self.tree_sort_state.clear()
        self.scan_threat_signature = ()
        self.trust_signature = ""
        self.language_var.set(LANGUAGES[self.language])

        self._build_sidebar()
        self._build_views()
        self.show_view(view)

    def hide_to_tray(self) -> None:
        self._save_window_geometry()
        self.hiding_to_tray = True
        self.withdraw()
        self.after(100, self._finish_hide_to_tray)

    def show_from_tray(self) -> None:
        self._restore_window_geometry()
        self.deiconify()
        if self.state() == "iconic":
            self.state("normal")
        self.lift()
        self.focus_force()

    def _handle_unmap(self, event=None) -> None:
        if event is not None and event.widget is not self:
            return
        if self.hiding_to_tray:
            return
        self.after(50, self._hide_iconified_window)

    def _hide_iconified_window(self) -> None:
        if self.hiding_to_tray:
            return
        try:
            if self.state() == "iconic":
                self.hide_to_tray()
        except tk.TclError:
            return

    def _finish_hide_to_tray(self) -> None:
        self.hiding_to_tray = False

    def _track_window_geometry(self, event=None) -> None:
        if event is not None and event.widget is not self:
            return
        try:
            if self.state() != "normal":
                return
            geometry = self.geometry()
        except tk.TclError:
            return
        if self._is_restorable_geometry(geometry):
            self.last_window_geometry = geometry

    def _save_window_geometry(self) -> None:
        try:
            state = self.state()
            if state not in {"normal", "zoomed", "iconic"}:
                return
            self.update_idletasks()
            current_geometry = self.geometry()
        except tk.TclError:
            return
        geometry = self.last_window_geometry
        if state in {"normal", "zoomed"} and self._is_restorable_geometry(current_geometry):
            geometry = current_geometry
            self.last_window_geometry = geometry
        if not self._is_restorable_geometry(geometry):
            return
        if self.engine.get_snapshot()["settings"].window_geometry == geometry:
            return
        self.engine.update_window_geometry(geometry)

    def _restore_window_geometry(self) -> None:
        geometry = self.engine.get_snapshot()["settings"].window_geometry
        if not self._is_restorable_geometry(geometry):
            geometry = DEFAULT_WINDOW_GEOMETRY
        try:
            self.geometry(geometry)
        except tk.TclError:
            self.geometry(DEFAULT_WINDOW_GEOMETRY)

    def _is_restorable_geometry(self, geometry: str) -> bool:
        if not geometry or "x" not in geometry:
            return False
        try:
            dimensions = geometry.split("+", 1)[0].split("-", 1)[0]
            width, height = [int(value) for value in dimensions.split("x", 1)]
        except (ValueError, IndexError):
            return False
        return width >= MIN_WINDOW_SIZE[0] and height >= MIN_WINDOW_SIZE[1]

    def pick_custom_target(self) -> None:
        folder = filedialog.askdirectory()
        if folder and self.target_entry:
            self.target_entry.delete(0, "end")
            self.target_entry.insert(0, folder)

    def scan_custom_target(self) -> None:
        if self.target_entry:
            self.engine.custom_scan(self.target_entry.get().strip())

    def stop_scan(self) -> None:
        if self.engine.cancel_scan():
            self.scan_status_var.set(self.t("scan.stopping_status"))

    def set_notifier(self, notifier) -> None:
        self.notifier = notifier

    def set_language_change_callback(self, callback) -> None:
        self.language_change_callback = callback

    def restore_selected(self) -> None:
        if not self.quarantine_tree:
            return
        selected = self.quarantine_tree.selection()
        if not selected:
            return
        values = self.quarantine_tree.item(selected[0], "values")
        self.engine.quarantine.restore(values[0])
        self.refresh_view()

    def delete_selected(self) -> None:
        if not self.quarantine_tree:
            return
        selected = self.quarantine_tree.selection()
        if not selected:
            return
        values = self.quarantine_tree.item(selected[0], "values")
        self.engine.quarantine.delete(values[0])
        self.refresh_view()

    def save_settings(self) -> None:
        roots = [line.strip() for line in self.paths_box.get("1.0", "end").splitlines() if line.strip()]
        current: AppSettings = self.engine.get_snapshot()["settings"]
        previous_language = self.language
        current.realtime_enabled = bool(self.settings_vars["realtime_enabled"].get())
        current.process_guard_enabled = bool(self.settings_vars["process_guard_enabled"].get())
        current.ransomware_guard_enabled = bool(self.settings_vars["ransomware_guard_enabled"].get())
        current.automatic_quarantine = bool(self.settings_vars["automatic_quarantine"].get())
        current.language = self.language_by_label.get(self.language_var.get(), "en")
        current.scan_roots = roots
        self.engine.update_settings(current)
        if current.language != previous_language:
            self.language = normalize_language(current.language)
            if self.language_change_callback:
                self.language_change_callback(self.language)
            self._rebuild_interface()

    def refresh_view(self) -> None:
        try:
            snapshot = self.engine.get_snapshot()
            state = snapshot["state"]
            self.language = normalize_language(snapshot["settings"].language)
            self.status_var.set(self.t("status.active") if snapshot["settings"].realtime_enabled else self.t("status.paused"))
            self.scan_var.set(state["last_scan_summary"])
            self.quick_summary_var.set(self.t("scan.counter", threats=state["threats_found"], files=state["files_scanned"]))
            self._refresh_scan_controls(state)
            if self.progress_bar:
                self.progress_bar.set(float(state["scan_progress"]))
            self._refresh_scan_threats(snapshot.get("current_scan_threats", []))
            if self.result_tree:
                self._refresh_tree(
                    self.result_tree,
                    [
                        (
                            item["scanned_at"],
                            item["severity"],
                            item["score"],
                            self._attack_summary_for_result(item),
                            item["path"],
                            item.get("action_taken", "none"),
                        )
                        for item in reversed(snapshot["history"][-40:])
                    ],
                )
            if self.event_tree:
                self._refresh_tree(
                    self.event_tree,
                    [
                        (item["timestamp"], item["level"], item["title"], item["description"])
                        for item in reversed(snapshot["events"][-60:])
                    ],
                )
            if self.forensic_tree:
                self._refresh_forensics(snapshot["history"])
            if self.quarantine_tree:
                self._refresh_tree(
                    self.quarantine_tree,
                    [
                        (item["id"], item["original_name"], item["score"], item["reason"], item["quarantined_at"])
                        for item in snapshot["quarantine"]
                    ],
                    preserve_selection=True,
                )
            if self.incident_tree:
                incident_rows: list[tuple] = []
                self.incident_detail_by_key = {}
                for item in reversed(snapshot.get("incidents", [])[-120:]):
                    row = (
                        item.get("timestamp", ""),
                        str(item.get("severity", "")).upper(),
                        item.get("behavior_score", ""),
                        item.get("confidence", ""),
                        self._attack_summary_for_incident(item),
                        item.get("reason", ""),
                        item.get("status", ""),
                        len(item.get("related_paths", [])),
                        len(item.get("recovery_files", [])),
                        "; ".join(item.get("tags", [])[:3]),
                        item.get("trigger_path", ""),
                    )
                    incident_rows.append(row)
                    self.incident_detail_by_key[self._row_key(row)] = self._incident_detail(item)
                self._refresh_tree(
                    self.incident_tree,
                    incident_rows,
                    preserve_selection=True,
                )
                self._refresh_selected_incident_detail()
            self._refresh_trust_center(snapshot.get("telemetry", {}))
            if self.previous_scan_in_progress and not state["scan_in_progress"]:
                self._notify_scan_transition(state["last_scan_summary"])
            self.previous_scan_in_progress = bool(state["scan_in_progress"])
        except Exception as exc:
            self.status_var.set(f"UI refresh recovered: {exc}")
        finally:
            self.after(1200, self.refresh_view)

    def _refresh_scan_controls(self, state: dict) -> None:
        in_progress = bool(state.get("scan_in_progress"))
        stopping = bool(state.get("scan_cancel_requested"))
        for button in self.scan_action_buttons:
            button.configure(state="disabled" if in_progress else "normal")
        if self.target_entry:
            self.target_entry.configure(state="disabled" if in_progress else "normal")
        if self.stop_scan_button:
            self.stop_scan_button.configure(
                state="disabled" if not in_progress or stopping else "normal",
                text=self.t("scan.stopping") if stopping else self.t("scan.stop"),
            )
        if stopping:
            self.scan_status_var.set(self.t("scan.stopping_status"))
        elif in_progress:
            self.scan_status_var.set(str(state.get("scan_label", "Scanning...")))
        else:
            self.scan_status_var.set(self.t("scan.ready"))

    def _refresh_tree(self, tree: ttk.Treeview, rows: list[tuple], preserve_selection: bool = False) -> None:
        rows = self._apply_tree_sort(tree, rows)
        signature = tuple(rows)
        tree_key = id(tree)
        if self.tree_signatures.get(tree_key) == signature:
            return
        self.tree_signatures[tree_key] = signature

        selected_key = None
        focused_key = None
        if preserve_selection:
            selected = tree.selection()
            if selected:
                selected_values = tree.item(selected[0], "values")
                if selected_values:
                    selected_key = selected_values[0]
            focused = tree.focus()
            if focused:
                focused_values = tree.item(focused, "values")
                if focused_values:
                    focused_key = focused_values[0]

        for item in tree.get_children():
            tree.delete(item)
        selection_item = ""
        focus_item = ""
        for index, row in enumerate(rows):
            item_id = tree.insert("", "end", values=row, tags=self._tree_tags_for_row(row, index))
            if preserve_selection and selected_key is not None and row and row[0] == selected_key:
                selection_item = item_id
            if preserve_selection and focused_key is not None and row and row[0] == focused_key:
                focus_item = item_id
        if preserve_selection and selection_item:
            tree.selection_set(selection_item)
            tree.see(selection_item)
        if preserve_selection and focus_item:
            tree.focus(focus_item)

    def _toggle_tree_sort(self, tree: ttk.Treeview, column: str) -> None:
        tree_key = id(tree)
        current_column, current_reverse = self.tree_sort_state.get(tree_key, ("", False))
        reverse = False if current_column != column else not current_reverse
        self.tree_sort_state[tree_key] = (column, reverse)
        self._update_tree_headings(tree)
        rows = [tree.item(item, "values") for item in tree.get_children()]
        self.tree_signatures.pop(tree_key, None)
        self._refresh_tree(tree, rows, preserve_selection=True)

    def _apply_tree_sort(self, tree: ttk.Treeview, rows: list[tuple]) -> list[tuple]:
        tree_key = id(tree)
        columns = self.tree_columns.get(tree_key, ())
        sort_state = self.tree_sort_state.get(tree_key)
        if not sort_state or sort_state[0] not in columns:
            self._update_tree_headings(tree)
            return list(rows)
        column, reverse = sort_state
        column_index = columns.index(column)
        sorted_rows = sorted(rows, key=lambda row: self._sortable_value(row[column_index] if column_index < len(row) else ""), reverse=reverse)
        self._update_tree_headings(tree)
        return sorted_rows

    def _update_tree_headings(self, tree: ttk.Treeview) -> None:
        tree_key = id(tree)
        heading_map = self.tree_headings.get(tree_key, {})
        sort_column, reverse = self.tree_sort_state.get(tree_key, ("", False))
        for column, heading in heading_map.items():
            suffix = ""
            if column == sort_column:
                suffix = " v" if reverse else " ^"
            tree.heading(column, text=f"{heading}{suffix}", command=lambda current=column, widget=tree: self._toggle_tree_sort(widget, current))

    def _sortable_value(self, value):
        text = str(value).strip()
        if not text:
            return (2, "")
        numeric_candidate = text.replace(",", ".")
        try:
            return (0, float(numeric_candidate))
        except ValueError:
            pass
        lowered = text.lower()
        if len(text) >= 19 and text[4:5] == "-" and text[7:8] == "-":
            return (1, text)
        return (1, lowered)

    def _row_key(self, row) -> tuple[str, ...]:
        return tuple(str(value) for value in row)

    def _tree_tags_for_row(self, row: tuple, index: int = 0) -> tuple[str, ...]:
        values = [str(value).casefold() for value in row]
        joined = " | ".join(values)
        tags = ["row_even" if index % 2 == 0 else "row_odd"]
        if any(value in {"critical", "error"} for value in values):
            tags.append("severity_critical")
        elif "high" in values:
            tags.append("severity_high")
        elif any(value in {"medium", "warning"} for value in values):
            tags.append("severity_medium")
        elif "low" in values:
            tags.append("severity_low")
        elif "info" in values:
            tags.append("severity_info")
        if "quarantined" in joined or "blocked" in joined:
            tags.append("status_quarantined")
        elif "contained" in joined or "panic" in joined:
            tags.append("status_contained")
        elif "observed" in joined or "recovery_evidence" in joined:
            tags.append("status_observed")
        if "trusted-publisher" in joined or "valid authenticode" in joined:
            tags.append("trusted")
        return tuple(tags)

    def _attack_summary_for_result(self, item: dict) -> str:
        attack = item.get("attack") or correlate_scan_result(item)
        return self._short_cell_text(attack.get("summary") or "None", 72)

    def _attack_summary_for_incident(self, incident: dict) -> str:
        attack = incident.get("attack") or correlate_incident(incident)
        return self._short_cell_text(attack.get("summary") or "None", 72)

    def _xai_summary_for_result(self, item: dict) -> str:
        xai = item.get("xai") or explain_scan_result(item)
        parts = []
        for contribution in xai.get("top_contributions", [])[:3]:
            category = contribution.get("category", "signal")
            points = contribution.get("points", "")
            evidence = contribution.get("evidence", "")
            parts.append(f"{category} +{points}: {evidence}")
        if xai.get("counter_evidence"):
            parts.append("Counter-evidence present")
        return self._short_cell_text("; ".join(parts) or "No XAI contribution", 180)

    def _xai_summary_for_incident(self, incident: dict) -> str:
        xai = incident.get("xai") or explain_incident(incident)
        parts = []
        for contribution in xai.get("top_contributions", [])[:4]:
            signal = contribution.get("signal", "signal")
            value = contribution.get("value", "")
            parts.append(f"{signal}={value}")
        if xai.get("counter_evidence"):
            parts.append("counter-evidence present")
        return self._short_cell_text("; ".join(parts) or "No XAI contribution", 180)

    def _short_cell_text(self, text: str, limit: int = 96) -> str:
        cleaned = " ".join(str(text).split())
        if len(cleaned) <= limit:
            return cleaned
        return f"{cleaned[: max(0, limit - 3)].rstrip()}..."

    def _refresh_forensics(self, history: list[dict]) -> None:
        if not self.forensic_tree:
            return
        rows: list[tuple] = []
        self.forensic_detail_by_key = {}
        for item in reversed(history[-120:]):
            post_alert = item.get("post_alert") or {}
            if not post_alert:
                continue
            process_count, module_count, open_file_count, connection_count = self._forensic_counts(post_alert)
            row = (
                item.get("scanned_at", ""),
                str(item.get("severity", "")).upper(),
                item.get("score", ""),
                Path(item.get("path", "")).name,
                process_count,
                module_count,
                open_file_count,
                connection_count,
            )
            rows.append(row)
            self.forensic_detail_by_key[self._row_key(row)] = self._forensic_detail(item)
        self._refresh_tree(self.forensic_tree, rows, preserve_selection=True)
        self._refresh_selected_forensic_detail()

    def _forensic_counts(self, post_alert: dict) -> tuple[int, int, int, int]:
        processes = post_alert.get("matched_processes", []) or []
        modules = sum(len(process.get("memory_maps", []) or []) for process in processes)
        open_files = sum(len(process.get("open_files", []) or []) for process in processes)
        connections = sum(len(process.get("connections", []) or []) for process in processes)
        return int(post_alert.get("matched_process_count", len(processes))), modules, open_files, connections

    def _refresh_selected_forensic_detail(self) -> None:
        if not self.forensic_tree or not self.forensic_detail_text:
            return
        selected = self.forensic_tree.selection()
        if not selected:
            first = self.forensic_tree.get_children()
            if first:
                selected = (first[0],)
                self.forensic_tree.selection_set(first[0])
                self.forensic_tree.focus(first[0])
            else:
                self.forensic_detail_signature = None
                self.forensic_detail_text.configure(state="normal")
                self.forensic_detail_text.delete("1.0", "end")
                self.forensic_detail_text.insert("1.0", self.t("forensics.empty"))
                self.forensic_detail_text.configure(state="disabled")
                return
        values = self.forensic_tree.item(selected[0], "values")
        row_key = self._row_key(values)
        detail = self.forensic_detail_by_key.get(row_key, self.t("forensics.empty"))
        signature = (row_key, detail)
        if self.forensic_detail_signature == signature:
            return
        self.forensic_detail_signature = signature
        self.forensic_detail_text.configure(state="normal")
        self.forensic_detail_text.delete("1.0", "end")
        self.forensic_detail_text.insert("1.0", detail)
        self.forensic_detail_text.configure(state="disabled")

    def _forensic_detail(self, item: dict) -> str:
        post_alert = item.get("post_alert") or {}
        processes = post_alert.get("matched_processes", []) or []
        notes = post_alert.get("notes", []) or []
        lines = [
            f"Alert: {Path(item.get('path', '')).name} | score {item.get('score', 'n/a')} | {str(item.get('severity', '')).upper()}",
            f"Collected: {post_alert.get('collected_at', '')}",
            f"Trigger: {post_alert.get('trigger_reason', '')} | {post_alert.get('trigger_path', '')}",
            "",
        ]
        if notes:
            lines.append("Notes:")
            lines.extend(f"- {note}" for note in notes[:4])
            lines.append("")
        if not processes:
            lines.append("No process snapshot was available for this alert.")
            return "\n".join(lines)
        for index, process in enumerate(processes, start=1):
            lines.extend(
                [
                    f"Process {index}: {process.get('name', '')} [{process.get('pid', '')}]",
                    f"  Exe: {process.get('exe', '')}",
                    f"  User: {process.get('username', '')} | Parent PID: {process.get('ppid', '')} | Status: {process.get('status', '')}",
                    f"  Started: {process.get('create_time', '')}",
                    f"  Cmd: {' '.join(process.get('cmdline', []) or [])}",
                ]
            )
            children = process.get("children", []) or []
            if children:
                lines.append("  Children:")
                lines.extend(f"  - {child.get('name', '')} [{child.get('pid', '')}] {child.get('exe', '')}" for child in children[:6])
            open_files = process.get("open_files", []) or []
            if open_files:
                lines.append("  Open files:")
                lines.extend(f"  - {path}" for path in open_files[:8])
            connections = process.get("connections", []) or []
            if connections:
                lines.append("  Connections:")
                lines.extend(
                    f"  - {conn.get('local', '')} -> {conn.get('remote', '')} {conn.get('status', '')}"
                    for conn in connections[:8]
                )
            memory_maps = process.get("memory_maps", []) or []
            if memory_maps:
                lines.append("  Mapped modules:")
                lines.extend(
                    f"  - {module.get('path', '')} rss={module.get('rss', 0)} private={module.get('private', 0)}"
                    for module in memory_maps[:12]
                )
            lines.append("")
        return "\n".join(lines).strip()

    def _refresh_selected_incident_detail(self) -> None:
        if not self.incident_tree or not self.incident_detail_text:
            return
        selected = self.incident_tree.selection()
        if not selected:
            first = self.incident_tree.get_children()
            if first:
                selected = (first[0],)
                self.incident_tree.selection_set(first[0])
                self.incident_tree.focus(first[0])
            else:
                self.incident_detail_signature = None
                return
        values = self.incident_tree.item(selected[0], "values")
        row_key = self._row_key(values)
        detail = self.incident_detail_by_key.get(row_key, "Incident detail is not available yet.")
        signature = (row_key, detail)
        if self.incident_detail_signature == signature:
            return
        self.incident_detail_signature = signature
        self.incident_detail_text.configure(state="normal")
        self.incident_detail_text.delete("1.0", "end")
        self.incident_detail_text.insert("1.0", detail)
        self.incident_detail_text.configure(state="disabled")

    def _incident_detail(self, incident: dict) -> str:
        signals = incident.get("signals", {})
        timeline = incident.get("timeline", [])
        evidence = incident.get("evidence", [])
        related_paths = incident.get("related_paths", [])
        attack = incident.get("attack") or correlate_incident(incident)
        xai = incident.get("xai") or explain_incident(incident)
        graph = incident.get("incident_graph") or build_incident_graph({**incident, "attack": attack})
        lines = [
            f"Model: {incident.get('behavior_model', 'legacy')}",
            f"Score: {incident.get('behavior_score', 'n/a')}/100 | Confidence: {incident.get('confidence', 'n/a')} | Status: {incident.get('status', 'n/a')}",
            f"Signals: {signals.get('sensitive_file_count', len(related_paths))} sensitive file(s), {signals.get('directory_count', 'n/a')} folder(s), {signals.get('extension_count', 'n/a')} extension family/families, {signals.get('burst_rate_per_second', 'n/a')} file(s)/s",
            f"Recovery coverage: {signals.get('recovery_coverage_percent', 0)}% | Protected-root hits: {signals.get('protected_root_hits', 0)}",
            f"Tags: {', '.join(incident.get('tags', [])) or 'none'}",
            "",
            f"MITRE ATT&CK: {attack.get('summary') or 'None'}",
        ]
        for technique in attack.get("techniques", [])[:5]:
            lines.append(
                f"- {technique.get('technique_id')} {technique.get('name')} | confidence {technique.get('confidence')} | {', '.join(technique.get('tactics', []))}"
            )
        lines.extend(
            [
                "",
                f"XAI: {self._xai_summary_for_incident(incident)}",
            ]
        )
        counter_evidence = xai.get("counter_evidence", []) or []
        if counter_evidence:
            lines.append("Counter-evidence:")
            lines.extend(f"- {item.get('signal', '')}: {item.get('explanation', '')}" for item in counter_evidence[:4])
        lines.extend(
            [
                "",
                f"Incident graph: {len(graph.get('nodes', []))} node(s), {len(graph.get('edges', []))} edge(s)",
            ]
        )
        for edge in graph.get("edges", [])[:8]:
            lines.append(f"- {edge.get('source', '')} -> {edge.get('target', '')} [{edge.get('relation', '')}]")
        lines.extend(["", "Timeline:"])
        lines.extend(f"- {step.get('time', '')} [{step.get('step', '')}] {step.get('detail', '')}" for step in timeline[:6])
        lines.append("")
        lines.append("Evidence:")
        lines.extend(f"- {item}" for item in evidence[:6])
        if related_paths:
            lines.append("")
            lines.append("Affected sample:")
            lines.extend(f"- {path}" for path in related_paths[:4])
        return "\n".join(lines)

    def _refresh_scan_threats(self, threats: list[dict]) -> None:
        if not self.scan_threat_tree:
            return
        self.scan_threat_count_var.set(self.t("scan.threat_count", count=len(threats)))
        rows: list[tuple] = []
        for threat in threats:
            hits = threat.get("hits", []) or [{}]
            for hit in hits:
                rows.append(
                    (
                        threat.get("scanned_at", ""),
                        str(threat.get("severity", "")).upper(),
                        str(threat.get("score", "")),
                        Path(threat.get("path", "")).name,
                        hit.get("explanation", threat.get("threat_label", "")),
                        hit.get("evidence", ""),
                        threat.get("action_taken", "none"),
                    )
                )
            post_alert = threat.get("post_alert") or {}
            if post_alert:
                rows.append(
                    (
                        threat.get("scanned_at", ""),
                        str(threat.get("severity", "")).upper(),
                        str(threat.get("score", "")),
                        Path(threat.get("path", "")).name,
                        "Post-alert process/memory context",
                        self._post_alert_evidence(post_alert),
                        threat.get("action_taken", "none"),
                    )
                )
            attack_summary = self._attack_summary_for_result(threat)
            if attack_summary and attack_summary != "None":
                rows.append(
                    (
                        threat.get("scanned_at", ""),
                        str(threat.get("severity", "")).upper(),
                        str(threat.get("score", "")),
                        Path(threat.get("path", "")).name,
                        "MITRE ATT&CK correlation",
                        attack_summary,
                        threat.get("action_taken", "none"),
                    )
                )
            xai_summary = self._xai_summary_for_result(threat)
            if xai_summary and xai_summary != "No XAI contribution":
                rows.append(
                    (
                        threat.get("scanned_at", ""),
                        str(threat.get("severity", "")).upper(),
                        str(threat.get("score", "")),
                        Path(threat.get("path", "")).name,
                        "XAI explanation",
                        xai_summary,
                        threat.get("action_taken", "none"),
                    )
                )
        signature = tuple(rows)
        if signature == self.scan_threat_signature:
            return
        self.scan_threat_signature = signature
        self._refresh_tree(self.scan_threat_tree, rows)

    def _post_alert_evidence(self, post_alert: dict) -> str:
        process_count = post_alert.get("matched_process_count", 0)
        processes = post_alert.get("matched_processes", []) or []
        if not processes:
            notes = post_alert.get("notes", []) or []
            return "; ".join(str(item) for item in notes[:2])
        process = processes[0]
        maps = len(process.get("memory_maps", []) or [])
        open_files = len(process.get("open_files", []) or [])
        connections = len(process.get("connections", []) or [])
        return f"{process_count} process(es), {maps} mapped module(s), {open_files} open file(s), {connections} connection(s)"

    def _refresh_trust_center(self, telemetry: dict) -> None:
        if not self.trust_text:
            return
        text = self._trust_center_text(telemetry)
        if text == self.trust_signature:
            return
        self.trust_signature = text
        self.trust_text.configure(state="normal")
        self.trust_text.delete("1.0", "end")
        self.trust_text.insert("1.0", text)
        self.trust_text.configure(state="disabled")

    def _trust_center_text(self, telemetry: dict) -> str:
        lines = [trust_center_summary(self.language), "", self.t("trust.telemetry.title")]
        summary = telemetry.get("summary") or self.t("trust.telemetry.pending")
        lines.append(f"- {summary}")
        collected_at = telemetry.get("collected_at")
        if collected_at:
            lines.append(f"- {self.t('trust.telemetry.checked')}: {collected_at}")
        services = telemetry.get("services", {})
        for label_key, service_key in [
            ("trust.telemetry.sysmon", "sysmon"),
            ("trust.telemetry.defender", "defender"),
            ("trust.telemetry.security", "windows_security"),
        ]:
            service = services.get(service_key, {})
            if not service:
                lines.append(f"- {self.t(label_key)}: {self.t('trust.telemetry.pending')}")
                continue
            installed = self.t("trust.telemetry.installed") if service.get("installed") else self.t("trust.telemetry.not_installed")
            state = service.get("state", "unknown")
            lines.append(f"- {self.t(label_key)}: {installed}, {state}")
        lines.append("")
        lines.append(self.t("trust.telemetry.note"))
        return "\n".join(lines)

    def _notify_scan_transition(self, summary: str) -> None:
        if not summary or summary == self.last_notified_summary:
            return
        localized_summary = self._localized_scan_summary(summary)
        title = self.t("notify.completed")
        if "failed" in summary.lower():
            title = self.t("notify.interrupted")
        elif "stopped" in summary.lower():
            title = self.t("notify.stopped")
        if self.notifier:
            self.notifier(title, localized_summary)
        if self.state() != "withdrawn":
            box = messagebox.showinfo if title == self.t("notify.completed") else messagebox.showwarning
            box(title, localized_summary)
        self.last_notified_summary = summary

    def _localized_scan_summary(self, summary: str) -> str:
        label_keys = {
            "Quick scan": "scan.quick",
            "Full scan": "scan.full",
            "Custom scan": "scan.custom",
        }
        completed = re.match(r"^(?P<label>.+) completed: (?P<scanned>\d+) files, (?P<found>\d+) threats\.$", summary)
        if completed:
            label = self.t(label_keys.get(completed.group("label"), completed.group("label")))
            return self.t("summary.completed", label=label, scanned=completed.group("scanned"), found=completed.group("found"))
        stopped = re.match(r"^(?P<label>.+) stopped: (?P<scanned>\d+) files, (?P<found>\d+) threats\.$", summary)
        if stopped:
            label = self.t(label_keys.get(stopped.group("label"), stopped.group("label")))
            return self.t("summary.stopped", label=label, scanned=stopped.group("scanned"), found=stopped.group("found"))
        failed = re.match(r"^(?P<label>.+) failed after (?P<scanned>\d+) files: (?P<reason>.*)$", summary)
        if failed:
            label = self.t(label_keys.get(failed.group("label"), failed.group("label")))
            return self.t("summary.failed", label=label, scanned=failed.group("scanned"), reason=failed.group("reason"))
        return summary
