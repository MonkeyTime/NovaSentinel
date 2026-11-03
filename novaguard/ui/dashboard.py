from __future__ import annotations

import os
import re
import threading
from dataclasses import replace
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk

from novaguard import APP_NAME, APP_VERSION
from novaguard.attack import build_incident_graph, correlate_incident, correlate_scan_result, explain_incident, explain_scan_result
from novaguard.bootstrap import ensure_icon_assets
from novaguard.core.updater import UpdateInfo, download_update_installer, fetch_latest_update, launch_update_installer
from novaguard.i18n import LANGUAGES, normalize_language, tr, trust_center_summary
from novaguard.models import AppSettings
from novaguard.research import research_summary
from novaguard.core.premium import fetch_latest_premium_update
from novaguard.ui.theme import COLORS
from novaguard.ui.workspace import WorkspaceViews, NAV


ctk.set_default_color_theme("blue")
ctk.ThemeManager.theme["CTk"]["fg_color"] = COLORS["bg"]
ctk.ThemeManager.theme["CTkFrame"]["fg_color"] = COLORS["panel"]
ctk.ThemeManager.theme["CTkFrame"]["top_fg_color"] = COLORS["panel_soft"]
ctk.ThemeManager.theme["CTkLabel"]["text_color"] = COLORS["text"]
ctk.ThemeManager.theme["CTkFont"].update(family="Segoe UI", size=12)
ctk.ThemeManager.theme["CTkButton"].update(fg_color=COLORS["button"], hover_color=COLORS["button_hover"],
                                          text_color=("#ffffff", "#ffffff"), corner_radius=8)
ctk.ThemeManager.theme["CTkEntry"].update(fg_color=COLORS["panel"], border_color=COLORS["line"],
                                         text_color=COLORS["text"], placeholder_text_color=COLORS["text_soft"], border_width=1, corner_radius=8)
ctk.ThemeManager.theme["CTkSwitch"].update(progress_color=COLORS["accent"], fg_color=COLORS["line"],
                                          button_color=("#ffffff", "#eceef6"), text_color=COLORS["text"])
ctk.ThemeManager.theme["CTkOptionMenu"].update(fg_color=COLORS["panel_lift"], button_color=COLORS["panel_soft"],
                                              button_hover_color=COLORS["line"], text_color=COLORS["text"])
ctk.ThemeManager.theme["CTkTextbox"].update(fg_color=COLORS["panel"], border_color=COLORS["line"], text_color=COLORS["text"])
ctk.ThemeManager.theme["CTkScrollbar"].update(button_color=COLORS["line"], button_hover_color=COLORS["text_soft"])


DEFAULT_WINDOW_GEOMETRY = "1180x720"
MIN_WINDOW_SIZE = (1040, 640)


class NovaSentinelWindow(WorkspaceViews, ctk.CTk):
    def __init__(self, engine) -> None:
        super().__init__()
        self.engine = engine
        self.title(f"{APP_NAME} {APP_VERSION}")
        settings: AppSettings = self.engine.get_snapshot()["settings"]
        ctk.set_appearance_mode(settings.appearance_mode)
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

        self._build_shell()

        self.frames: dict[str, ctk.CTkFrame] = {}
        self.status_var = tk.StringVar(value=self.t("status.active"))
        self.scan_var = tk.StringVar(value="No scan yet")
        self.quick_summary_var = tk.StringVar(value=self.t("scan.counter", threats=0, files=0))
        self.scan_status_var = tk.StringVar(value=self.t("scan.ready"))
        self.settings_vars: dict[str, tk.Variable] = {}
        self.language_var = tk.StringVar(value=LANGUAGES[self.language])
        self.dark_mode_var = tk.BooleanVar(value=settings.appearance_mode == "dark")
        self.language_by_label = {label: code for code, label in LANGUAGES.items()}
        self.premium_key_var = tk.StringVar(value="")
        self.premium_status_var = tk.StringVar(value="")
        self.premium_plan_var = tk.StringVar(value="")
        self.premium_customer_var = tk.StringVar(value="")
        self.premium_expires_var = tk.StringVar(value="")
        self.premium_license_var = tk.StringVar(value="")
        self.premium_device_var = tk.StringVar(value="")
        self.premium_key_mask_var = tk.StringVar(value="")
        self.premium_feedback_var = tk.StringVar(value="")
        self.premium_features_var = tk.StringVar(value="")
        self.premium_activate_button: ctk.CTkButton | None = None
        self.premium_refresh_button: ctk.CTkButton | None = None
        self.premium_key_entry: ctk.CTkEntry | None = None
        self.premium_status_label: ctk.CTkLabel | None = None
        self.premium_features_title_label: ctk.CTkLabel | None = None
        self.premium_features_value_label: ctk.CTkLabel | None = None

        self.update_info: UpdateInfo | None = None
        self.update_button: ctk.CTkButton | None = None
        self.first_nav_button: ctk.CTkButton | None = None
        self.nav_buttons: dict[str, ctk.CTkButton] = {}
        self.update_check_in_progress = False
        self.update_install_in_progress = False
        self.update_notified_tag = ""
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
        self.review_feedback_var = tk.StringVar(value="")
        self.trust_signature = ""
        self.tree_signatures: dict[int, tuple[tuple, ...]] = {}
        self.tree_columns: dict[int, tuple[str, ...]] = {}
        self.tree_headings: dict[int, dict[str, str]] = {}
        self.tree_sort_state: dict[int, tuple[str, bool]] = {}
        self.notifier = None
        self.language_change_callback = None
        self.previous_scan_in_progress = False
        self.scan_animation_tick = 0
        self.scan_progress_indeterminate = False
        self.last_notified_summary = ""
        self.window_icon = None
        self.hiding_to_tray = False
        self.current_view = "Dashboard"

        self._apply_window_icon()
        self._configure_tree_style()

        self._build_topbar()
        self._build_sidebar()
        self._build_views()
        self.show_view("Dashboard")
        self._refresh_workspace(self.engine.get_snapshot())
        self.bind("<Control-Key-1>", lambda event: self.show_view("Dashboard"))
        self.bind("<Control-Key-2>", lambda event: self.show_view("Scan Center"))
        self.bind("<Control-comma>", lambda event: self.show_view("Settings"))
        self.after(1200, self.refresh_view)
        self.after(3500, self.check_for_updates)

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
        self.frames["Premium"] = self._premium_view()
        for frame in self.frames.values():
            frame.configure(fg_color=COLORS["bg"], corner_radius=0)


    def review_selected_threat(self, action: str) -> None:
        selected = self.scan_threat_tree.selection() if self.scan_threat_tree else ()
        if not selected:
            self.review_feedback_var.set(self.t("review.select"))
            return
        path = str(self.scan_threat_tree.item(selected[0], "values")[3])
        if action == "quarantine":
            if not messagebox.askyesno(self.t("review.quarantine"), self.t("review.confirm", path=path), parent=self):
                return
            success, message = self.engine.quarantine_current_threat(path)
        else:
            success, message = self.engine.ignore_current_threat(path)
        self.review_feedback_var.set(self.t("review.updated") if success else message)
        self._refresh_scan_threats(self.engine.get_snapshot().get("current_scan_threats", []))

    def _ransomware_view(self) -> ctk.CTkFrame:
        frame = self._page(scroll=True)
        self._page_heading(frame, self.t("ransomware.title"), self.u("expert"))
        header = ctk.CTkFrame(frame, fg_color=COLORS["panel"])
        header.pack(fill="x", padx=18, pady=(0, 12))
        ctk.CTkLabel(
            header,
            text=self.t("ransomware.body"),
            text_color=COLORS["text_soft"],
            wraplength=600,
            justify="left",
        ).pack(fill="x", padx=18, pady=14)
        actions = ctk.CTkFrame(header, fg_color="transparent")
        actions.pack(fill="x", padx=18, pady=(0, 14))
        self._button(actions, self.t("ransomware.panic"), self._confirm_panic_mode, kind="secondary").pack(side="left")
        self._button(actions, self.t("ransomware.release_panic"), self._confirm_release_panic_mode, kind="secondary").pack(side="left", padx=10)

        self.incident_tree = self._make_tree(
            frame,
            columns=("time", "severity", "score", "confidence", "attack", "reason", "status", "files", "recovery", "tags", "trigger"),
            headings=(self.t("heading.time"), self.t("heading.severity"), self.t("heading.score"), self.t("heading.confidence"), self.t("heading.attack"), self.t("heading.reason"), self.t("heading.status"), self.t("heading.files"), self.t("heading.recovery"), self.t("heading.tags"), self.t("heading.trigger")),
            height=10,
        )
        self.incident_tree.container.pack(fill="both", expand=True, padx=18, pady=(0, 12))
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
        detail_card = ctk.CTkFrame(frame, fg_color=COLORS["panel"])
        detail_card.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        ctk.CTkLabel(detail_card, text="Incident detail", font=ctk.CTkFont(size=18, weight="bold")).pack(anchor="w", padx=18, pady=(12, 4))
        self.incident_detail_text = ctk.CTkTextbox(detail_card, height=210)
        self.incident_detail_text.pack(fill="both", expand=True, padx=18, pady=(0, 14))
        self.incident_detail_text.insert("1.0", "Select an incident to inspect its behavior score, timeline, evidence and recovery coverage.")
        self.incident_detail_text.configure(state="disabled")
        return frame

    def _forensics_view(self) -> ctk.CTkFrame:
        frame = self._page(scroll=True)
        self._page_heading(frame, self.t("forensics.title"), self.t("forensics.body"))

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
        self.forensic_tree.container.pack(fill="both", expand=True, padx=18, pady=(0, 12))
        self.forensic_tree.column("time", width=145, anchor="w")
        self.forensic_tree.column("severity", width=90, anchor="w")
        self.forensic_tree.column("score", width=70, anchor="w")
        self.forensic_tree.column("file", width=240, anchor="w")
        self.forensic_tree.column("processes", width=90, anchor="w")
        self.forensic_tree.column("modules", width=90, anchor="w")
        self.forensic_tree.column("files", width=90, anchor="w")
        self.forensic_tree.column("connections", width=110, anchor="w")
        self.forensic_tree.bind("<<TreeviewSelect>>", lambda _event: self._refresh_selected_forensic_detail())

        detail_card = ctk.CTkFrame(frame, fg_color=COLORS["panel"])
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

    def _confirm_release_panic_mode(self) -> None:
        confirmed = messagebox.askyesno(
            self.t("ransomware.release_panic.confirm_title"),
            self.t("ransomware.release_panic.confirm_body"),
            parent=self,
        )
        if not confirmed:
            return
        self.engine.release_panic_mode()
        self.status_var.set(self.t("ransomware.release_panic.done"))


    def _premium_view(self) -> ctk.CTkFrame:
        frame = self._page(scroll=True)
        self._page_heading(frame, self.t("premium.title"), self.u("premium_body"))

        status_card = ctk.CTkFrame(frame, fg_color=COLORS["panel_soft"])
        status_card.pack(fill="x", padx=18, pady=(0, 12))
        ctk.CTkLabel(status_card, text=self.t("premium.status_title"), font=ctk.CTkFont(weight="bold")).pack(
            anchor="w", padx=18, pady=(18, 8)
        )
        self.premium_status_label = ctk.CTkLabel(
            status_card,
            textvariable=self.premium_status_var,
            justify="left",
            wraplength=600,
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        self.premium_status_label.pack(anchor="w", padx=18, pady=(0, 12))

        features_card = ctk.CTkFrame(frame, fg_color=COLORS["panel"])
        features_card.pack(fill="x", padx=18, pady=(0, 12))
        self.premium_features_title_label = ctk.CTkLabel(
            features_card,
            text=self.t("premium.active_features_title"),
            font=ctk.CTkFont(size=15, weight="bold"),
        )
        self.premium_features_title_label.pack(anchor="w", padx=18, pady=(14, 8))
        self.premium_features_value_label = ctk.CTkLabel(
            features_card,
            textvariable=self.premium_features_var,
            justify="left",
            wraplength=600,
        )
        self.premium_features_value_label.pack(anchor="w", padx=18, pady=(0, 18))

        entitlement_card = ctk.CTkFrame(frame, fg_color=COLORS["panel_soft"])
        entitlement_card.pack(fill="x", padx=18, pady=(0, 12))
        ctk.CTkLabel(entitlement_card, text=self.t("premium.entitlements_title"), font=ctk.CTkFont(weight="bold")).pack(
            anchor="w", padx=18, pady=(14, 10)
        )
        details_grid = ctk.CTkFrame(entitlement_card, fg_color="transparent")
        details_grid.pack(fill="x", padx=18, pady=(0, 16))
        self._add_premium_detail_row(details_grid, self._premium_localize("premium.customer", "Customer"), self.premium_customer_var, row=0, col=0)
        self._add_premium_detail_row(details_grid, self._premium_localize("premium.license", "License"), self.premium_license_var, row=0, col=1)
        self._add_premium_detail_row(details_grid, self._premium_localize("premium.plan", "Plan"), self.premium_plan_var, row=1, col=0)
        self._add_premium_detail_row(details_grid, self._premium_localize("premium.expires", "Expires"), self.premium_expires_var, row=1, col=1)
        self._add_premium_detail_row(details_grid, self._premium_localize("premium.device", "Device"), self.premium_device_var, row=2, col=0)
        self._add_premium_detail_row(details_grid, self._premium_localize("premium.key_hint", "Key"), self.premium_key_mask_var, row=2, col=1)

        activation_card = ctk.CTkFrame(frame, fg_color=COLORS["panel"])
        activation_card.pack(fill="x", padx=18, pady=(0, 18))
        ctk.CTkLabel(activation_card, text=self.t("premium.activate"), font=ctk.CTkFont(size=18, weight="bold")).pack(anchor="w", padx=18, pady=(18, 10))
        self.premium_key_entry = ctk.CTkEntry(activation_card, textvariable=self.premium_key_var, width=500, placeholder_text=self.t("premium.key_placeholder"))
        self.premium_key_entry.pack(anchor="w", padx=18, pady=(0, 10))
        action_row = ctk.CTkFrame(activation_card, fg_color="transparent")
        action_row.pack(fill="x", padx=18, pady=(0, 14))
        self.premium_activate_button = ctk.CTkButton(
            action_row,
            text=self.t("premium.activate_button"),
            command=self._activate_premium,
        )
        self.premium_activate_button.pack(side="left")
        self.premium_refresh_button = ctk.CTkButton(
            action_row,
            text=self.t("premium.refresh_button"),
            command=self._refresh_premium_view,
            width=130,
        )
        self.premium_refresh_button.pack(side="left", padx=(10, 0))
        ctk.CTkLabel(activation_card, textvariable=self.premium_feedback_var, text_color=COLORS["text_soft"], wraplength=550, justify="left").pack(anchor="w", padx=18, pady=(0, 14))
        self.premium_feedback_var.set(self.t("premium.enter_key_hint"))

        self._refresh_premium_view()
        return frame

    def _add_premium_detail_row(self, parent: ctk.CTkFrame, label: str, value_var: tk.StringVar, row: int, col: int) -> None:
        row_frame = ctk.CTkFrame(parent, fg_color="transparent")
        row_frame.grid(row=row * 2 + col, column=0, padx=(0, 0), pady=(0, 8), sticky="ew")
        ctk.CTkLabel(row_frame, text=label, width=190, anchor="w", text_color=COLORS["text"], font=ctk.CTkFont(weight="bold")).pack(
            side="left"
        )
        ctk.CTkLabel(
            row_frame,
            textvariable=value_var,
            anchor="w",
            justify="left",
            wraplength=400,
        ).pack(side="left", fill="x", expand=True)
        parent.grid_columnconfigure(col, weight=1)
        parent.grid_columnconfigure(1 - col, minsize=0)

    def _premium_localize(self, key: str, fallback: str) -> str:
        value = self.t(key)
        return value if value != key else fallback

    def _trust_center_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.content)
        self._page_heading(frame, self.t("trust.title"), self.u("trust_body"))
        self.trust_text = ctk.CTkTextbox(frame)
        self.trust_text.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        self.trust_text.insert("1.0", self._trust_center_text({}))
        self.trust_text.configure(state="disabled")
        return frame

    def _research_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.content)
        self._page_heading(frame, self.t("research.title"), self.u("research_body"))
        text = ctk.CTkTextbox(frame)
        text.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        text.insert("1.0", research_summary(self.language))
        text.configure(state="disabled")
        return frame

    def _make_tree(self, parent, columns, headings, height=16) -> ttk.Treeview:
        container = ctk.CTkFrame(parent, fg_color="transparent")
        container.grid_columnconfigure(0, weight=1)
        container.grid_rowconfigure(0, weight=1)
        tree = ttk.Treeview(container, columns=columns, show="headings", height=height, style="Nova.Treeview")
        tree.container = container
        tree.grid(row=0, column=0, sticky="nsew")
        vertical = ctk.CTkScrollbar(container, command=tree.yview)
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal = ctk.CTkScrollbar(container, orientation="horizontal", command=tree.xview)
        horizontal.grid(row=1, column=0, sticky="ew")
        tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        tree_key = id(tree)
        self.tree_columns[tree_key] = tuple(columns)
        self.tree_headings[tree_key] = dict(zip(columns, headings))
        for column, heading in zip(columns, headings):
            tree.heading(column, text=heading, command=lambda current=column, widget=tree: self._toggle_tree_sort(widget, current))
            width = self._column_width(column)
            tree.column(column, width=width, minwidth=width, anchor="w", stretch=column not in {"score", "severity", "id"})
        self._configure_tree_tags(tree)
        return tree

    def _theme_color(self, key: str) -> str:
        return COLORS[key][1 if ctk.get_appearance_mode() == "Dark" else 0]

    def _configure_tree_style(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(
            "Nova.Treeview",
            background=self._theme_color("bg"),
            foreground=self._theme_color("text"),
            fieldbackground=self._theme_color("bg"),
            borderwidth=0,
            rowheight=38,
            bordercolor=self._theme_color("line"),
            lightcolor=self._theme_color("line"),
            darkcolor=self._theme_color("line"),
            relief="flat",
            font=("Segoe UI", 11),
        )
        style.configure(
            "Nova.Treeview.Heading",
            background=self._theme_color("panel_soft"),
            foreground=self._theme_color("text"),
            relief="flat",
            font=("Segoe UI", 10, "bold"),
            padding=(8, 6),
        )
        style.map(
            "Nova.Treeview",
            background=[("selected", self._theme_color("panel_soft"))],
            foreground=[("selected", self._theme_color("accent"))],
        )
        style.map("Nova.Treeview.Heading", background=[("active", self._theme_color("panel_lift"))])

    def _configure_tree_tags(self, tree: ttk.Treeview) -> None:
        tree.tag_configure("row_even", background=self._theme_color("bg"))
        tree.tag_configure("row_odd", background=self._theme_color("panel"))
        tree.tag_configure("severity_critical", foreground=self._theme_color("critical"))
        tree.tag_configure("severity_high", foreground=self._theme_color("high"))
        tree.tag_configure("severity_medium", foreground=self._theme_color("medium"))
        tree.tag_configure("severity_low", foreground=self._theme_color("text_soft"))
        tree.tag_configure("severity_info", foreground=self._theme_color("text_soft"))
        tree.tag_configure("status_quarantined", foreground=self._theme_color("critical"))
        tree.tag_configure("status_contained", foreground=self._theme_color("high"))
        tree.tag_configure("status_observed", foreground=self._theme_color("text_soft"))
        tree.tag_configure("trusted", foreground=self._theme_color("success"))

    def _column_width(self, column: str) -> int:
        return {
            "id": 150,
            "time": 180,
            "level": 125,
            "title": 235,
            "name": 190,
            "reason": 190,
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
        self.breadcrumb_var.set(self.u("overview") if name == "Dashboard" else self.t(NAV[name][1]))
        if name in {"Ransomware", "Forensics", "Trust Center", "Research", "Premium"} and not getattr(self, "_advanced_expanded", False):
            self._toggle_advanced()
        self._refresh_nav_selection()

    def _refresh_nav_selection(self) -> None:
        for name, button in self.nav_buttons.items():
            active = name == self.current_view
            button.configure(
                fg_color=COLORS["panel_soft"] if active else "transparent",
                hover_color=COLORS["panel_soft"] if active else COLORS["panel_lift"],
                text_color=COLORS["accent"] if active else COLORS["text_soft"],
                image=self._icon(NAV[name][0], "accent" if active else "text_soft"),
                font=ctk.CTkFont(size=13, weight="bold" if active else "normal"),
            )

    def t(self, key: str, **kwargs) -> str:
        return tr(self.language, key, **kwargs)

    def change_appearance(self) -> None:
        mode = "dark" if self.dark_mode_var.get() else "light"
        self.engine.settings.appearance_mode = mode
        from novaguard.config import save_settings
        save_settings(self.engine.settings)
        ctk.set_appearance_mode(mode)
        self._configure_tree_style()
        for tree in (self.result_tree, self.event_tree, getattr(self, "activity_result_tree", None), self.forensic_tree,
                     self.quarantine_tree, self.incident_tree, self.scan_threat_tree):
            if tree is not None:
                self._configure_tree_tags(tree)

    def _rebuild_interface(self) -> None:
        view = self.current_view if self.current_view in self.frames else "Dashboard"
        self.sidebar.destroy()
        self.sidebar_separator.destroy()
        self.shell.destroy()
        self._build_shell()

        self.frames = {}
        self.update_button = None
        self.first_nav_button = None
        self.nav_buttons = {}
        self.target_entry = None
        self.premium_key_entry = None
        self.premium_activate_button = None
        self.premium_refresh_button = None
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
        self.trust_signature = ""
        self.language_var.set(LANGUAGES[self.language])

        self._build_topbar()
        self._build_sidebar()
        self._build_views()
        self.show_view(view)
        self._refresh_workspace(self.engine.get_snapshot())

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
        folder = filedialog.askdirectory(parent=self)
        if folder and self.target_entry:
            self.target_entry.delete(0, "end")
            self.target_entry.insert(0, folder)
            self.scan_input_feedback_var.set("")

    def scan_custom_target(self) -> None:
        if not self.target_entry or self.engine.get_snapshot()["state"].get("scan_in_progress"):
            return
        target = self.target_entry.get().strip()
        if not target or not Path(target).exists():
            self.scan_input_feedback_var.set(self.u("target_required"))
            return
        self.scan_input_feedback_var.set("")
        self.engine.custom_scan(target)

    def stop_scan(self) -> None:
        if self.engine.cancel_scan():
            self.scan_status_var.set(self.t("scan.stopping_status"))

    def set_notifier(self, notifier) -> None:
        self.notifier = notifier

    def check_for_updates(self) -> None:
        if self.update_check_in_progress or self.update_install_in_progress:
            return
        self.update_check_in_progress = True
        thread = threading.Thread(target=self._check_for_updates_worker, name="NovaSentinelUpdateCheck", daemon=True)
        thread.start()

    def _check_for_updates_worker(self) -> None:
        try:
            premium_state = self.engine.get_premium_state()
            if premium_state.has_feature("premium_updates"):
                try:
                    update = fetch_latest_premium_update(APP_VERSION)
                except Exception:
                    update = fetch_latest_update(APP_VERSION)
            else:
                update = fetch_latest_update(APP_VERSION)
        except Exception:
            update = None
        self.after(0, lambda: self._finish_update_check(update))

    def _finish_update_check(self, update: UpdateInfo | None) -> None:
        self.update_check_in_progress = False
        self.update_info = update
        self._refresh_update_button()
        if update and update.tag != self.update_notified_tag:
            self.update_notified_tag = update.tag
            if self.notifier:
                self.notifier(
                    self.t("notify.update_available"),
                    self.t("notify.update_available_body", version=update.version),
                )

    def _refresh_update_button(self) -> None:
        if not self.update_button:
            return
        if not self.update_info:
            self.update_button.pack_forget()
            return
        self.update_button.configure(
            text=self.t("update.button", version=self.update_info.version),
            state="disabled" if self.update_install_in_progress else "normal",
        )
        if self.update_button.winfo_manager():
            return
        pack_options = {"fill": "x", "padx": 18, "pady": (0, 12)}
        self.update_button.pack(**pack_options)

    def start_update(self) -> None:
        if not self.update_info or self.update_install_in_progress:
            return
        update = self.update_info
        approved = messagebox.askyesno(
            self.t("update.confirm_title"),
            self.t("update.confirm_body", version=update.version, file=update.asset_name),
            parent=self,
        )
        if not approved:
            return
        self.update_install_in_progress = True
        if self.update_button:
            self.update_button.configure(text=self.t("update.downloading"), state="disabled")
        thread = threading.Thread(target=self._install_update_worker, args=(update,), name="NovaSentinelUpdateInstall", daemon=True)
        thread.start()

    def _install_update_worker(self, update: UpdateInfo) -> None:
        try:
            installer_path = download_update_installer(update)
        except Exception as exc:
            error = str(exc)
            self.after(0, lambda error=error: self._handle_update_error(error))
            return
        self.after(0, lambda: self._launch_update(installer_path))

    def _handle_update_error(self, error: str) -> None:
        self.update_install_in_progress = False
        self._refresh_update_button()
        messagebox.showwarning(self.t("update.error_title"), self.t("update.error_body", error=error), parent=self)

    def _launch_update(self, installer_path: Path) -> None:
        if self.update_button:
            self.update_button.configure(text=self.t("update.launching"), state="disabled")
        try:
            launch_update_installer(installer_path)
        except Exception as exc:
            self._handle_update_error(str(exc))
            return
        try:
            self.engine.stop_background_services()
        finally:
            self.destroy()
            os._exit(0)

    def request_system_quarantine_decision(self, payload: dict) -> bool:
        if threading.current_thread() is threading.main_thread():
            return self._ask_system_quarantine_decision(payload)
        completed = threading.Event()
        result = {"approved": False}

        def _ask() -> None:
            result["approved"] = self._ask_system_quarantine_decision(payload)
            completed.set()

        self.after(0, _ask)
        completed.wait()
        return bool(result["approved"])

    def _ask_system_quarantine_decision(self, payload: dict) -> bool:
        path = str(payload.get("path", ""))
        score = payload.get("score", "")
        sha256 = str(payload.get("sha256", ""))
        try:
            if self.state() in {"withdrawn", "iconic"}:
                self.show_from_tray()
        except tk.TclError:
            pass
        approved = messagebox.askyesno(
            self.t("quarantine.system.confirm_title"),
            self.t(
                "quarantine.system.confirm_body",
                file=Path(path).name or path,
                score=score,
                hash=sha256[:12] or "unknown",
                path=path,
            ),
            parent=self,
        )
        title_key = "notify.system_quarantine_approved" if approved else "notify.system_quarantine_refused"
        body_key = "notify.system_quarantine_approved_body" if approved else "notify.system_quarantine_refused_body"
        message = self.t(body_key, file=Path(path).name or path)
        if self.notifier:
            self.notifier(self.t(title_key), message)
        return approved

    def set_language_change_callback(self, callback) -> None:
        self.language_change_callback = callback

    def restore_selected(self) -> None:
        if not self.quarantine_tree:
            return
        selected = self.quarantine_tree.selection()
        if not selected:
            return
        values = self.quarantine_tree.item(selected[0], "values")
        if not messagebox.askyesno(self.t("quarantine.restore"), self.u("restore_confirm").format(name=values[1]), parent=self):
            return
        try:
            success = self.engine.quarantine.restore(values[0])
        except OSError:
            success = False
        self.quarantine_feedback_var.set(self.u("action_done" if success else "action_failed"))
        self._refresh_workspace(self.engine.get_snapshot())

    def delete_selected(self) -> None:
        if not self.quarantine_tree:
            return
        selected = self.quarantine_tree.selection()
        if not selected:
            return
        values = self.quarantine_tree.item(selected[0], "values")
        if not messagebox.askyesno(self.t("quarantine.delete"), self.u("delete_confirm").format(name=values[1]), parent=self):
            return
        try:
            success = self.engine.quarantine.delete(values[0])
        except OSError:
            success = False
        self.quarantine_feedback_var.set(self.u("action_done" if success else "action_failed"))
        self._refresh_workspace(self.engine.get_snapshot())

    def save_settings(self) -> None:
        roots = [line.strip() for line in self.paths_box.get("1.0", "end").splitlines() if line.strip()]
        current = replace(self.engine.get_snapshot()["settings"])
        previous_language = self.language
        current.realtime_enabled = bool(self.settings_vars["realtime_enabled"].get())
        current.process_guard_enabled = bool(self.settings_vars["process_guard_enabled"].get())
        current.ransomware_guard_enabled = bool(self.settings_vars["ransomware_guard_enabled"].get())
        current.automatic_quarantine = bool(self.settings_vars["automatic_quarantine"].get())
        current.notify_scan_completion = bool(self.settings_vars["notify_scan_completion"].get())
        current.language = self.language_by_label.get(self.language_var.get(), "en")
        current.scan_roots = roots
        self.engine.update_settings(current)
        if current.language != previous_language:
            self.language = normalize_language(current.language)
            if self.language_change_callback:
                self.language_change_callback(self.language)
            self._rebuild_interface()
        if hasattr(self, "settings_feedback_var"):
            self.settings_feedback_var.set(self.u("saved"))
        self._refresh_workspace(self.engine.get_snapshot())

    def refresh_view(self) -> None:
        try:
            snapshot = self.engine.get_snapshot()
            state = snapshot["state"]
            self.language = normalize_language(snapshot["settings"].language)
            self.status_var.set(self.t("status.active") if snapshot["settings"].realtime_enabled else self.t("status.paused"))
            self.scan_var.set(self._localized_scan_summary(state["last_scan_summary"]))
            if state["scan_in_progress"] or state["last_scan_summary"] == "No scan yet":
                self.quick_summary_var.set(self.t("scan.counter", threats=state["threats_found"], files=state["files_scanned"]))
            else:
                self.quick_summary_var.set(self._localized_scan_summary(state["last_scan_summary"]))
            if state["scan_in_progress"] and not self.previous_scan_in_progress:
                self.review_feedback_var.set("")
            self._refresh_scan_controls(state)
            self._refresh_scan_threats(snapshot.get("current_scan_threats", []))
            self._refresh_workspace(snapshot)
            self._refresh_scan_empty_state(snapshot.get("current_scan_threats", []), state)
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
            if self.forensic_tree:
                self._refresh_forensics(snapshot["history"])
            if self.incident_tree:
                incident_rows: list[tuple] = []
                incident_row_ids: list[str] = []
                self.incident_detail_by_key = {}
                for index, item in enumerate(reversed(snapshot.get("incidents", [])[-120:])):
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
                    incident_id = self._incident_row_id(item, index)
                    detail = self._incident_detail(item)
                    incident_rows.append(row)
                    incident_row_ids.append(incident_id)
                    self.incident_detail_by_key[incident_id] = detail
                    self.incident_detail_by_key[self._row_key(row)] = detail
                self._refresh_tree(
                    self.incident_tree,
                    incident_rows,
                    preserve_selection=True,
                    row_ids=incident_row_ids,
                )
                self._refresh_selected_incident_detail()
            self._refresh_trust_center(snapshot.get("telemetry", {}))
            self._refresh_premium_view()
            if self.previous_scan_in_progress and not state["scan_in_progress"]:
                self._notify_scan_transition(state["last_scan_summary"])
            self.previous_scan_in_progress = bool(state["scan_in_progress"])
        except Exception as exc:
            self.status_var.set(f"UI refresh recovered: {exc}")
        finally:
            self.after(1200, self.refresh_view)

    def _refresh_premium_view(self) -> None:
        try:
            state = self.engine.get_premium_state()
            unknown = self._premium_localize("premium.unknown", "unknown")
            never = self._premium_localize("premium.never", "never")
            inactive_status = state.status or self._premium_localize("premium.inactive", "inactive")
            active_features = [self._display_premium_feature(feature) for feature in state.features]
            feature_summary = ", ".join(active_features) if active_features else self._premium_localize(
                "premium.features_none",
                "No active premium features.",
            )
            if state.active:
                status = self.t(
                    "premium.status_active",
                    plan=state.plan or unknown,
                    customer=state.customer or unknown,
                    expiry=state.expires_at or never,
                )
                status_color = COLORS["success"]
            else:
                status = self.t("premium.status_inactive", status=inactive_status)
                status_color = COLORS["high"]
                if state.status in {"expired", "unsupported_plan", "inactive"}:
                    status_color = COLORS["critical"]
                feature_summary = self._premium_localize("premium.features_inactive", "No active premium features.")

            self.premium_plan_var.set(state.plan or unknown)
            self.premium_customer_var.set(state.customer or unknown)
            self.premium_expires_var.set(state.expires_at or never)
            self.premium_license_var.set(state.license_id or unknown)
            self.premium_device_var.set(state.device_id or unknown)
            self.premium_key_mask_var.set(state.key_mask or unknown)
            if not state.active:
                self.premium_features_var.set(self._premium_localize("premium.features_inactive", "No active premium features."))
                if self.premium_plan_var.get() == unknown and inactive_status == self._premium_localize("premium.inactive", "inactive"):
                    self.premium_plan_var.set(self._premium_localize("premium.inactive", "inactive"))
                    self.premium_customer_var.set(self._premium_localize("premium.inactive", "inactive"))
                    self.premium_expires_var.set(never)
                    self.premium_license_var.set(self._premium_localize("premium.inactive", "inactive"))
                    self.premium_device_var.set(self._premium_localize("premium.inactive", "inactive"))
                    self.premium_key_mask_var.set(self._premium_localize("premium.inactive", "inactive"))
            self.premium_status_var.set(status)
            self.premium_features_var.set(feature_summary)
            self.premium_feedback_var.set(self.t("premium.refresh_hint"))
            if self.premium_activate_button:
                self.premium_activate_button.configure(state="normal")
            if self.premium_refresh_button:
                self.premium_refresh_button.configure(state="normal")
            if self.premium_status_label:
                self.premium_status_label.configure(text_color=status_color)
        except Exception as exc:
            self.premium_status_var.set(self.t("premium.status_error", error=str(exc)))
            self.premium_features_var.set(self._premium_localize("premium.features_inactive", "No active premium features."))
            self.premium_plan_var.set(self._premium_localize("premium.inactive", "inactive"))
            self.premium_customer_var.set(self._premium_localize("premium.unknown", "unknown"))
            self.premium_expires_var.set(self._premium_localize("premium.never", "never"))
            self.premium_license_var.set(self._premium_localize("premium.unknown", "unknown"))
            self.premium_device_var.set(self._premium_localize("premium.unknown", "unknown"))
            self.premium_key_mask_var.set(self._premium_localize("premium.unknown", "unknown"))
            if self.premium_refresh_button:
                self.premium_refresh_button.configure(state="normal")
            if self.premium_status_label:
                self.premium_status_label.configure(text_color=COLORS["critical"])

    def _activate_premium(self) -> None:
        key = self.premium_key_var.get().strip()
        if not key:
            self.premium_feedback_var.set(self.t("premium.key_required"))
            return
        if self.premium_activate_button:
            self.premium_activate_button.configure(state="disabled")
        if self.premium_key_entry:
            self.premium_key_entry.configure(state="disabled")
        if self.premium_refresh_button:
            self.premium_refresh_button.configure(state="disabled")
        self.premium_feedback_var.set(self.t("premium.activating"))
        thread = threading.Thread(
            target=self._activate_premium_worker,
            args=(key,),
            name="NovaSentinelPremiumActivation",
            daemon=True,
        )
        thread.start()

    def _activate_premium_worker(self, key: str) -> None:
        try:
            self.engine.activate_premium_key(key)
            self.after(0, self._on_premium_activated)
        except Exception as exc:
            self.after(0, self._on_premium_activation_failed, str(exc))

    def _on_premium_activated(self) -> None:
        self._refresh_premium_view()
        if self.premium_key_entry:
            self.premium_key_entry.configure(state="normal")
        if self.premium_activate_button:
            self.premium_activate_button.configure(state="normal")
        self.premium_feedback_var.set(self.t("premium.activated"))

    def _on_premium_activation_failed(self, error: str) -> None:
        if self.premium_key_entry:
            self.premium_key_entry.configure(state="normal")
        if self.premium_activate_button:
            self.premium_activate_button.configure(state="normal")
        if self.premium_refresh_button:
            self.premium_refresh_button.configure(state="normal")
        self.premium_feedback_var.set(self.t("premium.activation_failed", error=error))

    def _display_premium_feature(self, feature: str) -> str:
        key = f"premium.feature.{feature}"
        translated = self.t(key)
        if translated == key:
            return feature.replace("_", " ")
        return translated

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
            total = int(state.get("scan_total_files") or 0)
            scanned = int(state.get("files_scanned") or 0)
            label = str(state.get("scan_label", "Scanning"))
            dots = "." * ((self.scan_animation_tick % 3) + 1)
            self.scan_animation_tick += 1
            if total > 0:
                self.scan_status_var.set(f"{label} - {scanned}/{total} {self.t('scan.files_suffix')}{dots}")
            else:
                self.scan_status_var.set(f"{label} - {scanned} {self.t('scan.files_suffix')} {self.t('scan.discovering')}{dots}")
        else:
            self.scan_animation_tick = 0
            self.scan_status_var.set(self.t("scan.ready"))
        self._refresh_progress_bar(state, in_progress)

    def _refresh_progress_bar(self, state: dict, in_progress: bool) -> None:
        if not self.progress_bar:
            return
        total = int(state.get("scan_total_files") or 0)
        if in_progress and total <= 0:
            if not self.scan_progress_indeterminate:
                try:
                    self.progress_bar.configure(mode="indeterminate", indeterminate_speed=1.25)
                    self.progress_bar.start()
                except Exception:
                    pass
                self.scan_progress_indeterminate = True
            return
        if self.scan_progress_indeterminate:
            try:
                self.progress_bar.stop()
                self.progress_bar.configure(mode="determinate")
            except Exception:
                pass
            self.scan_progress_indeterminate = False
        self.progress_bar.set(float(state.get("scan_progress", 0.0) or 0.0))

    def _refresh_tree(
        self,
        tree: ttk.Treeview,
        rows: list[tuple],
        preserve_selection: bool = False,
        row_ids: list[str] | None = None,
    ) -> None:
        row_pairs = list(zip(rows, row_ids or [None] * len(rows)))
        row_pairs = self._apply_tree_sort_pairs(tree, row_pairs)
        rows = [row for row, _row_id in row_pairs]
        signature = tuple((row, row_id or "") for row, row_id in row_pairs)
        tree_key = id(tree)
        if self.tree_signatures.get(tree_key) == signature:
            return
        self.tree_signatures[tree_key] = signature

        selected_key = None
        focused_key = None
        selected_iid = None
        focused_iid = None
        if preserve_selection:
            selected = tree.selection()
            if selected:
                selected_iid = selected[0]
                selected_values = tree.item(selected[0], "values")
                if selected_values:
                    selected_key = selected_values[0]
            focused = tree.focus()
            if focused:
                focused_iid = focused
                focused_values = tree.item(focused, "values")
                if focused_values:
                    focused_key = focused_values[0]

        for item in tree.get_children():
            tree.delete(item)
        selection_item = ""
        focus_item = ""
        for index, (row, row_id) in enumerate(row_pairs):
            insert_options = {"values": row, "tags": self._tree_tags_for_row(row, index)}
            if row_id:
                insert_options["iid"] = row_id
            try:
                item_id = tree.insert("", "end", **insert_options)
            except tk.TclError:
                insert_options.pop("iid", None)
                item_id = tree.insert("", "end", **insert_options)
            if preserve_selection and row_id and selected_iid == row_id:
                selection_item = item_id
            elif preserve_selection and not row_ids and selected_key is not None and row and str(row[0]) == str(selected_key):
                selection_item = item_id
            if preserve_selection and row_id and focused_iid == row_id:
                focus_item = item_id
            elif preserve_selection and not row_ids and focused_key is not None and row and str(row[0]) == str(focused_key):
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
        return [row for row, _row_id in self._apply_tree_sort_pairs(tree, [(row, None) for row in rows])]

    def _apply_tree_sort_pairs(self, tree: ttk.Treeview, row_pairs: list[tuple[tuple, str | None]]) -> list[tuple[tuple, str | None]]:
        tree_key = id(tree)
        columns = self.tree_columns.get(tree_key, ())
        sort_state = self.tree_sort_state.get(tree_key)
        if not sort_state or sort_state[0] not in columns:
            self._update_tree_headings(tree)
            return list(row_pairs)
        column, reverse = sort_state
        column_index = columns.index(column)
        sorted_rows = sorted(
            row_pairs,
            key=lambda pair: self._sortable_value(pair[0][column_index] if column_index < len(pair[0]) else ""),
            reverse=reverse,
        )
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

    def _incident_row_id(self, incident: dict, index: int = 0) -> str:
        incident_id = str(incident.get("id") or "").strip()
        if incident_id:
            return f"incident:{incident_id}"
        timestamp = str(incident.get("timestamp", "")).strip() or "unknown"
        trigger = Path(str(incident.get("trigger_path", ""))).name or "incident"
        return f"incident:fallback:{index}:{timestamp}:{trigger}"

    def _tree_tags_for_row(self, row: tuple, index: int = 0) -> tuple[str, ...]:
        level_codes = {"information": "info", "faible": "low", "à vérifier": "medium", "élevée": "high", "critique": "critical", "avertissement": "warning", "erreur": "error"}
        values = [level_codes.get(str(value).casefold(), str(value).casefold()) for value in row]
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
        detail = self.incident_detail_by_key.get(selected[0]) or self.incident_detail_by_key.get(row_key, "Incident detail is not available yet.")
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
        if self.notifier and self.engine.settings.notify_scan_completion and self.state() == "withdrawn":
            self.notifier(title, localized_summary)
        self.last_notified_summary = summary

    def _localized_scan_summary(self, summary: str) -> str:
        if summary == "No scan yet":
            return self.t("summary.none")
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
