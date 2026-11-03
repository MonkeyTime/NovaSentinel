"""Desktop presentation inspired by LevelUp, independent of the protection engine."""
from __future__ import annotations

import os
import tkinter as tk
from tkinter import filedialog

import customtkinter as ctk

from novaguard import APP_VERSION
from novaguard.i18n import LANGUAGES
from novaguard.ui.icons import icon
from novaguard.ui.theme import COLORS as C


COPY = {
    "computer": ("Mon ordinateur", "My computer"),
    "workspace": ("VOTRE ESPACE SÉCURITÉ", "YOUR SECURITY WORKSPACE"),
    "overview": ("Vue d’ensemble", "Overview"),
    "advanced": ("Plus d’outils", "More tools"),
    "less": ("Moins d’outils", "Fewer tools"),
    "local": ("Une protection discrète", "Quiet protection"),
    "local_body": ("Vos fichiers restent sur cet ordinateur.\nVous gardez la main sur les décisions.", "Your files stay on this computer.\nDecisions stay in your hands."),
    "eyebrow": ("VOTRE SÉCURITÉ, EN CLAIR", "YOUR SECURITY, MADE CLEAR"),
    "overview_body": ("L’essentiel de votre protection, au même endroit.", "Your protection essentials, all in one place."),
    "device": ("SUR CET ORDINATEUR", "ON THIS COMPUTER"),
    "enabled": ("Protections activées", "Protections enabled"),
    "partial": ("Protection à ajuster", "Review your protection"),
    "hero_enabled": ("Veiller sur vos fichiers. Sans vous interrompre.", "Watching your files. Without interrupting you."),
    "hero_partial": ("Certaines protections sont en pause. Vous pouvez les réactiver dans les préférences.", "Some protections are paused. You can enable them in preferences."),
    "scan_running": ("Une analyse est en cours", "A scan is running"),
    "scan_running_body": ("Vous pouvez continuer à utiliser votre ordinateur. Suivez l’avancement quand vous le souhaitez.", "Keep using your computer. Check progress whenever you like."),
    "start": ("Lancer une analyse", "Start a scan"),
    "view_scan": ("Voir l’analyse", "View scan"),
    "folder": ("Choisir un dossier", "Choose a folder"),
    "status_heading": ("Votre protection en un coup d’œil", "Your protection at a glance"),
    "status_hint": ("Des informations utiles, sans bruit", "Useful information, without the noise"),
    "shields": ("Protections activées", "Protections enabled"),
    "shields_meta": ("Fichiers, applications et fichiers leurres", "Files, applications and canaries"),
    "review": ("À vérifier dans cette analyse", "To review in this scan"),
    "review_meta": ("Un indice n’est pas une menace confirmée", "A signal is not a confirmed threat"),
    "quarantine": ("Fichiers isolés", "Isolated files"),
    "quarantine_meta": ("Consultez ou restaurez les fichiers", "Review or restore isolated files"),
    "preferences": ("Gérer les préférences", "Manage preferences"),
    "review_link": ("Examiner les résultats", "Review results"),
    "quarantine_link": ("Ouvrir la quarantaine", "Open quarantine"),
    "activity": ("Dernière activité", "Recent activity"),
    "all_activity": ("Tout voir", "View all"),
    "activity_empty": ("Rien à signaler pour le moment", "Nothing to report yet"),
    "activity_empty_body": ("Les analyses et les événements importants apparaîtront ici.", "Scans and important events will appear here."),
    "footer": ("Votre tranquillité. Tout simplement.", "Peace of mind. Simply."),
    "scan_body": ("Choisissez ce que vous souhaitez vérifier. Nous vous expliquons les résultats.", "Choose what to check. We’ll explain the results."),
    "quick_body": ("Les dossiers surveillés, pour un contrôle du quotidien.", "Your monitored folders, for an everyday check."),
    "full_body": ("Tous les disques locaux. Cette analyse peut durer plus longtemps.", "All local drives. This scan may take longer."),
    "custom_body": ("Un fichier ou un dossier précis, à votre rythme.", "A specific file or folder, at your own pace."),
    "recommended": ("AU QUOTIDIEN", "EVERYDAY CHECK"),
    "complete": ("PLUS EN PROFONDEUR", "MORE THOROUGH"),
    "custom": ("Une cible précise", "A specific target"),
    "choose_file": ("Choisir un fichier", "Choose a file"),
    "browse": ("Parcourir…", "Browse…"),
    "target_required": ("Choisissez un fichier ou un dossier existant pour commencer.", "Choose an existing file or folder to start."),
    "results_empty": ("Tout commence par une analyse", "Start with a scan"),
    "results_empty_body": ("Les éléments qui demandent votre attention seront présentés ici, avec leurs explications.", "Items that need your attention will appear here with an explanation."),
    "results_clear": ("Aucun élément à vérifier dans cette analyse", "No items to review in this scan"),
    "results_clear_body": ("Le résumé de l’analyse est disponible ci-dessus.", "The scan summary is available above."),
    "settings_body": ("Une protection qui s’adapte à votre façon de travailler.", "Protection that fits the way you work."),
    "protection": ("Protection", "Protection"),
    "protection_body": ("Choisissez les surveillances à activer sur cet ordinateur.", "Choose which protections to enable on this computer."),
    "realtime_body": ("Vérifie les fichiers qui changent dans les dossiers surveillés.", "Checks files as they change in your monitored folders."),
    "process_body": ("Examine les applications à leur lancement.", "Checks applications when they launch."),
    "ransomware_body": ("Vérifie les fichiers leurres et conserve les événements inhabituels.", "Checks canary integrity and records unusual activity."),
    "automatic_body": ("Isole automatiquement les fichiers jugés malveillants selon la politique de détection.", "Automatically isolates files judged malicious by the detection policy."),
    "comfort": ("Votre confort", "Your preferences"),
    "comfort_body": ("Moins d’interruptions, les informations au bon endroit.", "Fewer interruptions, information where it belongs."),
    "notify_body": ("Une notification discrète si la fenêtre est masquée. Désactivée par défaut.", "A quiet notification when the window is hidden. Off by default."),
    "folders_title": ("Dossiers surveillés", "Monitored folders"),
    "folders_body": ("Un chemin par ligne. Ces dossiers servent aussi à l’analyse rapide.", "One path per line. Quick scans use these folders too."),
    "add_folder": ("Ajouter un dossier", "Add folder"),
    "save_hint": ("Les changements s’appliquent après enregistrement.", "Changes apply when you save."),
    "saved": ("Préférences enregistrées", "Preferences saved"),
    "not_saved": ("Modifications non enregistrées", "Unsaved changes"),
    "leave_title": ("Conserver vos modifications ?", "Keep your changes?"),
    "leave_body": ("Vos préférences ont été modifiées. Enregistrer avant de changer de page ?", "Your preferences have changed. Save before leaving this page?"),
    "cancel": ("Annuler", "Cancel"),
    "events_body": ("Retrouvez ce qui s’est passé et les fichiers récemment analysés.", "Review what happened and the files recently scanned."),
    "events_tab": ("Événements", "Events"),
    "files_tab": ("Fichiers analysés", "Scanned files"),
    "search": ("Rechercher dans l’activité…", "Search activity…"),
    "search_label": ("Rechercher", "Search"),
    "only_alerts": ("Alertes uniquement", "Alerts only"),
    "no_activity": ("Aucune activité enregistrée", "No recorded activity"),
    "no_matches": ("Aucun résultat pour ces filtres", "No results for these filters"),
    "no_matches_body": ("Essayez un autre mot ou désactivez le filtre des alertes.", "Try a different word or turn off the alerts filter."),
    "recent_count": ("{count} élément(s) dans l’activité récente", "{count} item(s) in recent activity"),
    "quarantine_body": ("Les fichiers isolés restent à l’écart. Vous décidez de la suite.", "Isolated files stay out of the way. You decide what happens next."),
    "quarantine_empty": ("Votre quarantaine est vide", "Your quarantine is empty"),
    "quarantine_empty_body": ("Les fichiers isolés apparaîtront ici. Aucune action n’est nécessaire sur cette page.", "Isolated files will appear here. No action is needed on this page."),
    "quarantine_select": ("Sélectionnez un fichier pour afficher les actions disponibles.", "Select a file to see available actions."),
    "restore_confirm": ("Restaurer « {name} » ? Le fichier redeviendra accessible. Ne restaurez que les fichiers que vous reconnaissez.", "Restore ‘{name}’? The file will be accessible again. Only restore files you recognize."),
    "delete_confirm": ("Supprimer définitivement « {name} » de la quarantaine ? Cette suppression ne peut pas être annulée.", "Permanently delete ‘{name}’ from quarantine? This cannot be undone."),
    "action_done": ("Action effectuée. La quarantaine a été actualisée.", "Done. Quarantine has been updated."),
    "action_failed": ("L’action n’a pas abouti. Le fichier peut être inaccessible ou ne plus être présent.", "The action failed. The file may be unavailable or no longer present."),
    "running_results": ("Les éléments à examiner apparaîtront ici pendant l’analyse.", "Items to review will appear here as the scan runs."),
    "expert": ("Des indices et des explications pour aller plus loin.", "Evidence and explanations for a closer look."),
    "premium_body": ("Gérez les fonctionnalités et l’abonnement de cet ordinateur.", "Manage this computer’s features and subscription."),
    "research_body": ("Les sources qui guident la conception de NovaSentinel.", "The sources behind NovaSentinel’s design."),
    "trust_body": ("Comprenez ce que l’application observe et les limites de ses protections.", "Understand what the app observes and the limits of its protection."),
}

NAV = {
    "Dashboard": ("grid", "nav.dashboard"), "Scan Center": ("scan", "nav.scan"),
    "Quarantine": ("lock", "nav.quarantine"), "Events": ("clock", "nav.events"),
    "Ransomware": ("shield", "nav.ransomware"), "Forensics": ("pulse", "nav.forensics"),
    "Trust Center": ("check", "nav.trust"), "Research": ("book", "nav.research"),
    "Premium": ("briefcase", "nav.premium"), "Settings": ("settings", "nav.settings"),
}


class WorkspaceViews:
    def u(self, key: str) -> str:
        return COPY[key][0 if self.language == "fr" else 1]

    def _icon(self, name, tone="text_soft", size=20):
        if not hasattr(self, "_ui_icons"):
            self._ui_icons = {}
        key = (name, tone, size)
        if key not in self._ui_icons:
            self._ui_icons[key] = icon(name, tone, size)
        return self._ui_icons[key]

    def _button(self, parent, text, command, *, kind="primary", image=None, **kwargs):
        secondary = kind == "secondary"
        button = ctk.CTkButton(
            parent, text=text, command=command, height=38, corner_radius=8,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color=C["panel"] if secondary else C["button"],
            text_color=C["text"] if secondary else "#ffffff",
            hover_color=C["panel_lift"] if secondary else C["button_hover"],
            border_width=1 if secondary else 0, border_color=C["line"],
            image=image, compound="left", **kwargs,
        )
        button._canvas.configure(takefocus=1)
        button.bind("<Return>", lambda event: button.invoke())
        button.bind("<space>", lambda event: button.invoke())
        button.bind("<FocusIn>", lambda event: button.configure(border_width=2, border_color=C["accent"]))
        button.bind("<FocusOut>", lambda event: button.configure(border_width=1 if secondary else 0, border_color=C["line"]))
        return button

    def _build_shell(self):
        self.sidebar = ctk.CTkFrame(self, width=232, corner_radius=0, fg_color=C["panel"])
        self.sidebar.pack_propagate(False)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar_separator = ctk.CTkFrame(self, width=1, corner_radius=0, fg_color=C["line"])
        self.sidebar_separator.grid(row=0, column=0, sticky="nse")
        self.shell = ctk.CTkFrame(self, corner_radius=0, fg_color=C["bg"])
        self.shell.grid(row=0, column=1, sticky="nsew")
        self.shell.grid_columnconfigure(0, weight=1)
        self.shell.grid_rowconfigure(1, weight=1)
        self.content = ctk.CTkFrame(self.shell, corner_radius=0, fg_color=C["bg"])
        self.content.grid(row=1, column=0, sticky="nsew", padx=22, pady=(14, 12))
        self.content.grid_rowconfigure(0, weight=1)
        self.content.grid_columnconfigure(0, weight=1)

    def _build_topbar(self):
        topbar = ctk.CTkFrame(self.shell, height=64, fg_color=C["panel"], corner_radius=0)
        topbar.grid(row=0, column=0, sticky="ew")
        topbar.pack_propagate(False)
        ctk.CTkFrame(topbar, height=1, corner_radius=0, fg_color=C["line"]).pack(side="bottom", fill="x")
        self.breadcrumb_var = tk.StringVar(value=self.u("overview"))
        ctk.CTkLabel(topbar, text=self.u("computer") + "    /", text_color=C["text_soft"], font=ctk.CTkFont(size=12)).pack(side="left", padx=(30, 18))
        ctk.CTkLabel(topbar, textvariable=self.breadcrumb_var, font=ctk.CTkFont(size=12, weight="bold")).pack(side="left")
        ctk.CTkSwitch(topbar, text=self.t("settings.dark_mode"), variable=self.dark_mode_var,
                      command=self.change_appearance, switch_width=30, switch_height=18,
                      font=ctk.CTkFont(size=11), text_color=C["text_soft"], width=126).pack(side="right", padx=28)

    def _build_sidebar(self):
        brand = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        brand.pack(fill="x", padx=20, pady=(28, 25))
        badge = ctk.CTkLabel(brand, text="", image=self._icon("shield", "white", 23),
                             width=34, height=37, corner_radius=10, fg_color=C["button"])
        badge.pack(side="left")
        ctk.CTkLabel(brand, text="NovaSentinel", font=ctk.CTkFont(size=21, weight="bold")).pack(side="left", padx=9)
        navigation = ctk.CTkScrollableFrame(self.sidebar, fg_color="transparent", corner_radius=0,
                                           scrollbar_button_color=C["panel"], scrollbar_button_hover_color=C["line"])
        navigation.pack(fill="both", expand=True, padx=10)
        ctk.CTkLabel(navigation, text=self.u("workspace"), text_color=C["text_soft"],
                     font=ctk.CTkFont(size=9, weight="bold"), anchor="w").pack(fill="x", padx=12, pady=(10, 12))
        def nav_button(parent, name):
            glyph, key = NAV[name]
            button = self._button(parent, self.u("overview") if name == "Dashboard" else self.t(key),
                                  lambda: self.show_view(name), kind="secondary", width=184,
                                  image=self._icon(glyph))
            button.configure(anchor="w", fg_color="transparent", text_color=C["text_soft"],
                             border_width=0, height=40, font=ctk.CTkFont(size=13))
            button.pack(fill="x", padx=4, pady=3)
            self.nav_buttons[name] = button
            if self.first_nav_button is None:
                self.first_nav_button = button
        for name in ("Dashboard", "Scan Center", "Quarantine", "Events"):
            nav_button(navigation, name)
        ctk.CTkFrame(navigation, height=1, fg_color=C["line"]).pack(fill="x", padx=12, pady=16)
        self.advanced_toggle = self._button(navigation, self.u("advanced"), self._toggle_advanced,
                                             kind="secondary", image=self._icon("chevron"), width=184)
        self.advanced_toggle.configure(anchor="w", border_width=0, fg_color="transparent", text_color=C["text_soft"])
        self.advanced_toggle.pack(fill="x", padx=4)
        self.advanced_navigation = ctk.CTkFrame(navigation, fg_color="transparent")
        for name in ("Ransomware", "Forensics", "Trust Center", "Research", "Premium"):
            nav_button(self.advanced_navigation, name)
        if getattr(self, "_advanced_expanded", False):
            self.advanced_navigation.pack(fill="x", pady=(8, 0))
            self.advanced_toggle.configure(text=self.u("less"))
        # Bottom actions remain reachable even when the navigation scrolls.
        footer = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        footer.pack(fill="x", padx=20, pady=(12, 18))
        nav_button(footer, "Settings")
        ctk.CTkFrame(footer, height=1, fg_color=C["line"]).pack(fill="x", pady=(12, 16))
        ctk.CTkLabel(footer, text="●  " + self.u("local"), text_color=C["success"],
                     font=ctk.CTkFont(size=11, weight="bold"), anchor="w").pack(fill="x")
        ctk.CTkLabel(footer, text=self.u("local_body"), text_color=C["text_soft"], wraplength=190,
                     justify="left", anchor="w", font=ctk.CTkFont(size=10)).pack(fill="x", pady=(5, 12))
        ctk.CTkLabel(footer, text=f"NOVASENTINEL                         v{APP_VERSION}",
                     text_color=C["text_soft"], font=ctk.CTkFont(size=9), anchor="w").pack(fill="x")
        self.update_button = self._button(footer, self.t("update.button", version=""), self.start_update, width=180)
        self._refresh_update_button()

    def _toggle_advanced(self):
        self._advanced_expanded = not getattr(self, "_advanced_expanded", False)
        self.advanced_toggle.configure(text=self.u("less" if self._advanced_expanded else "advanced"))
        if self._advanced_expanded:
            self.advanced_navigation.pack(fill="x", pady=(8, 0))
        else:
            self.advanced_navigation.pack_forget()

    def _page(self, *, scroll=False):
        if scroll:
            return ctk.CTkScrollableFrame(self.content, fg_color=C["bg"], corner_radius=0,
                                          scrollbar_button_color=C["line"], scrollbar_button_hover_color=C["text_soft"])
        return ctk.CTkFrame(self.content, fg_color=C["bg"], corner_radius=0)

    def _page_heading(self, parent, title, description):
        heading = ctk.CTkFrame(parent, fg_color="transparent")
        heading.pack(fill="x", padx=8, pady=(10, 22))
        ctk.CTkLabel(heading, text=self.u("eyebrow"), text_color=C["accent"], anchor="w",
                     font=ctk.CTkFont(size=9, weight="bold")).pack(fill="x", pady=(0, 4))
        ctk.CTkLabel(heading, text=title, anchor="w", font=ctk.CTkFont(size=28, weight="bold")).pack(fill="x")
        ctk.CTkLabel(heading, text=description, text_color=C["text_soft"], anchor="w",
                     wraplength=650, justify="left", font=ctk.CTkFont(size=12)).pack(fill="x", pady=(3, 0))

    def _card(self, parent, **kwargs):
        return ctk.CTkFrame(parent, fg_color=C["panel"], border_width=1, border_color=C["line"], corner_radius=12, **kwargs)

    def _chip(self, parent, glyph, size=34):
        return ctk.CTkLabel(parent, text="", image=self._icon(glyph, "accent", int(size * .52)),
                             width=size, height=size, fg_color=C["panel_soft"], corner_radius=10)

    def _dashboard_view(self):
        page = self._page(scroll=True)
        self._page_heading(page, self.u("overview"), self.u("overview_body"))
        hero = self._card(page)
        hero.pack(fill="x", padx=8)
        top = ctk.CTkFrame(hero, fg_color="transparent")
        top.pack(fill="x", padx=24, pady=(22, 12))
        self._chip(top, "shield", 64).pack(side="left", padx=(0, 18))
        identity = ctk.CTkFrame(top, fg_color="transparent")
        identity.pack(side="left", fill="both", expand=True)
        ctk.CTkLabel(identity, text=self.u("device"), text_color=C["text_soft"], font=ctk.CTkFont(size=9, weight="bold"), anchor="w").pack(fill="x")
        self.home_title_var = tk.StringVar(value=self.u("enabled"))
        self.home_description_var = tk.StringVar(value=self.u("hero_enabled"))
        ctk.CTkLabel(identity, textvariable=self.home_title_var, anchor="w", font=ctk.CTkFont(size=21, weight="bold")).pack(fill="x", pady=2)
        ctk.CTkLabel(identity, textvariable=self.home_description_var, anchor="w", text_color=C["text_soft"],
                     wraplength=470, justify="left", font=ctk.CTkFont(size=12)).pack(fill="x")
        actions = ctk.CTkFrame(hero, fg_color="transparent")
        actions.pack(fill="x", padx=24, pady=(4, 20))
        self.home_scan_button = self._button(actions, self.u("start"), self._home_scan,
                                              image=self._icon("scan", "white", 17))
        self.home_scan_button.pack(side="left")
        self._button(actions, self.u("folder"), self._home_folder, kind="secondary",
                      image=self._icon("folder", size=17)).pack(side="left", padx=10)
        self.home_device_label = ctk.CTkLabel(actions, text=os.environ.get("COMPUTERNAME", "Windows"),
                                             text_color=C["text_soft"], font=ctk.CTkFont(size=10))
        self.home_device_label.pack(side="right")
        section = ctk.CTkFrame(page, fg_color="transparent")
        section.pack(fill="x", padx=8, pady=(22, 12))
        ctk.CTkLabel(section, text=self.u("status_heading"), font=ctk.CTkFont(size=15, weight="bold")).pack(side="left")
        metrics = ctk.CTkFrame(page, fg_color="transparent")
        metrics.pack(fill="x", padx=3)
        metrics.grid_columnconfigure((0, 1, 2), weight=1, uniform="metric")
        self.home_values = {}
        for column, (key, glyph, label, meta, link, view) in enumerate([
            ("shields", "shield", "shields", "shields_meta", "preferences", "Settings"),
            ("review", "scan", "review", "review_meta", "review_link", "Scan Center"),
            ("quarantine", "lock", "quarantine", "quarantine_meta", "quarantine_link", "Quarantine"),
        ]):
            card = self._card(metrics)
            card.grid(row=0, column=column, sticky="nsew", padx=5)
            header = ctk.CTkFrame(card, fg_color="transparent")
            header.pack(fill="x", padx=16, pady=(16, 10))
            self._chip(header, glyph, 30).pack(side="left")
            ctk.CTkLabel(header, text=self.u(label), wraplength=125, justify="left", anchor="w",
                         text_color=C["text_soft"], font=ctk.CTkFont(size=11)).pack(side="left", padx=9)
            value = tk.StringVar(value="—")
            self.home_values[key] = value
            ctk.CTkLabel(card, textvariable=value, anchor="w", font=ctk.CTkFont(size=27, weight="bold")).pack(fill="x", padx=16)
            ctk.CTkLabel(card, text=self.u(meta), wraplength=180, anchor="w", justify="left",
                         text_color=C["text_soft"], font=ctk.CTkFont(size=10)).pack(fill="x", padx=16, pady=(2, 13))
            ctk.CTkFrame(card, height=1, fg_color=C["line"]).pack(fill="x", padx=16)
            self._button(card, self.u(link) + "  →", lambda target=view: self.show_view(target),
                          kind="secondary", width=130).pack(fill="x", padx=12, pady=8)
        activity = self._card(page)
        activity.pack(fill="x", padx=8, pady=(18, 0))
        row = ctk.CTkFrame(activity, fg_color="transparent")
        row.pack(fill="x", padx=20, pady=(12, 4))
        ctk.CTkLabel(row, text=self.u("activity"), font=ctk.CTkFont(size=14, weight="bold")).pack(side="left")
        self._button(row, self.u("all_activity") + "  →", lambda: self.show_view("Events"), kind="secondary", width=90).pack(side="right")
        self.home_activity = ctk.CTkFrame(activity, fg_color="transparent")
        self.home_activity.pack(fill="x", padx=20, pady=(0, 14))
        self.home_activity_signature = None
        ctk.CTkLabel(page, text=self.u("footer"), text_color=C["text_soft"], font=ctk.CTkFont(size=10), anchor="w").pack(fill="x", padx=8, pady=(18, 8))
        return page

    def _home_scan(self):
        state = self.engine.get_snapshot()["state"]
        if not state.get("scan_in_progress"):
            self.engine.quick_scan()
        self.show_view("Scan Center")

    def _home_folder(self):
        self.show_view("Scan Center")
        self.pick_custom_target()

    def _refresh_workspace(self, snapshot):
        settings = snapshot["settings"]
        state = snapshot["state"]
        enabled = sum(bool(getattr(settings, name)) for name in ("realtime_enabled", "process_guard_enabled", "ransomware_guard_enabled"))
        running = bool(state.get("scan_in_progress"))
        self.home_title_var.set(self.u("scan_running") if running else self.u("enabled" if enabled == 3 else "partial"))
        self.home_description_var.set(self.u("scan_running_body") if running else self.u("hero_enabled" if enabled == 3 else "hero_partial"))
        self.home_scan_button.configure(text=self.u("view_scan" if running else "start"))
        self.home_values["shields"].set(f"{enabled} / 3")
        findings = snapshot.get("current_scan_threats", [])
        self.home_values["review"].set(str(sum(item.get("action_taken", "none") not in {"quarantined", "ignored", "missing"} for item in findings)))
        self.home_values["quarantine"].set(str(len(snapshot.get("quarantine", []))))
        activity = list(reversed(snapshot.get("events", [])[-3:]))
        signature = tuple((item.get("timestamp"), item.get("title"), item.get("level"), item.get("description")) for item in activity)
        if signature != self.home_activity_signature:
            self.home_activity_signature = signature
            for child in self.home_activity.winfo_children():
                child.destroy()
            if not activity:
                ctk.CTkLabel(self.home_activity, text=self.u("activity_empty"), anchor="w", font=ctk.CTkFont(size=12, weight="bold")).pack(fill="x", pady=(8, 0))
                ctk.CTkLabel(self.home_activity, text=self.u("activity_empty_body"), anchor="w", text_color=C["text_soft"], font=ctk.CTkFont(size=11)).pack(fill="x", pady=(0, 6))
            for item in activity:
                row = ctk.CTkFrame(self.home_activity, fg_color="transparent")
                row.pack(fill="x", pady=5)
                glyph = "check" if item.get("level") == "info" else "pulse"
                self._chip(row, glyph, 28).pack(side="left", padx=(0, 10))
                title = self._event_title(str(item.get("title", "")))
                ctk.CTkLabel(row, text=title, anchor="w", wraplength=450, justify="left", font=ctk.CTkFont(size=11)).pack(side="left", fill="x", expand=True)
                ctk.CTkLabel(row, text=str(item.get("timestamp", "")).replace("T", "  ")[:16],
                             text_color=C["text_soft"], font=ctk.CTkFont(size=10)).pack(side="right")
        self._refresh_activity(snapshot)
        self._refresh_quarantine(snapshot.get("quarantine", []))

    def _scan_view(self):
        page = self._page(scroll=True)
        self._page_heading(page, self.t("scan.title"), self.u("scan_body"))
        choices = ctk.CTkFrame(page, fg_color="transparent")
        choices.pack(fill="x", padx=3)
        choices.grid_columnconfigure((0, 1), weight=1, uniform="scan")
        self.scan_action_buttons = []
        for column, title, body, eyebrow, kind in [
            (0, "scan.quick", "quick_body", "recommended", "quick"),
            (1, "scan.full", "full_body", "complete", "full"),
        ]:
            card = self._card(choices)
            card.grid(row=0, column=column, sticky="nsew", padx=5)
            ctk.CTkLabel(card, text=self.u(eyebrow), text_color=C["accent"], anchor="w", font=ctk.CTkFont(size=9, weight="bold")).pack(fill="x", padx=18, pady=(14, 0))
            row = ctk.CTkFrame(card, fg_color="transparent")
            row.pack(fill="x", padx=18, pady=(2, 8))
            ctk.CTkLabel(row, text=self.t(title), anchor="w", font=ctk.CTkFont(size=16, weight="bold")).pack(side="left")
            button = self._button(row, self.t("scan.quick") if kind == "quick" else self.t("scan.full"),
                                  self.engine.quick_scan if kind == "quick" else self.engine.full_scan,
                                  kind="primary" if kind == "quick" else "secondary", width=134)
            # One compact primary action per card, with a predictable focus target.
            button.configure(text=self.u("start"), height=32, width=118)
            button.pack(side="right", padx=(8, 0))
            self.scan_action_buttons.append(button)
            ctk.CTkLabel(card, text=self.u(body), text_color=C["text_soft"], wraplength=265, anchor="w",
                         justify="left", font=ctk.CTkFont(size=11)).pack(fill="x", padx=18, pady=(0, 14))
        custom = self._card(page)
        custom.pack(fill="x", padx=8, pady=12)
        custom.grid_columnconfigure(0, weight=1)
        self.target_entry = ctk.CTkEntry(custom, placeholder_text=self.t("scan.placeholder"), height=36,
                                        font=ctk.CTkFont(size=12))
        self.target_entry.grid(row=0, column=0, sticky="ew", padx=(16, 8), pady=12)
        self.target_entry.bind("<Return>", lambda event: self.scan_custom_target())
        browse = self._button(custom, self.u("browse"), self.pick_custom_target, kind="secondary", width=100)
        browse.grid(row=0, column=1, padx=(0, 8), pady=12)
        run = self._button(custom, self.t("scan.target"), self.scan_custom_target, width=125)
        run.grid(row=0, column=2, padx=(0, 16), pady=12)
        self.scan_action_buttons.extend([browse, run])
        file_button = self._button(custom, self.u("choose_file"), self._pick_file, kind="secondary", width=120)
        file_button.grid(row=1, column=0, sticky="w", padx=16, pady=(0, 10))
        self.scan_action_buttons.append(file_button)
        self.scan_input_feedback_var = tk.StringVar()
        ctk.CTkLabel(custom, textvariable=self.scan_input_feedback_var, text_color=C["high"], font=ctk.CTkFont(size=11),
                     wraplength=430, anchor="w").grid(row=1, column=1, columnspan=2, sticky="w", padx=8)
        progress = ctk.CTkFrame(page, fg_color="transparent")
        progress.pack(fill="x", padx=10, pady=(0, 10))
        self.stop_scan_button = self._button(progress, self.t("scan.stop"), self.stop_scan, kind="secondary", width=130)
        self.stop_scan_button.pack(side="right", padx=(15, 0))
        summary = ctk.CTkFrame(progress, fg_color="transparent")
        summary.pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(summary, textvariable=self.scan_status_var, text_color=C["text_soft"], anchor="w",
                     font=ctk.CTkFont(size=11), wraplength=550).pack(fill="x")
        self.progress_bar = ctk.CTkProgressBar(summary, height=5, progress_color=C["accent"], fg_color=C["line"])
        self.progress_bar.pack(fill="x", pady=(5, 0))
        self.progress_bar.set(0)
        results = self._card(page)
        results.pack(fill="both", expand=True, padx=8, pady=(0, 4))
        row = ctk.CTkFrame(results, fg_color="transparent")
        row.pack(fill="x", padx=18, pady=(12, 4))
        ctk.CTkLabel(row, text=self.t("scan.threats"), font=ctk.CTkFont(size=14, weight="bold")).pack(side="left")
        ctk.CTkLabel(row, textvariable=self.scan_threat_count_var, text_color=C["text_soft"], font=ctk.CTkFont(size=10)).pack(side="right")
        ctk.CTkLabel(results, textvariable=self.quick_summary_var, text_color=C["text_soft"], anchor="w", font=ctk.CTkFont(size=10)).pack(fill="x", padx=18)
        self.scan_threat_tree = self._make_tree(results,
            columns=("time", "severity", "score", "file", "detail", "evidence", "status"),
            headings=tuple(self.t("heading." + key) for key in ("time", "severity", "score", "path", "detail", "evidence", "status")), height=5)
        self.scan_results_host = results
        self.scan_empty = ctk.CTkFrame(results, fg_color="transparent")
        self.scan_empty.pack(fill="both", expand=True, padx=18, pady=10)
        self.scan_empty_title = ctk.CTkLabel(self.scan_empty, text=self.u("results_empty"), font=ctk.CTkFont(size=14, weight="bold"))
        self.scan_empty_title.pack(pady=(14, 2))
        self.scan_empty_description = ctk.CTkLabel(self.scan_empty, text=self.u("results_empty_body"), text_color=C["text_soft"],
                                                  wraplength=520, justify="center", font=ctk.CTkFont(size=11))
        self.scan_empty_description.pack(pady=(0, 12))
        self.scan_review_toolbar = ctk.CTkFrame(results, fg_color="transparent")
        self.review_buttons = []
        for text, action in [("review.quarantine", "quarantine"), ("review.ignore", "ignore")]:
            button = self._button(self.scan_review_toolbar, self.t(text), lambda value=action: self.review_selected_threat(value), kind="secondary", width=135)
            button.pack(side="left", padx=(0, 8))
            button.configure(state="disabled", height=32)
            self.review_buttons.append(button)
        ctk.CTkLabel(self.scan_review_toolbar, textvariable=self.review_feedback_var, text_color=C["text_soft"],
                     font=ctk.CTkFont(size=10), wraplength=270).pack(side="left", padx=6)
        self.scan_detail_by_path = {}
        self.scan_detail_signature = None
        self.scan_detail_card = ctk.CTkFrame(results, fg_color=C["bg"], corner_radius=8)
        self.scan_detail_title = ctk.CTkLabel(self.scan_detail_card, text="", anchor="w", justify="left", wraplength=580,
                                             font=ctk.CTkFont(size=12, weight="bold"))
        self.scan_detail_title.pack(fill="x", padx=14, pady=(10, 4))
        self.scan_detail_text = ctk.CTkTextbox(self.scan_detail_card, height=125, fg_color="transparent", wrap="word",
                                              font=ctk.CTkFont(size=11))
        self.scan_detail_text.pack(fill="both", expand=True, padx=10, pady=(0, 8))
        self.scan_detail_text.configure(state="disabled")
        self.scan_threat_tree.bind("<<TreeviewSelect>>", lambda event: self._refresh_review_actions())
        return page

    def _pick_file(self):
        path = filedialog.askopenfilename(parent=self)
        if path:
            self.target_entry.delete(0, "end")
            self.target_entry.insert(0, path)
            self.scan_input_feedback_var.set("")

    def _refresh_review_actions(self):
        selection = self.scan_threat_tree.selection()
        selected = bool(selection)
        for button in self.review_buttons:
            button.configure(state="normal" if selected else "disabled")
        if not selected:
            self.scan_detail_card.pack_forget()
            self.scan_detail_signature = None
            return
        values = self.scan_threat_tree.item(selection[0], "values")
        path = str(values[3])
        detail = self.scan_detail_by_path.get(path, "")
        signature = (path, detail)
        if signature != self.scan_detail_signature:
            self.scan_detail_signature = signature
            self.scan_detail_title.configure(text=path)
            self.scan_detail_text.configure(state="normal")
            self.scan_detail_text.delete("1.0", "end")
            self.scan_detail_text.insert("1.0", detail)
            self.scan_detail_text.configure(state="disabled")
        self.scan_detail_card.pack(fill="x", padx=18, pady=(0, 12))

    def _refresh_scan_threats(self, threats):
        if not self.scan_threat_tree:
            return
        self.scan_threat_count_var.set(self.t("scan.threat_count", count=len(threats)))
        self.scan_detail_by_path = {}
        rows = []
        row_ids = []
        for threat in threats:
            path = str(threat.get("path", ""))
            hits = threat.get("hits", []) or []
            detail = "\n\n".join(str(hit.get("explanation", "")) + "\n" + str(hit.get("evidence", "")) for hit in hits)
            self.scan_detail_by_path[path] = detail
            rows.append((threat.get("scanned_at", ""), self._level_label(str(threat.get("severity", "")).lower()), threat.get("score", 0),
                         path, hits[0].get("explanation", "") if hits else threat.get("threat_label", ""),
                         "; ".join(str(hit.get("evidence", "")) for hit in hits[:2]), self._action_label(threat.get("action_taken", "none"))))
            row_ids.append(path + "::0")
        self._refresh_tree(self.scan_threat_tree, rows, preserve_selection=True, row_ids=row_ids)
        self._refresh_scan_empty_state(threats)

    def _refresh_scan_empty_state(self, findings, state=None):
        if not hasattr(self, "scan_empty"):
            return
        if findings:
            self.scan_empty.pack_forget()
            self.scan_review_toolbar.pack(fill="x", padx=18, pady=(8, 6))
            self.scan_threat_tree.container.pack(fill="both", expand=True, padx=18, pady=(0, 12))
        else:
            self.scan_threat_tree.container.pack_forget()
            self.scan_review_toolbar.pack_forget()
            self.scan_empty.pack(fill="both", expand=True, padx=18, pady=8)
            has_scan = state and state.get("last_scan_summary") not in {None, "", "No scan yet"}
            title = self.u("results_clear" if has_scan else "results_empty")
            description = self._localized_scan_summary(state["last_scan_summary"]) if has_scan else self.u("results_empty_body")
            if state and state.get("scan_in_progress"):
                title, description = self.u("scan_running"), self.u("running_results")
            elif has_scan and ("failed" in state["last_scan_summary"] or "stopped" in state["last_scan_summary"]):
                title = self.t("notify.interrupted")
            self.scan_empty_title.configure(text=title)
            self.scan_empty_description.configure(text=description)
        self._refresh_review_actions()

    def _empty(self, parent, glyph, title, description):
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        self._chip(frame, glyph, 48).pack(pady=(42, 10))
        heading = ctk.CTkLabel(frame, text=title, font=ctk.CTkFont(size=16, weight="bold"))
        heading.pack(pady=(2, 5))
        detail = ctk.CTkLabel(frame, text=description, text_color=C["text_soft"], font=ctk.CTkFont(size=12),
                              wraplength=500, justify="center")
        detail.pack(pady=(0, 40))
        frame.heading, frame.detail = heading, detail
        return frame

    def _events_view(self):
        page = self._page()
        self._page_heading(page, self.t("events.title"), self.u("events_body"))
        controls = ctk.CTkFrame(page, fg_color="transparent")
        controls.pack(fill="x", padx=8, pady=(0, 12))
        self.activity_kind_var = tk.StringVar(value=self.u("events_tab"))
        self._activity_snapshot = self.engine.get_snapshot()
        ctk.CTkSegmentedButton(controls, values=[self.u("events_tab"), self.u("files_tab")], variable=self.activity_kind_var,
                               selected_color=C["panel_soft"], selected_hover_color=C["panel_soft"],
                               unselected_color=C["panel"], unselected_hover_color=C["panel_lift"],
                               fg_color=C["line"], text_color=C["text"], height=36,
                               command=lambda value: self._refresh_activity(self._activity_snapshot)).pack(side="left")
        self.activity_alerts_var = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(controls, text=self.u("only_alerts"), variable=self.activity_alerts_var, checkbox_width=17, checkbox_height=17,
                        fg_color=C["button"], border_color=C["text_soft"], font=ctk.CTkFont(size=11),
                        command=lambda: self._refresh_activity(self._activity_snapshot)).pack(side="right")
        self.activity_search_var = tk.StringVar()
        search_row = ctk.CTkFrame(page, fg_color="transparent")
        search_row.pack(fill="x", padx=8, pady=(0, 14))
        ctk.CTkLabel(search_row, text=self.u("search_label"), image=self._icon("scan", size=17), compound="left",
                     text_color=C["text_soft"], font=ctk.CTkFont(size=11)).pack(side="left", padx=(0, 14))
        ctk.CTkEntry(search_row, textvariable=self.activity_search_var, height=38,
                     font=ctk.CTkFont(size=12)).pack(side="left", fill="x", expand=True)
        self.activity_search_var.trace_add("write", lambda *_: self._refresh_activity(self._activity_snapshot))
        card = self._card(page)
        card.pack(fill="both", expand=True, padx=8, pady=(0, 6))
        self.activity_count_var = tk.StringVar()
        ctk.CTkLabel(card, textvariable=self.activity_count_var, text_color=C["text_soft"], font=ctk.CTkFont(size=11), anchor="w").pack(fill="x", padx=20, pady=(16, 10))
        self.event_tree = self._make_tree(card, ("time", "level", "title", "description"),
                                          tuple(self.t("heading." + key) for key in ("time", "level", "title", "description")))
        self.activity_result_tree = self._make_tree(card, ("time", "severity", "score", "path", "action"),
                                                     tuple(self.t("heading." + key) for key in ("time", "severity", "score", "path", "action")))
        self.activity_empty = self._empty(card, "clock", self.u("no_activity"), self.u("activity_empty_body"))
        return page

    def _refresh_activity(self, snapshot):
        if not hasattr(self, "activity_empty"):
            return
        self._activity_snapshot = snapshot
        query = self.activity_search_var.get().strip().casefold()
        only_alerts = self.activity_alerts_var.get()
        files = self.activity_kind_var.get() == self.u("files_tab")
        rows = []
        for item in reversed(snapshot.get("history" if files else "events", [])):
            severity = str(item.get("severity" if files else "level", "info")).casefold()
            if only_alerts and severity not in {"critical", "high", "medium", "warning", "error"}:
                continue
            event_title = self._event_title(str(item.get("title", "")))
            if query and query not in (event_title + " " + " ".join(str(value) for value in item.values())).casefold():
                continue
            if files:
                rows.append((str(item.get("scanned_at", "")).replace("T", "  "), self._level_label(severity), item.get("score", 0),
                             item.get("path", ""), self._action_label(item.get("action_taken", "none"))))
            else:
                rows.append((str(item.get("timestamp", "")).replace("T", "  "), self._level_label(severity), event_title, item.get("description", "")))
        self.activity_count_var.set(self.u("recent_count").format(count=len(rows)))
        shown, hidden = (self.activity_result_tree, self.event_tree) if files else (self.event_tree, self.activity_result_tree)
        hidden.container.pack_forget()
        self._refresh_tree(shown, rows)
        if rows:
            self.activity_empty.pack_forget()
            shown.container.pack(fill="both", expand=True, padx=18, pady=(0, 16))
        else:
            shown.container.pack_forget()
            filtered = bool(query or only_alerts)
            self.activity_empty.heading.configure(text=self.u("no_matches" if filtered else "no_activity"))
            self.activity_empty.detail.configure(text=self.u("no_matches_body" if filtered else "activity_empty_body"))
            self.activity_empty.pack(fill="both", expand=True)

    def _level_label(self, value):
        if self.language != "fr":
            return value.capitalize()
        return {"info": "Information", "low": "Faible", "medium": "À vérifier", "high": "Élevée",
                "critical": "Critique", "warning": "Avertissement", "error": "Erreur"}.get(value, value)

    def _action_label(self, value):
        if self.language != "fr":
            return str(value).replace("_", " ").capitalize()
        return {"none": "Aucune action", "quarantined": "En quarantaine", "ignored": "Ignoré pour cette analyse",
                "quarantine_refused": "Quarantaine refusée", "missing": "Fichier absent"}.get(value, value)

    def _event_title(self, title):
        if self.language != "fr":
            return title
        common = {
            "Settings updated": "Préférences enregistrées", "Threat quarantined": "Fichier mis en quarantaine",
            "Threat ignored": "Élément ignoré pour cette analyse", "Suspicious process launch": "Application à vérifier",
            "Document modification burst observed": "Modifications inhabituelles observées",
            "Canary file touched": "Fichier leurre modifié", "File changed after scan": "Fichier modifié après l’analyse",
            "System file requires review": "Fichier système à vérifier", "Watcher unavailable": "Surveillance indisponible",
        }
        for source, key in [("Quick scan", "scan.quick"), ("Full scan", "scan.full"), ("Custom scan", "scan.custom")]:
            for suffix, label in [("completed", "terminée"), ("stopped", "arrêtée"), ("failed", "interrompue")]:
                common[f"{source} {suffix}"] = f"{self.t(key)} {label}"
        return common.get(title, title)

    def _reason_label(self, value):
        if self.language != "fr":
            return str(value).replace("_", " ").capitalize()
        return {"manual_review": "Décision manuelle", "manual_scan": "Analyse manuelle",
                "realtime_protection": "Protection en temps réel", "process_guard": "Surveillance des applications",
                "panic_mode": "Mode d’urgence"}.get(value, str(value).replace("_", " "))

    def _quarantine_view(self):
        page = self._page()
        self._page_heading(page, self.t("quarantine.title"), self.u("quarantine_body"))
        card = self._card(page)
        card.pack(fill="both", expand=True, padx=8, pady=(0, 6))
        toolbar = ctk.CTkFrame(card, fg_color="transparent")
        toolbar.pack(fill="x", padx=18, pady=(16, 10))
        self.quarantine_restore_button = self._button(toolbar, self.t("quarantine.restore"), self.restore_selected, kind="secondary")
        self.quarantine_restore_button.pack(side="left", padx=(0, 8))
        self.quarantine_delete_button = self._button(toolbar, self.t("quarantine.delete"), self.delete_selected, kind="secondary")
        self.quarantine_delete_button.configure(text_color=C["critical"])
        self.quarantine_delete_button.pack(side="left")
        self.quarantine_feedback_var = tk.StringVar(value=self.u("quarantine_select"))
        ctk.CTkLabel(card, textvariable=self.quarantine_feedback_var, text_color=C["text_soft"], font=ctk.CTkFont(size=11),
                     anchor="w", justify="left", wraplength=630).pack(fill="x", padx=20, pady=(0, 10))
        self.quarantine_tree = self._make_tree(card, ("id", "name", "score", "reason", "time", "path"),
            tuple(self.t("heading." + key) for key in ("id", "name", "score", "reason", "time", "path")))
        self.quarantine_tree.configure(displaycolumns=("name", "path", "score", "reason", "time"))
        self.quarantine_tree.bind("<<TreeviewSelect>>", lambda event: self._refresh_quarantine_actions())
        self.quarantine_empty = self._empty(card, "lock", self.u("quarantine_empty"), self.u("quarantine_empty_body"))
        return page

    def _refresh_quarantine_actions(self):
        selected = bool(self.quarantine_tree.selection())
        self.quarantine_restore_button.configure(state="normal" if selected else "disabled")
        self.quarantine_delete_button.configure(state="normal" if selected else "disabled")

    def _refresh_quarantine(self, entries):
        if not hasattr(self, "quarantine_empty"):
            return
        self._refresh_tree(self.quarantine_tree,
            [(item.get("id", ""), item.get("original_name", ""), item.get("score", ""), self._reason_label(item.get("reason", "")),
              str(item.get("quarantined_at", "")).replace("T", "  "), item.get("original_path", "")) for item in entries],
            preserve_selection=True, row_ids=[str(item.get("id", index)) for index, item in enumerate(entries)])
        if entries:
            self.quarantine_empty.pack_forget()
            self.quarantine_tree.container.pack(fill="both", expand=True, padx=18, pady=(0, 16))
        else:
            self.quarantine_tree.container.pack_forget()
            self.quarantine_empty.pack(fill="both", expand=True)
        self._refresh_quarantine_actions()

    def _settings_view(self):
        page = self._page()
        self._page_heading(page, self.t("settings.title"), self.u("settings_body"))
        footer = ctk.CTkFrame(page, fg_color="transparent")
        footer.pack(side="bottom", fill="x", padx=8, pady=(12, 0))
        self.settings_feedback_var = tk.StringVar(value=self.u("save_hint"))
        self._button(footer, self.t("settings.save"), self.save_settings).pack(side="right")
        ctk.CTkLabel(footer, textvariable=self.settings_feedback_var, text_color=C["text_soft"],
                     font=ctk.CTkFont(size=11), wraplength=450, anchor="w").pack(side="left", fill="x", expand=True)
        form = ctk.CTkScrollableFrame(page, fg_color="transparent", corner_radius=0,
                                     scrollbar_button_color=C["line"], scrollbar_button_hover_color=C["text_soft"])
        form.pack(fill="both", expand=True)
        settings = self.engine.get_snapshot()["settings"]
        self.settings_vars = {name: tk.BooleanVar(value=getattr(settings, name)) for name in (
            "realtime_enabled", "process_guard_enabled", "ransomware_guard_enabled", "automatic_quarantine", "notify_scan_completion")}
        def section(title, description):
            card = self._card(form)
            card.pack(fill="x", padx=8, pady=(0, 14))
            ctk.CTkLabel(card, text=self.u(title), anchor="w", font=ctk.CTkFont(size=15, weight="bold")).pack(fill="x", padx=20, pady=(16, 0))
            ctk.CTkLabel(card, text=self.u(description), text_color=C["text_soft"], wraplength=580, justify="left", anchor="w",
                         font=ctk.CTkFont(size=11)).pack(fill="x", padx=20, pady=(0, 10))
            return card
        protections = section("protection", "protection_body")
        for name, key, body in [
            ("realtime_enabled", "settings.realtime", "realtime_body"),
            ("process_guard_enabled", "settings.process", "process_body"),
            ("ransomware_guard_enabled", "settings.ransomware", "ransomware_body"),
            ("automatic_quarantine", "settings.auto_quarantine", "automatic_body"),
        ]:
            self._setting_row(protections, name, key, body)
        comfort = section("comfort", "comfort_body")
        self._setting_row(comfort, "notify_scan_completion", "settings.notify_scan_completion", "notify_body")
        row = ctk.CTkFrame(comfort, fg_color="transparent")
        row.pack(fill="x", padx=20, pady=(4, 18))
        ctk.CTkLabel(row, text=self.t("settings.language"), font=ctk.CTkFont(size=12)).pack(side="left")
        self.language_var.set(LANGUAGES[self.language])
        ctk.CTkOptionMenu(row, values=list(LANGUAGES.values()), variable=self.language_var,
                          command=lambda value: self.settings_feedback_var.set(self.u("not_saved")), height=34, width=145).pack(side="right")
        folders = section("folders_title", "folders_body")
        self.paths_box = ctk.CTkTextbox(folders, height=100, border_width=1, border_color=C["line"], fg_color=C["bg"],
                                       font=ctk.CTkFont(size=12))
        self.paths_box.pack(fill="x", padx=20, pady=(0, 10))
        self.paths_box.insert("1.0", "\n".join(settings.scan_roots))
        self.paths_box.bind("<KeyRelease>", lambda event: self.settings_feedback_var.set(self.u("not_saved")))
        self._button(folders, self.u("add_folder"), self._add_scan_folder, kind="secondary", image=self._icon("folder", size=16)).pack(anchor="w", padx=20, pady=(0, 16))
        return page

    def _setting_row(self, parent, name, title, body):
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=20, pady=(0, 12))
        switch = ctk.CTkSwitch(row, text="", variable=self.settings_vars[name], onvalue=True, offvalue=False,
                              width=36, switch_width=32, switch_height=19,
                              command=lambda: self.settings_feedback_var.set(self.u("not_saved")))
        switch.pack(side="right", padx=(16, 0))
        labels = ctk.CTkFrame(row, fg_color="transparent")
        labels.pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(labels, text=self.t(title), anchor="w", font=ctk.CTkFont(size=12, weight="bold")).pack(fill="x")
        ctk.CTkLabel(labels, text=self.u(body), text_color=C["text_soft"], wraplength=540, justify="left", anchor="w",
                     font=ctk.CTkFont(size=10)).pack(fill="x")

    def _add_scan_folder(self):
        path = filedialog.askdirectory(parent=self)
        if not path:
            return
        roots = [line.strip() for line in self.paths_box.get("1.0", "end").splitlines() if line.strip()]
        normalize = lambda value: os.path.normcase(os.path.normpath(value))
        if normalize(path) not in {normalize(item) for item in roots}:
            roots.append(path)
            self.paths_box.delete("1.0", "end")
            self.paths_box.insert("1.0", "\n".join(roots))
            self.settings_feedback_var.set(self.u("not_saved"))
