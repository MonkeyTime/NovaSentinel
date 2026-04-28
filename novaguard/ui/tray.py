from __future__ import annotations

import threading
import time
from collections.abc import Callable

import pystray

from novaguard.bootstrap import create_shield_icon
from novaguard.i18n import normalize_language, tr


class TrayController:
    def __init__(
        self,
        on_open: Callable[[], None],
        on_quick_scan: Callable[[], None],
        on_toggle_realtime: Callable[[], None],
        on_panic_mode: Callable[[], None],
        on_exit: Callable[[], None],
        language: str = "en",
    ) -> None:
        self.on_open = on_open
        self.on_quick_scan = on_quick_scan
        self.on_toggle_realtime = on_toggle_realtime
        self.on_panic_mode = on_panic_mode
        self.on_exit = on_exit
        self.language = normalize_language(language)
        self.last_tray_activation = 0.0
        self.icon = pystray.Icon(
            "NovaSentinel",
            create_shield_icon(),
            "NovaSentinel",
            menu=self._build_menu(),
        )
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        if self.thread and self.thread.is_alive():
            return
        self.thread = threading.Thread(target=self.icon.run, name="NovaSentinelTray", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.icon.stop()

    def notify(self, title: str, message: str) -> None:
        try:
            self.icon.notify(message, title)
        except Exception:
            pass

    def update_language(self, language: str) -> None:
        self.language = normalize_language(language)
        self.icon.menu = self._build_menu()

    def _exit(self) -> None:
        self.stop()
        self.on_exit()

    def _open_on_double_click(self) -> None:
        now = time.monotonic()
        if now - self.last_tray_activation <= 0.55:
            self.last_tray_activation = 0.0
            self.on_open()
            return
        self.last_tray_activation = now

    def _build_menu(self) -> pystray.Menu:
        return pystray.Menu(
            pystray.MenuItem(
                tr(self.language, "tray.open"),
                self._safe(self._open_on_double_click),
                default=True,
                visible=False,
            ),
            pystray.MenuItem(tr(self.language, "tray.open"), self._safe(lambda: self.on_open())),
            pystray.MenuItem(tr(self.language, "scan.quick"), self._safe(lambda: self.on_quick_scan())),
            pystray.MenuItem(tr(self.language, "tray.toggle"), self._safe(lambda: self.on_toggle_realtime())),
            pystray.MenuItem(tr(self.language, "ransomware.panic"), self._safe(lambda: self.on_panic_mode())),
            pystray.MenuItem(tr(self.language, "tray.exit"), self._safe(self._exit)),
        )

    def _safe(self, callback):
        def _wrapped(icon=None, item=None):
            callback()

        return _wrapped
