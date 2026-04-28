from __future__ import annotations

import ctypes
import os
import subprocess
import sys

from novaguard import APP_NAME
from novaguard.core.engine import NovaSentinelEngine
from novaguard.ui.dashboard import NovaSentinelWindow
from novaguard.ui.tray import TrayController


def _set_windows_app_id() -> None:
    if sys.platform != "win32" or not hasattr(ctypes, "windll"):
        return
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(f"NovaSentinel.{APP_NAME}")
    except Exception:
        pass


def _is_windows_admin() -> bool:
    if sys.platform != "win32" or not hasattr(ctypes, "windll"):
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _relaunch_as_admin() -> None:
    if getattr(sys, "frozen", False):
        executable = sys.executable
        parameters = subprocess.list2cmdline(sys.argv[1:])
    else:
        executable = sys.executable
        parameters = subprocess.list2cmdline([os.path.abspath(sys.argv[0]), *sys.argv[1:]])
    try:
        result = ctypes.windll.shell32.ShellExecuteW(None, "runas", executable, parameters, os.getcwd(), 1)
    except Exception as exc:
        raise RuntimeError(f"Unable to request administrator privileges: {exc}") from exc
    if result <= 32:
        raise RuntimeError(f"Administrator elevation was not granted, ShellExecuteW returned {result}.")


def _ensure_windows_admin() -> None:
    if _is_windows_admin():
        return
    _relaunch_as_admin()
    raise SystemExit(0)


def main() -> None:
    if sys.platform != "win32":
        print("NovaSentinel targets Windows 11 and is intended to run on win32.")
    _ensure_windows_admin()
    start_in_background = "--background" in sys.argv or "--tray" in sys.argv
    _set_windows_app_id()
    engine = NovaSentinelEngine()
    engine.start_background_services()
    app = NovaSentinelWindow(engine)
    if start_in_background:
        app.withdraw()

    def toggle_realtime() -> None:
        settings = engine.get_snapshot()["settings"]
        settings.realtime_enabled = not settings.realtime_enabled
        engine.update_settings(settings)

    def exit_app() -> None:
        engine.stop_background_services()
        app.destroy()
        os._exit(0)

    tray = TrayController(
        on_open=lambda: app.after(0, app.show_from_tray),
        on_quick_scan=engine.quick_scan,
        on_toggle_realtime=toggle_realtime,
        on_panic_mode=engine.panic_mode,
        on_exit=exit_app,
        language=engine.get_snapshot()["settings"].language,
    )
    app.set_notifier(lambda title, message: tray.notify(title, message))
    app.set_language_change_callback(tray.update_language)
    tray.start()
    app.mainloop()


if __name__ == "__main__":
    main()
