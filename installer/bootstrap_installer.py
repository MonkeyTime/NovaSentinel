from __future__ import annotations

import os
import json
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

import ctypes


APP_NAME = "NovaSentinel"
STARTUP_TASK_NAME = APP_NAME
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
SUPPORTED_LANGUAGES = [
    ("fr", "Francais"),
    ("en", "English"),
    ("es", "Espanol"),
    ("de", "Deutsch"),
    ("it", "Italiano"),
    ("pt", "Portugues"),
    ("ar", "Arabic"),
]
INSTALLER_TEXT = {
    "en": {
        "title": "NovaSentinel Setup",
        "language_title": "Setup language",
        "language_body": "Select the language to use for setup and NovaSentinel.",
        "install": "Install",
        "cancel": "Cancel",
        "payload_missing": "Installer payload is missing.",
        "launch_blocked": "Installation completed, but Windows blocked auto-launch:\n{error}",
        "completed": "NovaSentinel installation completed.",
        "fallback_prompt": "Choose setup language:\n\nYes = Francais\nNo = English\nCancel = stop setup",
    },
    "fr": {
        "title": "Installation NovaSentinel",
        "language_title": "Langue d'installation",
        "language_body": "Choisissez la langue de l'installation et de NovaSentinel.",
        "install": "Installer",
        "cancel": "Annuler",
        "payload_missing": "Le contenu de l'installateur est introuvable.",
        "launch_blocked": "Installation terminee, mais Windows a bloque le lancement automatique:\n{error}",
        "completed": "Installation de NovaSentinel terminee.",
        "fallback_prompt": "Choisissez la langue d'installation:\n\nOui = Francais\nNon = English\nAnnuler = arreter",
    },
}


def message_box(title: str, message: str, flags: int = 0) -> None:
    ctypes.windll.user32.MessageBoxW(None, message, title, flags)


def resource_path(name: str) -> Path:
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return base / name


def no_window_kwargs() -> dict[str, int]:
    if CREATE_NO_WINDOW:
        return {"creationflags": CREATE_NO_WINDOW}
    return {}


def installer_text(language: str) -> dict[str, str]:
    return INSTALLER_TEXT.get(language, INSTALLER_TEXT["en"])


def default_language() -> str:
    locale_name = (os.getenv("LANG") or os.getenv("LANGUAGE") or "").casefold()
    if locale_name.startswith("fr"):
        return "fr"
    return "en"


def choose_language() -> str | None:
    default = default_language()
    try:
        import tkinter as tk
        from tkinter import ttk
    except Exception:
        flags = 0x03 | 0x20
        result = ctypes.windll.user32.MessageBoxW(
            None,
            installer_text("fr")["fallback_prompt"],
            installer_text("fr")["title"],
            flags,
        )
        if result == 6:
            return "fr"
        if result == 7:
            return "en"
        return None

    selected: str | None = None
    root = tk.Tk()
    root.title(installer_text(default)["title"])
    root.resizable(False, False)

    language_var = tk.StringVar(value=default)
    labels = {label: code for code, label in SUPPORTED_LANGUAGES}

    frame = ttk.Frame(root, padding=18)
    frame.grid(row=0, column=0, sticky="nsew")
    ttk.Label(frame, text=installer_text(default)["language_title"], font=("Segoe UI", 12, "bold")).grid(
        row=0,
        column=0,
        sticky="w",
    )
    ttk.Label(frame, text=installer_text(default)["language_body"], wraplength=320).grid(
        row=1,
        column=0,
        sticky="w",
        pady=(8, 12),
    )
    language_box = ttk.Combobox(
        frame,
        state="readonly",
        values=[label for _, label in SUPPORTED_LANGUAGES],
        width=28,
    )
    language_box.set(next(label for code, label in SUPPORTED_LANGUAGES if code == default))
    language_box.grid(row=2, column=0, sticky="ew")

    buttons = ttk.Frame(frame)
    buttons.grid(row=3, column=0, sticky="e", pady=(16, 0))

    def sync_text(*_args: object) -> None:
        language_var.set(labels.get(language_box.get(), "en"))

    def finish() -> None:
        nonlocal selected
        sync_text()
        selected = language_var.get()
        root.destroy()

    def cancel() -> None:
        root.destroy()

    language_box.bind("<<ComboboxSelected>>", sync_text)
    ttk.Button(buttons, text=installer_text(default)["cancel"], command=cancel).grid(row=0, column=0, padx=(0, 8))
    ttk.Button(buttons, text=installer_text(default)["install"], command=finish).grid(row=0, column=1)
    root.protocol("WM_DELETE_WINDOW", cancel)
    root.bind("<Return>", lambda _event: finish())
    root.bind("<Escape>", lambda _event: cancel())

    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    left = (root.winfo_screenwidth() - width) // 2
    top = (root.winfo_screenheight() - height) // 2
    root.geometry(f"{width}x{height}+{left}+{top}")
    root.mainloop()
    return selected


def write_language_preference(language: str, appdata_dir: Path | None = None) -> None:
    appdata = appdata_dir or Path(os.getenv("APPDATA", str(Path.home() / "AppData" / "Roaming")))
    state_dir = appdata / APP_NAME
    settings_path = state_dir / "settings.json"
    state_dir.mkdir(parents=True, exist_ok=True)
    payload = {}
    if settings_path.exists():
        try:
            current = json.loads(settings_path.read_text(encoding="utf-8"))
            if isinstance(current, dict):
                payload = current
        except (OSError, json.JSONDecodeError):
            payload = {}
    payload["language"] = language
    temp_path = settings_path.with_name(f"{settings_path.name}.{os.getpid()}.tmp")
    temp_path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")
    temp_path.replace(settings_path)


def stop_running_app() -> None:
    subprocess.run(
        ["taskkill", "/IM", "NovaSentinel.exe", "/F"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        **no_window_kwargs(),
    )


def startup_shortcut_path() -> Path:
    return (
        Path(os.getenv("APPDATA", ""))
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "Startup"
        / "NovaSentinel.lnk"
    )


def remove_startup_shortcut() -> None:
    try:
        startup_shortcut_path().unlink(missing_ok=True)
    except OSError:
        pass


def create_startup_task(install_dir: Path) -> bool:
    exe_path = install_dir / "NovaSentinel.exe"
    action = f'"{exe_path}" --background'
    try:
        result = subprocess.run(
            [
                "schtasks",
                "/Create",
                "/TN",
                STARTUP_TASK_NAME,
                "/SC",
                "ONLOGON",
                "/RL",
                "HIGHEST",
                "/TR",
                action,
                "/F",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            **no_window_kwargs(),
        )
    except OSError:
        return False
    return result.returncode == 0


def create_shortcuts(install_dir: Path) -> None:
    startup = startup_shortcut_path().parent
    programs = Path(os.getenv("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs"
    desktop = Path.home() / "Desktop"
    icon_path = install_dir / "novasentinel_icon.ico"
    icon_location = icon_path if icon_path.exists() else install_dir / "NovaSentinel.exe"
    shortcuts = [
        (startup / "NovaSentinel.lnk", "--background"),
        (programs / "NovaSentinel.lnk", ""),
        (desktop / "NovaSentinel.lnk", ""),
    ]
    ps_script = "\n".join(
        [
            "$shell = New-Object -ComObject WScript.Shell",
            f"$target = '{str((install_dir / 'NovaSentinel.exe')).replace("'", "''")}'",
            f"$working = '{str(install_dir).replace("'", "''")}'",
            f"$icon = '{str(icon_location).replace("'", "''")}'",
            *[
                (
                    f"$shortcut = $shell.CreateShortcut('{str(link).replace("'", "''")}')\n"
                    "$shortcut.TargetPath = $target\n"
                    f"$shortcut.Arguments = '{arguments.replace("'", "''")}'\n"
                    "$shortcut.WorkingDirectory = $working\n"
                    "$shortcut.IconLocation = $icon\n"
                    "$shortcut.Save()"
                )
                for link, arguments in shortcuts
            ],
        ]
    )
    subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
        **no_window_kwargs(),
    )


def install() -> int:
    language = choose_language()
    if language is None:
        return 0
    text = installer_text(language)
    zip_path = resource_path("NovaSentinel.zip")
    uninstall_script = resource_path("uninstall_runtime.ps1")
    if not zip_path.exists():
        message_box(text["title"], text["payload_missing"], 0x10)
        return 1

    install_dir = Path(os.getenv("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))) / "Programs" / APP_NAME
    install_dir.parent.mkdir(parents=True, exist_ok=True)

    stop_running_app()
    shutil.rmtree(install_dir, ignore_errors=True)
    install_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(zip_path) as archive:
        archive.extractall(install_dir)

    shutil.copy2(uninstall_script, install_dir / "uninstall_runtime.ps1")
    create_shortcuts(install_dir)
    if create_startup_task(install_dir):
        remove_startup_shortcut()
    write_language_preference(language)

    exe_path = install_dir / "NovaSentinel.exe"
    try:
        subprocess.Popen([str(exe_path)], cwd=str(install_dir), **no_window_kwargs())
    except OSError as exc:
        message_box(
            text["title"],
            text["launch_blocked"].format(error=exc),
            0x30,
        )
        return 0

    message_box(text["title"], text["completed"], 0x40)
    return 0


if __name__ == "__main__":
    temp_dir = Path(tempfile.mkdtemp(prefix="novasentinel-installer-"))
    try:
        sys.exit(install())
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
