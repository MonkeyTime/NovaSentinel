from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any

from novaguard import APP_NAME
from novaguard.models import AppSettings


APPDATA_DIR = Path(os.getenv("APPDATA", str(Path.home() / "AppData" / "Roaming")))
STATE_DIR = APPDATA_DIR / APP_NAME
QUARANTINE_DIR = STATE_DIR / "quarantine"
LOG_DIR = STATE_DIR / "logs"
SETTINGS_FILE = STATE_DIR / "settings.json"
HISTORY_FILE = STATE_DIR / "history.json"
EVENTS_FILE = STATE_DIR / "events.json"
INCIDENTS_FILE = STATE_DIR / "incidents.json"
CANARY_DIR = STATE_DIR / "canaries"
RECOVERY_DIR = STATE_DIR / "recovery_vault"
LOCKDOWN_STATE_FILE = STATE_DIR / "lockdown_state.json"
JSON_WRITE_RETRY_DELAYS = (0.05, 0.15, 0.35, 0.75)
_JSON_WRITE_LOCK = threading.RLock()


def default_temp_roots() -> list[str]:
    home = Path.home()
    local_appdata = Path(os.getenv("LOCALAPPDATA", str(home / "AppData" / "Local")))
    windows_dir = Path(os.getenv("SystemRoot", r"C:\Windows"))
    candidates = [
        Path(os.getenv("TEMP", str(local_appdata / "Temp"))),
        Path(os.getenv("TMP", str(local_appdata / "Temp"))),
        local_appdata / "Temp",
        windows_dir / "Temp",
    ]
    unique: list[str] = []
    for path in candidates:
        if path.exists():
            candidate = str(path)
            if candidate not in unique:
                unique.append(candidate)
    return unique


def default_scan_roots() -> list[str]:
    home = Path.home()
    startup = home / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    candidates = [
        *[Path(path) for path in default_temp_roots()],
        home / "Desktop",
        home / "Downloads",
        home / "Documents",
        startup,
    ]
    unique: list[str] = []
    for path in candidates:
        if path.exists():
            candidate = str(path)
            if candidate not in unique:
                unique.append(candidate)
    return unique


def default_exclusions() -> list[str]:
    return []


def _legacy_default_exclusions() -> list[str]:
    local_appdata = Path(os.getenv("LOCALAPPDATA", str(Path.home() / "AppData" / "Local")))
    windows_dir = Path(os.getenv("SystemRoot", r"C:\Windows"))
    program_files = Path(os.getenv("ProgramFiles", r"C:\Program Files"))
    program_files_x86 = Path(os.getenv("ProgramFiles(x86)", r"C:\Program Files (x86)"))
    exclusions = [windows_dir, program_files, program_files_x86, STATE_DIR]
    app_root = Path(__file__).resolve().parents[1]
    exclusions.append(app_root)
    exclusions.append(local_appdata / "Programs" / APP_NAME)
    if getattr(sys, "frozen", False):
        exclusions.append(Path(sys.executable).resolve().parent)
    return [str(path) for path in exclusions if path.exists()]


def _path_key(path: str) -> str:
    return str(Path(path)).casefold()


def _prune_legacy_default_exclusions(exclusions: list[str]) -> list[str]:
    legacy_defaults = {_path_key(path) for path in _legacy_default_exclusions()}
    current_defaults = {_path_key(path) for path in default_exclusions()}
    pruned: list[str] = []
    for item in exclusions:
        if not item:
            continue
        key = _path_key(item)
        if key in legacy_defaults and key not in current_defaults:
            continue
        if item not in pruned:
            pruned.append(item)
    return pruned


def ensure_runtime_dirs() -> None:
    for directory in [STATE_DIR, QUARANTINE_DIR, LOG_DIR, CANARY_DIR, RECOVERY_DIR]:
        directory.mkdir(parents=True, exist_ok=True)


def load_settings() -> AppSettings:
    ensure_runtime_dirs()
    if not SETTINGS_FILE.exists():
        settings = AppSettings(
            scan_roots=default_scan_roots(),
            scan_exclusions=default_exclusions(),
        )
        save_settings(settings)
        return settings
    payload = _read_json_object(SETTINGS_FILE)
    stored_exclusions = payload.get("scan_exclusions", [])
    merged_exclusions: list[str] = []
    for item in [*_prune_legacy_default_exclusions(stored_exclusions), *default_exclusions()]:
        if item and item not in merged_exclusions:
            merged_exclusions.append(item)
    stored_roots = payload.get("scan_roots", [])
    merged_roots: list[str] = []
    for item in [*default_temp_roots(), *stored_roots, *default_scan_roots()]:
        if item and item not in merged_roots:
            merged_roots.append(item)
    return AppSettings(
        realtime_enabled=payload.get("realtime_enabled", True),
        process_guard_enabled=payload.get("process_guard_enabled", True),
        ransomware_guard_enabled=payload.get("ransomware_guard_enabled", True),
        automatic_quarantine=payload.get("automatic_quarantine", True),
        scan_roots=merged_roots,
        scan_exclusions=merged_exclusions,
        max_file_size_mb=payload.get("max_file_size_mb", 64),
        recent_scan_target=payload.get("recent_scan_target", ""),
        window_geometry=payload.get("window_geometry", ""),
        language=payload.get("language", "en"),
    )


def save_settings(settings: AppSettings) -> None:
    ensure_runtime_dirs()
    _write_json_atomic(SETTINGS_FILE, settings.to_dict())


def load_json_list(path: Path) -> list[dict]:
    ensure_runtime_dirs()
    if not path.exists():
        _write_json_atomic(path, [])
        return []
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        backup = path.with_suffix(path.suffix + ".bak")
        if backup.exists():
            try:
                payload = json.loads(backup.read_text(encoding="utf-8"))
                return payload if isinstance(payload, list) else []
            except json.JSONDecodeError:
                return []
        return []


def save_json_list(path: Path, items: list[dict]) -> None:
    ensure_runtime_dirs()
    _write_json_atomic(path, items)


def _is_transient_file_error(exc: OSError) -> bool:
    if getattr(exc, "winerror", None) == 32:
        return True
    message = str(exc).casefold()
    return (
        "winerror 32" in message
        or "used by another process" in message
        or "being used by another process" in message
        or "utilise par un autre processus" in message
        or "utilisé par un autre processus" in message
        or "le processus ne peut pas acceder au fichier" in message
        or "le processus ne peut pas accéder au fichier" in message
    )


def _json_temp_path(path: Path) -> Path:
    suffix = f".{os.getpid()}.{threading.get_ident()}.tmp"
    return path.with_name(f"{path.name}{suffix}")


def _write_json_atomic(path: Path, payload: Any) -> None:
    ensure_runtime_dirs()
    path.parent.mkdir(parents=True, exist_ok=True)
    backup = path.with_suffix(path.suffix + ".bak")
    temp = _json_temp_path(path)
    serialized = json.dumps(payload, indent=2, ensure_ascii=True)
    with _JSON_WRITE_LOCK:
        if path.exists():
            try:
                backup.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
            except OSError:
                pass
        try:
            temp.write_text(serialized, encoding="utf-8")
        except OSError:
            return
        for delay in [*JSON_WRITE_RETRY_DELAYS, None]:
            try:
                temp.replace(path)
                return
            except OSError as exc:
                if not _is_transient_file_error(exc) or delay is None:
                    break
                time.sleep(delay)
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass


def _read_json_object(path: Path) -> dict[str, Any]:
    for candidate in [path, path.with_suffix(path.suffix + ".bak")]:
        if not candidate.exists():
            continue
        try:
            payload = json.loads(candidate.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            return payload
    return {}
