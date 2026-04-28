from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

import psutil


MAX_MATCHED_PROCESSES = 5
MAX_CHILDREN = 8
MAX_OPEN_FILES = 10
MAX_CONNECTIONS = 8
MAX_MEMORY_MAPS = 24
USER_WRITABLE_MARKERS = (
    "\\appdata\\local\\temp\\",
    "\\downloads\\",
    "\\desktop\\",
    "\\public\\",
    "\\startup\\",
)


def collect_post_alert_context(trigger_path: str, trigger_score: int, trigger_reason: str = "detection") -> dict[str, Any]:
    target = Path(trigger_path)
    matched: list[dict[str, Any]] = []
    access_notes: list[str] = []
    for process in psutil.process_iter(["pid", "name", "exe", "cmdline", "ppid", "username", "create_time", "status"]):
        if len(matched) >= MAX_MATCHED_PROCESSES:
            break
        if not _process_matches(process, target):
            continue
        snapshot = _snapshot_process(process)
        if snapshot:
            matched.append(snapshot)
        else:
            pid = getattr(process, "pid", None) or getattr(process, "info", {}).get("pid", "unknown")
            access_notes.append(f"process {pid}: limited access")

    return {
        "collected_at": datetime.now().isoformat(timespec="seconds"),
        "trigger_path": str(target),
        "trigger_score": int(trigger_score),
        "trigger_reason": trigger_reason,
        "matched_process_count": len(matched),
        "matched_processes": matched,
        "notes": access_notes or [
            "No running process matched the alert path."
            if not matched
            else "User-space snapshot only; protected processes may hide modules, files or connections."
        ],
    }


def _process_matches(process: psutil.Process, target: Path) -> bool:
    info = getattr(process, "info", {})
    target_text = str(target).casefold()
    target_name = target.name.casefold()
    exe = str(info.get("exe") or "").casefold()
    cmdline = " ".join(str(item) for item in info.get("cmdline") or []).casefold()
    if target_text and target_text in {exe, cmdline}:
        return True
    if target_text and (target_text in exe or target_text in cmdline):
        return True
    return bool(target_name and (Path(exe).name.casefold() == target_name or target_name in cmdline))


def _snapshot_process(process: psutil.Process) -> dict[str, Any] | None:
    info = getattr(process, "info", {})
    try:
        children = _safe_children(process)
        return {
            "pid": info.get("pid"),
            "name": info.get("name") or "",
            "exe": info.get("exe") or "",
            "cmdline": list(info.get("cmdline") or []),
            "ppid": info.get("ppid"),
            "username": info.get("username") or "",
            "status": info.get("status") or "",
            "create_time": _format_timestamp(info.get("create_time")),
            "children": children,
            "open_files": _safe_open_files(process),
            "connections": _safe_connections(process),
            "memory_maps": _safe_memory_maps(process),
        }
    except (psutil.Error, OSError, RuntimeError):
        return None


def _safe_children(process: psutil.Process) -> list[dict[str, Any]]:
    try:
        children = process.children(recursive=False)
    except (psutil.Error, OSError, AttributeError):
        return []
    snapshots: list[dict[str, Any]] = []
    for child in children[:MAX_CHILDREN]:
        try:
            snapshots.append({
                "pid": child.pid,
                "name": child.name(),
                "exe": child.exe(),
            })
        except (psutil.Error, OSError):
            snapshots.append({"pid": getattr(child, "pid", None), "name": "", "exe": ""})
    return snapshots


def _safe_open_files(process: psutil.Process) -> list[str]:
    try:
        return [item.path for item in process.open_files()[:MAX_OPEN_FILES]]
    except (psutil.Error, OSError, AttributeError):
        return []


def _safe_connections(process: psutil.Process) -> list[dict[str, Any]]:
    try:
        connections = process.net_connections(kind="inet")
    except AttributeError:
        try:
            connections = process.connections(kind="inet")
        except (psutil.Error, OSError, AttributeError):
            return []
    except (psutil.Error, OSError):
        return []
    rows: list[dict[str, Any]] = []
    for connection in connections[:MAX_CONNECTIONS]:
        rows.append({
            "status": getattr(connection, "status", ""),
            "local": _address_text(getattr(connection, "laddr", "")),
            "remote": _address_text(getattr(connection, "raddr", "")),
        })
    return rows


def _safe_memory_maps(process: psutil.Process) -> list[dict[str, Any]]:
    try:
        maps = process.memory_maps(grouped=False)
    except (psutil.Error, OSError, AttributeError):
        return []
    selected: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in maps:
        path = str(getattr(item, "path", "") or "")
        key = path.casefold()
        if not path or key in seen:
            continue
        seen.add(key)
        if not _is_interesting_mapping(path):
            continue
        selected.append({
            "path": path,
            "rss": getattr(item, "rss", 0),
            "private": getattr(item, "private", 0),
        })
        if len(selected) >= MAX_MEMORY_MAPS:
            break
    return selected


def _is_interesting_mapping(path: str) -> bool:
    lowered = path.casefold()
    if any(marker in lowered for marker in USER_WRITABLE_MARKERS):
        return True
    return lowered.endswith((".exe", ".dll", ".sys", ".pyd"))


def _address_text(address: Any) -> str:
    if not address:
        return ""
    ip = getattr(address, "ip", None)
    port = getattr(address, "port", None)
    if ip is not None and port is not None:
        return f"{ip}:{port}"
    if isinstance(address, tuple) and len(address) >= 2:
        return f"{address[0]}:{address[1]}"
    return str(address)


def _format_timestamp(value: Any) -> str:
    try:
        return datetime.fromtimestamp(float(value)).isoformat(timespec="seconds")
    except (TypeError, ValueError, OSError):
        return ""
