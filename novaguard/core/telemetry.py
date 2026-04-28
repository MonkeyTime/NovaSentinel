from __future__ import annotations

import platform
import subprocess
from datetime import datetime


SERVICE_TIMEOUT_SECONDS = 1.5


def collect_telemetry_status() -> dict:
    if platform.system().lower() != "windows":
        return {
            "collected_at": datetime.now().isoformat(timespec="seconds"),
            "platform": platform.system(),
            "supported": False,
            "summary": "Windows service telemetry is only available on Windows.",
            "services": {},
        }

    services = {
        "sysmon": _first_available_service(["Sysmon64", "Sysmon"]),
        "defender": _first_available_service(["WinDefend"]),
        "windows_security": _first_available_service(["SecurityHealthService", "wscsvc"]),
    }
    sysmon = services["sysmon"]
    defender = services["defender"]
    if sysmon.get("running"):
        summary = "Sysmon is available; NovaSentinel can be paired with richer host telemetry."
    elif defender.get("running"):
        summary = "Microsoft Defender is running; Sysmon is not currently detected."
    else:
        summary = "Core Windows security telemetry was not confirmed from user-space checks."
    return {
        "collected_at": datetime.now().isoformat(timespec="seconds"),
        "platform": platform.system(),
        "supported": True,
        "summary": summary,
        "services": services,
    }


def _first_available_service(names: list[str]) -> dict:
    checked: list[dict] = []
    for name in names:
        status = _query_service(name)
        checked.append(status)
        if status.get("installed"):
            status["aliases_checked"] = names
            return status
    fallback = checked[0] if checked else {"name": "", "installed": False, "state": "unknown"}
    fallback["aliases_checked"] = names
    return fallback


def _query_service(name: str) -> dict:
    try:
        completed = subprocess.run(
            ["sc.exe", "query", name],
            capture_output=True,
            text=True,
            timeout=SERVICE_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "name": name,
            "installed": False,
            "running": False,
            "state": "unavailable",
            "detail": str(exc),
        }
    return _parse_sc_query(name, completed.stdout + completed.stderr, completed.returncode)


def _parse_sc_query(name: str, output: str, returncode: int) -> dict:
    lowered = output.lower()
    if returncode != 0 or "does not exist" in lowered or "1060" in lowered:
        return {
            "name": name,
            "installed": False,
            "running": False,
            "state": "not_installed",
            "detail": "service not installed",
        }

    state = "unknown"
    for line in output.splitlines():
        if "STATE" not in line.upper():
            continue
        parts = line.split(":", 1)
        if len(parts) == 2:
            state = parts[1].strip().split()[-1].lower()
            break
    return {
        "name": name,
        "installed": True,
        "running": state == "running",
        "state": state,
        "detail": "service detected",
    }
