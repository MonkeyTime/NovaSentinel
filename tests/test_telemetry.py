from __future__ import annotations

import subprocess

import novaguard.core.telemetry as telemetry_module
from novaguard.core.telemetry import _parse_sc_query, _query_service


def test_parse_sc_query_running_service():
    output = """
SERVICE_NAME: WinDefend
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
"""

    status = _parse_sc_query("WinDefend", output, 0)

    assert status["installed"] is True
    assert status["running"] is True
    assert status["state"] == "running"


def test_parse_sc_query_missing_service():
    output = "[SC] EnumQueryServicesStatus:OpenService FAILED 1060: The specified service does not exist as an installed service."

    status = _parse_sc_query("Sysmon64", output, 1060)

    assert status["installed"] is False
    assert status["running"] is False
    assert status["state"] == "not_installed"


def test_service_query_uses_no_window_flag(monkeypatch):
    calls = []
    monkeypatch.setattr(telemetry_module, "NO_WINDOW_FLAGS", 0x08000000)

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(telemetry_module.subprocess, "run", fake_run)

    _query_service("WinDefend")

    assert calls[0][1]["creationflags"] == 0x08000000
