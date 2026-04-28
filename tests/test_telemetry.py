from __future__ import annotations

from novaguard.core.telemetry import _parse_sc_query


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
