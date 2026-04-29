from __future__ import annotations

import json
import subprocess
from pathlib import Path

from installer import bootstrap_installer


def test_installer_text_falls_back_to_english():
    assert bootstrap_installer.installer_text("fr")["install"] == "Installer"
    assert bootstrap_installer.installer_text("unknown")["install"] == "Install"


def test_write_language_preference_preserves_existing_settings(tmp_path: Path):
    state_dir = tmp_path / "NovaSentinel"
    state_dir.mkdir()
    settings_path = state_dir / "settings.json"
    settings_path.write_text(
        json.dumps({"realtime_enabled": False, "language": "en"}),
        encoding="utf-8",
    )

    bootstrap_installer.write_language_preference("fr", appdata_dir=tmp_path)

    payload = json.loads(settings_path.read_text(encoding="utf-8"))
    assert payload["language"] == "fr"
    assert payload["realtime_enabled"] is False


def test_cmd_installer_starts_login_shortcut_in_background():
    install_script = Path(__file__).resolve().parents[1] / "installer" / "install_runtime.cmd"
    script = install_script.read_text(encoding="utf-8")

    assert "Join-Path $startup 'NovaSentinel.lnk'" in script
    assert "Arguments='--background'" in script
    assert "$shortcut.Arguments = $item.Arguments" in script
    assert "New-ScheduledTaskAction" in script
    assert "Register-ScheduledTask -TaskName '%APP_NAME%'" in script


def test_bootstrap_installer_registers_background_startup_task(monkeypatch, tmp_path: Path):
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(bootstrap_installer.subprocess, "run", fake_run)

    assert bootstrap_installer.create_startup_task(tmp_path) is True

    command = calls[0]
    assert command[:8] == [
        "schtasks",
        "/Create",
        "/TN",
        "NovaSentinel",
        "/SC",
        "ONLOGON",
        "/RL",
        "HIGHEST",
    ]
    assert command[8] == "/TR"
    assert command[9] == f'"{tmp_path / "NovaSentinel.exe"}" --background'


def test_uninstaller_removes_startup_task():
    uninstall_script = Path(__file__).resolve().parents[1] / "installer" / "uninstall_runtime.ps1"
    script = uninstall_script.read_text(encoding="utf-8")

    assert 'Unregister-ScheduledTask -TaskName "NovaSentinel"' in script
