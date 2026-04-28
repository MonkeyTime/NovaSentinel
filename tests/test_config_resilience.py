from __future__ import annotations

import json
from pathlib import Path

import novaguard.config as config
from novaguard.models import AppSettings


def _redirect_state(monkeypatch, root: Path) -> None:
    monkeypatch.setattr(config, "STATE_DIR", root)
    monkeypatch.setattr(config, "QUARANTINE_DIR", root / "quarantine")
    monkeypatch.setattr(config, "LOG_DIR", root / "logs")
    monkeypatch.setattr(config, "CANARY_DIR", root / "canaries")
    monkeypatch.setattr(config, "RECOVERY_DIR", root / "recovery_vault")
    monkeypatch.setattr(config, "SETTINGS_FILE", root / "settings.json")
    monkeypatch.setattr(config, "HISTORY_FILE", root / "history.json")
    monkeypatch.setattr(config, "EVENTS_FILE", root / "events.json")
    monkeypatch.setattr(config, "INCIDENTS_FILE", root / "incidents.json")
    monkeypatch.setattr(config, "LOCKDOWN_STATE_FILE", root / "lockdown_state.json")


def test_json_list_recovers_from_backup_when_primary_is_corrupt(tmp_path: Path, monkeypatch):
    _redirect_state(monkeypatch, tmp_path / "state")
    path = config.HISTORY_FILE

    config.save_json_list(path, [{"id": "first"}])
    config.save_json_list(path, [{"id": "second"}])
    path.write_text("{corrupt", encoding="utf-8")

    assert config.load_json_list(path) == [{"id": "first"}]


def test_settings_load_recovers_when_primary_is_corrupt(tmp_path: Path, monkeypatch):
    _redirect_state(monkeypatch, tmp_path / "state")

    config.save_settings(AppSettings(scan_roots=[str(tmp_path / "safe")], scan_exclusions=[]))
    config.save_settings(AppSettings(scan_roots=[str(tmp_path / "new")], scan_exclusions=[]))
    config.SETTINGS_FILE.write_text("{corrupt", encoding="utf-8")

    settings = config.load_settings()

    assert str(tmp_path / "safe") in settings.scan_roots


def test_settings_load_prunes_legacy_default_exclusions(tmp_path: Path, monkeypatch):
    _redirect_state(monkeypatch, tmp_path / "state")
    custom_exclusion = str(tmp_path / "custom_exclusion")

    config.ensure_runtime_dirs()
    config.SETTINGS_FILE.write_text(
        json.dumps({"scan_roots": [], "scan_exclusions": [str(config.STATE_DIR), custom_exclusion]}),
        encoding="utf-8",
    )

    settings = config.load_settings()

    assert str(config.STATE_DIR) not in settings.scan_exclusions
    assert custom_exclusion in settings.scan_exclusions


def test_json_write_retries_when_replace_is_temporarily_locked(tmp_path: Path, monkeypatch):
    _redirect_state(monkeypatch, tmp_path / "state")
    monkeypatch.setattr(config.time, "sleep", lambda _delay: None)
    path = config.HISTORY_FILE
    original_replace = Path.replace
    attempts = {"count": 0}

    def flaky_replace(self: Path, target: Path):
        if self.name.startswith(path.name) and self.name.endswith(".tmp") and target == path:
            attempts["count"] += 1
            if attempts["count"] == 1:
                raise OSError("[WinError 32] The process cannot access the file because it is being used by another process")
        return original_replace(self, target)

    monkeypatch.setattr(Path, "replace", flaky_replace)

    config.save_json_list(path, [{"id": "locked-once"}])

    assert config.load_json_list(path) == [{"id": "locked-once"}]
    assert attempts["count"] == 2


def test_json_write_drops_locked_update_without_crashing(tmp_path: Path, monkeypatch):
    _redirect_state(monkeypatch, tmp_path / "state")
    monkeypatch.setattr(config.time, "sleep", lambda _delay: None)
    path = config.HISTORY_FILE

    config.save_json_list(path, [{"id": "first"}])
    original_replace = Path.replace

    def locked_replace(self: Path, target: Path):
        if self.name.startswith(path.name) and self.name.endswith(".tmp") and target == path:
            raise OSError("[WinError 32] The process cannot access the file because it is being used by another process")
        return original_replace(self, target)

    monkeypatch.setattr(Path, "replace", locked_replace)

    config.save_json_list(path, [{"id": "second"}])

    assert config.load_json_list(path) == [{"id": "first"}]
    assert not list(path.parent.glob("history.json.*.tmp"))
