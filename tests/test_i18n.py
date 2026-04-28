from __future__ import annotations

from pathlib import Path

import novaguard.config as config
from novaguard.i18n import LANGUAGES, tr
from novaguard.models import AppSettings


def test_core_ui_translations_exist_for_supported_languages():
    for language in LANGUAGES:
        assert tr(language, "subtitle")
        assert tr(language, "nav.settings")
        assert tr(language, "settings.language")
        assert tr(language, "scan.quick")
        assert tr(language, "tray.open")


def test_language_setting_is_persisted(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(config, "STATE_DIR", tmp_path)
    monkeypatch.setattr(config, "QUARANTINE_DIR", tmp_path / "quarantine")
    monkeypatch.setattr(config, "LOG_DIR", tmp_path / "logs")
    monkeypatch.setattr(config, "CANARY_DIR", tmp_path / "canaries")
    monkeypatch.setattr(config, "RECOVERY_DIR", tmp_path / "recovery_vault")
    monkeypatch.setattr(config, "SETTINGS_FILE", tmp_path / "settings.json")

    config.save_settings(AppSettings(language="fr"))

    assert config.load_settings().language == "fr"
