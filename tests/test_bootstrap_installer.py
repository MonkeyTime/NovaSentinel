from __future__ import annotations

import json
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
