"""Keep all tests away from the installed application's state and ACLs."""
import sys
from pathlib import Path

import pytest
import novaguard.config as config


@pytest.fixture(autouse=True)
def isolated_runtime(tmp_path, monkeypatch):
    root = tmp_path / "runtime"
    paths = {name: value for name, value in vars(config).items()
             if name.isupper() and isinstance(value, Path)}
    replacements = {}
    for name, value in paths.items():
        if name in {"APPDATA_DIR", "PROGRAMDATA_DIR"}:
            replacement = root / name.lower()
        elif name.endswith("_DIR"):
            replacement = root / name.lower()
        else:
            replacement = root / value.name
        replacements[value] = replacement
    for module_name, module in list(sys.modules.items()):
        if module_name.startswith("novaguard") and module is not None:
            for name, value in list(vars(module).items()):
                if isinstance(value, Path) and value in replacements:
                    monkeypatch.setattr(module, name, replacements[value])
    monkeypatch.setattr(config, "_lock_down_directory", lambda directory: None)
