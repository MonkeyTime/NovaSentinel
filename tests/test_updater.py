from __future__ import annotations

import hashlib

import pytest

from novaguard.core.updater import (
    UpdateError,
    download_update_installer,
    is_newer_version,
    update_from_release_payload,
)


def _release_payload(version: str = "0.1.2", digest: str | None = None, asset_name: str | None = None) -> dict:
    installer_name = asset_name or f"NovaSentinel-Setup-{version}.exe"
    if digest is None:
        digest = "sha256:" + ("a" * 64)
    return {
        "tag_name": f"v{version}",
        "name": f"NovaSentinel {version}",
        "html_url": f"https://github.com/MonkeyTime/NovaSentinel/releases/tag/v{version}",
        "draft": False,
        "prerelease": False,
        "assets": [
            {
                "name": installer_name,
                "browser_download_url": f"https://github.com/MonkeyTime/NovaSentinel/releases/download/v{version}/{installer_name}",
                "digest": digest,
            }
        ],
    }


def test_version_comparison_uses_semver_ordering():
    assert is_newer_version("0.1.2", "0.1.1") is True
    assert is_newer_version("v0.2.0", "0.1.9") is True
    assert is_newer_version("0.1.1", "0.1.1") is False
    assert is_newer_version("0.1.0", "0.1.1") is False
    assert is_newer_version("latest", "0.1.1") is False


def test_update_payload_requires_exact_installer_asset_and_digest():
    update = update_from_release_payload(_release_payload(), "0.1.1")

    assert update is not None
    assert update.version == "0.1.2"
    assert update.asset_name == "NovaSentinel-Setup-0.1.2.exe"
    assert update.sha256 == "a" * 64

    with pytest.raises(UpdateError):
        update_from_release_payload(_release_payload(digest=""), "0.1.1")

    with pytest.raises(UpdateError):
        update_from_release_payload(_release_payload(asset_name="NovaSentinel.exe"), "0.1.1")


def test_update_payload_rejects_unexpected_download_hosts():
    payload = _release_payload()
    payload["assets"][0]["browser_download_url"] = "https://example.com/NovaSentinel-Setup-0.1.2.exe"

    with pytest.raises(UpdateError):
        update_from_release_payload(payload, "0.1.1")


def test_download_verifies_sha256(monkeypatch, tmp_path):
    payload = b"installer-bytes"
    digest = hashlib.sha256(payload).hexdigest()
    update = update_from_release_payload(_release_payload(digest=f"sha256:{digest}"), "0.1.1")
    assert update is not None

    class FakeResponse:
        headers = {"Content-Length": str(len(payload))}

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self, size=-1):
            if getattr(self, "_done", False):
                return b""
            self._done = True
            return payload

    monkeypatch.setattr("novaguard.core.updater.tempfile.gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr("novaguard.core.updater.urllib.request.urlopen", lambda request, timeout=0: FakeResponse())

    installer = download_update_installer(update)

    assert installer.exists()
    assert installer.read_bytes() == payload
