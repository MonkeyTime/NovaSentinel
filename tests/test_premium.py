from __future__ import annotations

import base64
import json
import uuid
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import novaguard.core.premium as premium


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _keypair(monkeypatch) -> Ed25519PrivateKey:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    monkeypatch.setattr(premium, "PREMIUM_PUBLIC_KEY", _b64(public))
    return private


def _signed(private: Ed25519PrivateKey, key: str, payload: dict) -> dict:
    return {key: payload, "signature": _b64(private.sign(premium.canonical_json(payload)))}


def _redirect_premium_state(monkeypatch, tmp_path: Path, device_id: str | None = None) -> str:
    device_id = device_id or str(uuid.uuid4())
    monkeypatch.setattr(premium, "PREMIUM_DEVICE_FILE", tmp_path / "premium_device.json")
    monkeypatch.setattr(premium, "PREMIUM_ENTITLEMENT_FILE", tmp_path / "premium_entitlement.json")
    premium.PREMIUM_DEVICE_FILE.write_text(json.dumps({"device_id": device_id}), encoding="utf-8")
    return device_id


def test_signed_premium_entitlement_activates_expected_features(tmp_path: Path, monkeypatch):
    private = _keypair(monkeypatch)
    device_id = _redirect_premium_state(monkeypatch, tmp_path)
    payload = _signed(
        private,
        "entitlement",
        {
            "license_id": "lic_123",
            "plan": "premium",
            "status": "active",
            "customer": "Example Customer",
            "device_id": device_id,
            "features": ["premium_updates", "large_file_scans", "unknown_feature"],
            "expires_at": "2099-01-01T00:00:00Z",
            "checked_at": "2026-06-09T10:00:00Z",
        },
    )

    state = premium.premium_state_from_signed_payload(payload)

    assert state.active is True
    assert state.license_id == "lic_123"
    assert state.has_feature("premium_updates") is True
    assert state.has_feature("large_file_scans") is True
    assert state.has_feature("unknown_feature") is False


def test_signed_premium_entitlement_is_bound_to_device(tmp_path: Path, monkeypatch):
    private = _keypair(monkeypatch)
    _redirect_premium_state(monkeypatch, tmp_path, device_id=str(uuid.uuid4()))
    payload = _signed(
        private,
        "entitlement",
        {
            "license_id": "lic_123",
            "plan": "premium",
            "status": "active",
            "device_id": str(uuid.uuid4()),
            "features": ["premium_updates"],
        },
    )

    with pytest.raises(premium.PremiumError, match="another device"):
        premium.premium_state_from_signed_payload(payload)


def test_premium_update_payload_requires_signature_and_exact_asset(tmp_path: Path, monkeypatch):
    private = _keypair(monkeypatch)
    _redirect_premium_state(monkeypatch, tmp_path)
    digest = "b" * 64
    payload = _signed(
        private,
        "update",
        {
            "version": "0.1.5",
            "tag": "v0.1.5",
            "asset_name": "NovaSentinel-Setup-0.1.5.exe",
            "download_url": "https://github.com/MonkeyTime/NovaSentinel/releases/download/v0.1.5/NovaSentinel-Setup-0.1.5.exe",
            "sha256": digest,
            "release_url": "https://github.com/MonkeyTime/NovaSentinel/releases/tag/v0.1.5",
        },
    )

    update = premium.premium_update_from_signed_payload(payload, "0.1.4")

    assert update is not None
    assert update.version == "0.1.5"
    assert update.sha256 == digest


def test_activate_premium_key_posts_key_and_caches_signed_entitlement(tmp_path: Path, monkeypatch):
    private = _keypair(monkeypatch)
    device_id = _redirect_premium_state(monkeypatch, tmp_path)
    signed_payload = _signed(
        private,
        "entitlement",
        {
            "license_id": "lic_123",
            "plan": "premium",
            "status": "active",
            "device_id": device_id,
            "features": ["premium_updates"],
        },
    )
    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return json.dumps(signed_payload).encode("utf-8")

    def fake_urlopen(request, timeout=0):
        captured["url"] = request.full_url
        captured["payload"] = json.loads(request.data.decode("utf-8"))
        return FakeResponse()

    monkeypatch.setattr(premium, "PREMIUM_VERIFY_URL", "https://example.com/premium/verify")
    monkeypatch.setattr(premium.urllib.request, "urlopen", fake_urlopen)

    state = premium.activate_premium_key("NSP-CLIENT-KEY")

    assert state.active is True
    assert captured["payload"]["key"] == "NSP-CLIENT-KEY"
    assert captured["payload"]["device_id"] == device_id
    assert premium.load_cached_premium_state().active is True
