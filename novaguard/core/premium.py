from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from novaguard import APP_VERSION
from novaguard.config import PREMIUM_DEVICE_FILE, PREMIUM_ENTITLEMENT_FILE, _write_json_atomic, ensure_runtime_dirs
from novaguard.core.updater import EXPECTED_ASSET_TEMPLATE, UpdateError, UpdateInfo, is_newer_version


PREMIUM_VERIFY_URL = os.getenv("NOVASENTINEL_PREMIUM_VERIFY_URL", "https://novasentinel.app/api/premium/verify")
PREMIUM_UPDATE_URL = os.getenv("NOVASENTINEL_PREMIUM_UPDATE_URL", "https://novasentinel.app/api/premium/releases/latest")
PREMIUM_PUBLIC_KEY = ""
REQUEST_TIMEOUT_SECONDS = 10
ALLOWED_FEATURES = {
    "premium_updates",
    "large_file_scans",
    "extended_forensics",
    "recovery_vault",
}


class PremiumError(RuntimeError):
    pass


@dataclass(frozen=True)
class PremiumState:
    active: bool
    status: str
    license_id: str = ""
    plan: str = ""
    customer: str = ""
    expires_at: str = ""
    checked_at: str = ""
    features: tuple[str, ...] = ()

    def has_feature(self, feature: str) -> bool:
        return self.active and feature in self.features


def mask_premium_key(key: str) -> str:
    cleaned = key.strip()
    if len(cleaned) <= 8:
        return "*" * len(cleaned)
    return f"{cleaned[:4]}...{cleaned[-4:]}"


def premium_key_fingerprint(key: str) -> str:
    return hashlib.sha256(key.strip().encode("utf-8")).hexdigest()


def get_premium_device_id() -> str:
    ensure_runtime_dirs()
    payload = _read_json_object(PREMIUM_DEVICE_FILE)
    current = str(payload.get("device_id", ""))
    if _is_valid_device_id(current):
        return current
    device_id = str(uuid.uuid4())
    _write_json_atomic(PREMIUM_DEVICE_FILE, {"device_id": device_id})
    return device_id


def activate_premium_key(key: str) -> PremiumState:
    cleaned = key.strip()
    if not cleaned:
        raise PremiumError("Premium key is empty.")
    payload = {
        "key": cleaned,
        "key_fingerprint": premium_key_fingerprint(cleaned),
        "device_id": get_premium_device_id(),
        "app_version": APP_VERSION,
    }
    response = _post_json(PREMIUM_VERIFY_URL, payload)
    state = premium_state_from_signed_payload(response, require_device_match=True)
    if not state.active:
        raise PremiumError(state.status or "Premium key is not active.")
    _write_json_atomic(
        PREMIUM_ENTITLEMENT_FILE,
        {
            "entitlement": response.get("entitlement", {}),
            "signature": str(response.get("signature", "")),
            "key_mask": mask_premium_key(cleaned),
            "key_fingerprint": premium_key_fingerprint(cleaned),
        },
    )
    return state


def load_cached_premium_state() -> PremiumState:
    payload = _read_json_object(PREMIUM_ENTITLEMENT_FILE)
    if not payload:
        return PremiumState(active=False, status="inactive")
    try:
        return premium_state_from_signed_payload(payload, require_device_match=True)
    except PremiumError as exc:
        return PremiumState(active=False, status=str(exc))


def premium_state_from_signed_payload(payload: dict[str, Any], require_device_match: bool = True) -> PremiumState:
    entitlement = payload.get("entitlement")
    if not isinstance(entitlement, dict):
        raise PremiumError("Premium entitlement is missing.")
    signature = str(payload.get("signature", ""))
    _verify_signed_object(entitlement, signature)
    if require_device_match and str(entitlement.get("device_id", "")) != get_premium_device_id():
        raise PremiumError("Premium entitlement belongs to another device.")
    plan = str(entitlement.get("plan", "")).strip().lower()
    status = str(entitlement.get("status", "")).strip().lower()
    features = tuple(sorted(feature for feature in entitlement.get("features", []) if feature in ALLOWED_FEATURES))
    expires_at = str(entitlement.get("expires_at", "")).strip()
    if status not in {"active", "trialing"}:
        return PremiumState(active=False, status=status or "inactive")
    if plan not in {"premium", "pro", "business"}:
        return PremiumState(active=False, status="unsupported_plan")
    if _is_expired(expires_at):
        return PremiumState(active=False, status="expired", expires_at=expires_at)
    return PremiumState(
        active=True,
        status=status,
        license_id=str(entitlement.get("license_id", "")),
        plan=plan,
        customer=str(entitlement.get("customer", "")),
        expires_at=expires_at,
        checked_at=str(entitlement.get("checked_at", "")),
        features=features,
    )


def fetch_latest_premium_update(current_version: str) -> UpdateInfo | None:
    state = load_cached_premium_state()
    if not state.has_feature("premium_updates"):
        return None
    cached = _read_json_object(PREMIUM_ENTITLEMENT_FILE)
    response = _post_json(
        PREMIUM_UPDATE_URL,
        {
            "device_id": get_premium_device_id(),
            "app_version": APP_VERSION,
            "license_id": state.license_id,
            "entitlement": cached.get("entitlement", {}),
            "signature": cached.get("signature", ""),
        },
    )
    return premium_update_from_signed_payload(response, current_version)


def premium_update_from_signed_payload(payload: dict[str, Any], current_version: str) -> UpdateInfo | None:
    update = payload.get("update")
    if not isinstance(update, dict):
        return None
    signature = str(payload.get("signature", ""))
    _verify_signed_object(update, signature)
    version = str(update.get("version", "")).strip()
    if not is_newer_version(version, current_version):
        return None
    expected_asset_name = EXPECTED_ASSET_TEMPLATE.format(version=version)
    asset_name = str(update.get("asset_name", ""))
    if asset_name != expected_asset_name:
        raise UpdateError(f"Premium release does not include {expected_asset_name}.")
    sha256 = str(update.get("sha256", "")).strip().lower().removeprefix("sha256:")
    if not re.fullmatch(r"[0-9a-f]{64}", sha256):
        raise UpdateError(f"Premium release asset {expected_asset_name} has an invalid SHA-256 digest.")
    download_url = str(update.get("download_url", ""))
    _require_premium_download_url(download_url)
    return UpdateInfo(
        version=version,
        tag=str(update.get("tag", f"v{version}")),
        name=str(update.get("name", f"NovaSentinel {version} Premium")),
        asset_name=asset_name,
        download_url=download_url,
        sha256=sha256,
        release_url=str(update.get("release_url", "")),
        published_at=str(update.get("published_at", "")),
    )


def canonical_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _verify_signed_object(payload: dict[str, Any], signature: str) -> None:
    public_key = _load_public_key()
    try:
        public_key.verify(_b64decode(signature), canonical_json(payload))
    except (InvalidSignature, ValueError) as exc:
        raise PremiumError("Premium server signature is invalid.") from exc


def _load_public_key() -> Ed25519PublicKey:
    public_key = PREMIUM_PUBLIC_KEY
    if not public_key and os.getenv("NOVASENTINEL_PREMIUM_DEV_MODE") == "1":
        public_key = os.getenv("NOVASENTINEL_PREMIUM_PUBLIC_KEY", "")
    if not public_key:
        raise PremiumError("Premium public key is not configured.")
    try:
        raw = _b64decode(public_key)
        return Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as exc:
        raise PremiumError("Premium public key is invalid.") from exc


def _post_json(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise PremiumError("Premium validation requires HTTPS.")
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, ensure_ascii=True).encode("utf-8"),
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "NovaSentinel-Premium",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            body = response.read().decode("utf-8")
    except Exception as exc:
        raise PremiumError(f"Premium validation failed: {exc}") from exc
    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:
        raise PremiumError("Premium server returned invalid JSON.") from exc
    if not isinstance(data, dict):
        raise PremiumError("Premium server returned an invalid payload.")
    return data


def _require_premium_download_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise UpdateError("Premium release download URL must use HTTPS.")
    if parsed.netloc.lower() == "github.com":
        expected_prefix = "/MonkeyTime/NovaSentinel/releases/download/"
        if parsed.path.startswith(expected_prefix):
            return
    premium_host = urlparse(PREMIUM_UPDATE_URL).netloc.lower()
    if premium_host and parsed.netloc.lower() == premium_host:
        return
    raise UpdateError("Premium release download URL is not an expected host.")


def _is_expired(value: str) -> bool:
    if not value:
        return False
    try:
        expires = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return True
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    return expires <= datetime.now(timezone.utc)


def _is_valid_device_id(value: str) -> bool:
    try:
        uuid.UUID(value)
    except ValueError:
        return False
    return True


def _read_json_object(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _b64decode(value: str) -> bytes:
    cleaned = value.strip()
    padding = "=" * (-len(cleaned) % 4)
    return base64.urlsafe_b64decode(cleaned + padding)
