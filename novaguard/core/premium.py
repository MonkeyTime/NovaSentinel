from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import urllib.parse
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
from novaguard.config import (
    PREMIUM_DEPLOYMENT_FILE,
    PREMIUM_DEVICE_FILE,
    PREMIUM_ENTITLEMENT_FILE,
    _write_json_atomic,
    ensure_runtime_dirs,
)
from novaguard.core.updater import EXPECTED_ASSET_TEMPLATE, UpdateError, UpdateInfo, is_newer_version


PREMIUM_VERIFY_URL = os.getenv("NOVASENTINEL_PREMIUM_VERIFY_URL", "https://novasentinel.app/api/premium/verify")
UPDATE_URL = os.getenv("NOVASENTINEL_UPDATE_URL") or os.getenv("NOVASENTINEL_PREMIUM_UPDATE_URL", "https://novasentinel.app/api/releases/latest")
PREMIUM_PUBLIC_KEY = ""
REQUEST_TIMEOUT_SECONDS = 10
ALLOWED_FEATURES = {
    "premium_updates",
    "beta_channel",
    "large_file_scans",
    "extended_forensics",
    "recovery_vault",
    "detection_rule_updates",
    "signature_database",
    "enriched_heuristics",
    "ioc_feeds",
    "realtime_rule_sync",
    "cloud_reputation",
    "unknown_hash_lookup",
    "community_score",
    "private_reputation_cache",
    "privacy_mode",
    "advanced_ransomware",
    "protected_sensitive_backups",
    "suspect_encryption_restore",
    "lightweight_snapshots",
    "suspect_process_lock",
    "advanced_behavior",
    "process_tree",
    "windows_persistence_detection",
    "suspicious_network_monitor",
    "file_process_registry_correlation",
    "forensics_pro",
    "report_export_pdf_html",
    "incident_timeline",
    "export_json_csv",
    "enriched_manual_evidence",
    "advanced_scheduling",
    "scheduled_scans",
    "scan_profiles",
    "usb_auto_scan",
    "advanced_exclusions",
    "fleet_console",
    "admin_console_download",
    "mass_deployment",
    "bulk_license_management",
    "preconfiguration_packages",
    "enterprise_mode",
    "silent_install",
    "deployment_grouping",
    "license_csv_export",
    "audit_logs",
    "deployment_audit",
    "priority_support",
    "signed_installer",
    "professional_docs",
}
PREMIUM_FEATURE_GROUPS = [
    {
        "code": "detection_rule_updates",
        "title_key": "premium.group.rules",
        "body_key": "premium.group.rules_body",
        "features": ("signature_database", "enriched_heuristics", "ioc_feeds", "realtime_rule_sync"),
    },
    {
        "code": "cloud_reputation",
        "title_key": "premium.group.cloud",
        "body_key": "premium.group.cloud_body",
        "features": ("unknown_hash_lookup", "community_score", "private_reputation_cache", "privacy_mode"),
    },
    {
        "code": "advanced_ransomware",
        "title_key": "premium.group.ransomware",
        "body_key": "premium.group.ransomware_body",
        "features": ("protected_sensitive_backups", "suspect_encryption_restore", "lightweight_snapshots", "suspect_process_lock"),
    },
    {
        "code": "advanced_behavior",
        "title_key": "premium.group.behavior",
        "body_key": "premium.group.behavior_body",
        "features": ("process_tree", "windows_persistence_detection", "suspicious_network_monitor", "file_process_registry_correlation"),
    },
    {
        "code": "forensics_pro",
        "title_key": "premium.group.forensics",
        "body_key": "premium.group.forensics_body",
        "features": ("report_export_pdf_html", "incident_timeline", "export_json_csv", "enriched_manual_evidence"),
    },
    {
        "code": "advanced_scheduling",
        "title_key": "premium.group.scheduling",
        "body_key": "premium.group.scheduling_body",
        "features": ("scheduled_scans", "scan_profiles", "usb_auto_scan", "advanced_exclusions"),
    },
    {
        "code": "fleet_console",
        "title_key": "premium.group.fleet",
        "body_key": "premium.group.fleet_body",
        "features": ("admin_console_download", "mass_deployment", "bulk_license_management", "preconfiguration_packages"),
    },
    {
        "code": "enterprise_mode",
        "title_key": "premium.group.enterprise",
        "body_key": "premium.group.enterprise_body",
        "features": ("silent_install", "deployment_grouping", "license_csv_export", "audit_logs", "deployment_audit"),
    },
    {
        "code": "premium_updates",
        "title_key": "premium.group.distribution",
        "body_key": "premium.group.distribution_body",
        "features": ("signed_installer", "priority_support", "beta_channel", "professional_docs"),
    },
]


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

    def has_any_feature(self, features: tuple[str, ...]) -> bool:
        return self.active and any(feature in self.features for feature in features)


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


def load_deployment_premium_key() -> str:
    env_key = os.getenv("NOVASENTINEL_PREMIUM_LICENSE_KEY", "").strip()
    if env_key:
        return env_key
    payload = _read_json_object(PREMIUM_DEPLOYMENT_FILE)
    return str(payload.get("license_key", "")).strip()


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
    if plan != "premium":
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


def fetch_latest_managed_update(current_version: str) -> UpdateInfo | None:
    state = load_cached_premium_state()
    if not state.has_feature("premium_updates"):
        return None
    channel = "beta" if state.has_feature("beta_channel") and os.getenv("NOVASENTINEL_PREMIUM_UPDATE_CHANNEL") == "beta" else "stable"
    query = urllib.parse.urlencode({"channel": channel, "current_version": current_version})
    separator = "&" if "?" in UPDATE_URL else "?"
    response = _get_json(f"{UPDATE_URL}{separator}{query}")
    return premium_update_from_signed_payload(response, current_version)


def fetch_latest_premium_update(current_version: str) -> UpdateInfo | None:
    return fetch_latest_managed_update(current_version)


def premium_update_from_signed_payload(payload: dict[str, Any], current_version: str) -> UpdateInfo | None:
    update = payload.get("update")
    if not isinstance(update, dict) and isinstance(payload.get("release"), dict):
        release = payload["release"]
        update = {
            "version": release.get("version", ""),
            "tag": f"v{release.get('version', '')}",
            "name": f"NovaSentinel {release.get('version', '')}",
            "asset_name": Path(urlparse(str(release.get("installer_url", "")).strip()).path).name,
            "download_url": release.get("installer_url", ""),
            "sha256": release.get("sha256", ""),
            "release_url": release.get("release_url", ""),
            "published_at": release.get("published_at", ""),
        }
    if not isinstance(update, dict):
        return None
    signature = str(payload.get("signature", ""))
    _verify_signed_object(update, signature)
    version = str(update.get("version", "")).strip()
    if not is_newer_version(version, current_version):
        return None
    asset_name = str(update.get("asset_name", ""))
    _require_premium_asset_name(asset_name, version)
    sha256 = str(update.get("sha256", "")).strip().lower().removeprefix("sha256:")
    if not re.fullmatch(r"[0-9a-f]{64}", sha256):
        raise UpdateError(f"Premium release asset {asset_name or version} has an invalid SHA-256 digest.")
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
            status = getattr(response, "status", 200)
            if status < 200 or status >= 300:
                raise PremiumError(f"Premium validation failed with HTTP {status}.")
            body = response.read().decode("utf-8", errors="replace")
    except Exception as exc:
        raise PremiumError(f"Premium validation failed: {exc}") from exc
    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:
        raise PremiumError("Premium server returned invalid JSON.") from exc
    if not isinstance(data, dict):
        raise PremiumError("Premium server returned an invalid payload.")
    return data


def _get_json(url: str) -> dict[str, Any]:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise PremiumError("Update lookup requires HTTPS.")
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "NovaSentinel-Premium",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            status = getattr(response, "status", 200)
            if status < 200 or status >= 300:
                raise PremiumError(f"Update lookup failed with HTTP {status}.")
            body = response.read().decode("utf-8", errors="replace")
    except Exception as exc:
        raise PremiumError(f"Update lookup failed: {exc}") from exc
    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:
        raise PremiumError("Premium server returned invalid JSON.") from exc
    if not isinstance(data, dict):
        raise PremiumError("Premium server returned an invalid payload.")
    return data


def _require_premium_asset_name(asset_name: str, version: str) -> None:
    expected_asset_name = EXPECTED_ASSET_TEMPLATE.format(version=version)
    if asset_name == expected_asset_name:
        return
    lowered = asset_name.lower()
    if lowered.endswith(".exe") and "novasentinel" in lowered and version in asset_name:
        return
    raise UpdateError(f"Premium release does not include a NovaSentinel installer for {version}.")


def _require_premium_download_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise UpdateError("Premium release download URL must use HTTPS.")
    if parsed.netloc.lower() == "github.com":
        expected_prefix = "/MonkeyTime/NovaSentinel/releases/download/"
        if parsed.path.startswith(expected_prefix):
            return
    premium_host = urlparse(UPDATE_URL).netloc.lower()
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
