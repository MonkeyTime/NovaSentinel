from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


GITHUB_RELEASE_API_URL = "https://api.github.com/repos/MonkeyTime/NovaSentinel/releases/latest"
EXPECTED_ASSET_TEMPLATE = "NovaSentinel-Setup-{version}.exe"
MAX_INSTALLER_BYTES = 250 * 1024 * 1024
REQUEST_TIMEOUT_SECONDS = 10
NO_WINDOW_FLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0)
TRUSTED_UPDATE_DOWNLOAD_HOSTS = {
    host.strip().lower()
    for host in os.getenv("NOVASENTINEL_UPDATE_TRUSTED_HOSTS", "novasentinel.app").split(",")
    if host.strip()
}


class UpdateError(RuntimeError):
    pass


@dataclass(frozen=True)
class UpdateInfo:
    version: str
    tag: str
    name: str
    asset_name: str
    download_url: str
    sha256: str
    release_url: str
    published_at: str = ""


def parse_version(version: str) -> tuple[int, ...] | None:
    cleaned = version.strip()
    if cleaned.startswith(("v", "V")):
        cleaned = cleaned[1:]
    if not re.fullmatch(r"\d+(?:\.\d+){1,3}", cleaned):
        return None
    return tuple(int(part) for part in cleaned.split("."))


def is_newer_version(candidate: str, current: str) -> bool:
    candidate_parts = parse_version(candidate)
    current_parts = parse_version(current)
    if candidate_parts is None or current_parts is None:
        return False
    size = max(len(candidate_parts), len(current_parts))
    return candidate_parts + (0,) * (size - len(candidate_parts)) > current_parts + (0,) * (size - len(current_parts))


def fetch_latest_update(current_version: str) -> UpdateInfo | None:
    request = urllib.request.Request(
        GITHUB_RELEASE_API_URL,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "NovaSentinel-Updater",
        },
    )
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        status = getattr(response, "status", 200)
        if status < 200 or status >= 300:
            raise UpdateError(f"GitHub release request failed with HTTP {status}.")
        payload = json.loads(response.read().decode("utf-8", errors="replace"))
    return update_from_release_payload(payload, current_version)


def update_from_release_payload(payload: dict[str, Any], current_version: str) -> UpdateInfo | None:
    if payload.get("draft") or payload.get("prerelease"):
        return None
    tag = str(payload.get("tag_name", "")).strip()
    latest_version = tag[1:] if tag.lower().startswith("v") else tag
    if not is_newer_version(latest_version, current_version):
        return None
    expected_asset_name = EXPECTED_ASSET_TEMPLATE.format(version=latest_version)
    asset = _find_release_asset(payload.get("assets", []), expected_asset_name)
    if asset is None:
        raise UpdateError(f"Release {tag} does not include {expected_asset_name}.")
    digest = str(asset.get("digest", "")).strip().lower()
    if not digest.startswith("sha256:"):
        raise UpdateError(f"Release asset {expected_asset_name} is missing a SHA-256 digest.")
    sha256 = digest.removeprefix("sha256:")
    if not re.fullmatch(r"[0-9a-f]{64}", sha256):
        raise UpdateError(f"Release asset {expected_asset_name} has an invalid SHA-256 digest.")
    download_url = str(asset.get("browser_download_url", ""))
    _require_github_download_url(download_url)
    return UpdateInfo(
        version=latest_version,
        tag=tag,
        name=str(payload.get("name", tag)),
        asset_name=expected_asset_name,
        download_url=download_url,
        sha256=sha256,
        release_url=str(payload.get("html_url", "")),
        published_at=str(payload.get("published_at", "")),
    )


def download_update_installer(update: UpdateInfo) -> Path:
    _require_github_download_url(update.download_url)
    target_dir = Path(tempfile.gettempdir()) / "NovaSentinel" / "updates" / update.version
    target_dir.mkdir(parents=True, exist_ok=True)
    target_path = target_dir / update.asset_name
    temp_path = target_path.with_suffix(target_path.suffix + ".download")
    request = urllib.request.Request(update.download_url, headers={"User-Agent": "NovaSentinel-Updater"})
    hasher = hashlib.sha256()
    downloaded = 0
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            status = getattr(response, "status", 200)
            if status < 200 or status >= 300:
                raise UpdateError(f"Installer download failed with HTTP {status}.")
            length = response.headers.get("Content-Length")
            if length is not None:
                try:
                    content_length = int(length)
                except ValueError as exc:
                    raise UpdateError("Installer download Content-Length header is invalid.") from exc
                if content_length > MAX_INSTALLER_BYTES:
                    raise UpdateError("Installer is larger than the allowed update size.")
            with temp_path.open("wb") as handle:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    downloaded += len(chunk)
                    if downloaded > MAX_INSTALLER_BYTES:
                        raise UpdateError("Installer download exceeded the allowed update size.")
                    hasher.update(chunk)
                    handle.write(chunk)
        digest = hasher.hexdigest()
        if digest.lower() != update.sha256.lower():
            raise UpdateError("Downloaded installer hash does not match the GitHub release digest.")
        temp_path.replace(target_path)
        return target_path
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise


def launch_update_installer(installer_path: Path) -> None:
    if not installer_path.exists():
        raise UpdateError("Downloaded installer is missing.")
    script_path = _write_update_script(installer_path)
    subprocess.Popen(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script_path),
        ],
        close_fds=True,
        cwd=str(installer_path.parent),
        creationflags=NO_WINDOW_FLAGS | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
    )


def _write_update_script(installer_path: Path) -> Path:
    process_id = os.getpid()
    install_dir = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path.cwd()
    script_dir = Path(tempfile.gettempdir()) / "NovaSentinel" / "updates"
    script_dir.mkdir(parents=True, exist_ok=True)
    script_path = script_dir / "run_update.ps1"
    script = f"""
$ErrorActionPreference = "SilentlyContinue"
$Installer = {json.dumps(str(installer_path))}
$AppPid = {process_id}
$InstallDir = {json.dumps(str(install_dir))}
$Uninstaller = Join-Path $InstallDir "uninstall_runtime.ps1"

Start-Sleep -Milliseconds 500
Get-Process -Id $AppPid -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 800

if (Test-Path -LiteralPath $Uninstaller) {{
    Start-Process -FilePath "powershell.exe" -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $Uninstaller, "-KeepData") -Wait -WindowStyle Hidden
    Start-Sleep -Milliseconds 800
}}

Start-Process -FilePath $Installer -Wait
"""
    script_path.write_text(script.strip() + "\n", encoding="utf-8")
    return script_path


def _find_release_asset(assets: Any, expected_name: str) -> dict[str, Any] | None:
    if not isinstance(assets, list):
        return None
    for asset in assets:
        if isinstance(asset, dict) and asset.get("name") == expected_name:
            return asset
    return None


def _require_github_download_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise UpdateError("Release asset download URL must use HTTPS.")
    if parsed.netloc.lower() == "github.com":
        expected_prefix = "/MonkeyTime/NovaSentinel/releases/download/"
        if parsed.path.startswith(expected_prefix):
            return
        raise UpdateError("Release asset download URL does not match the NovaSentinel repository.")
    if parsed.netloc.lower() in TRUSTED_UPDATE_DOWNLOAD_HOSTS and parsed.path.startswith("/release-downloads/"):
        return
    raise UpdateError("Release asset download URL is not an expected update host.")
