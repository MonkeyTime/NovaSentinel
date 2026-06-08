from __future__ import annotations

import hashlib
import json
import os
import shutil
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from novaguard.config import QUARANTINE_DIR, SYSTEM_QUARANTINE_DECISIONS_FILE


SYSTEM_DECISION_ALLOW = "allow"
SYSTEM_DECISION_DENY = "deny"


def calculate_file_sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_same_or_child(path: Path, root: Path) -> bool:
    try:
        return path.resolve().is_relative_to(root.resolve())
    except (OSError, ValueError):
        return False


def is_system_managed_path(path: str | Path) -> bool:
    target = Path(path)
    roots = [
        Path(value)
        for value in [
            os.getenv("SystemRoot", r"C:\Windows"),
            os.getenv("ProgramFiles", r"C:\Program Files"),
            os.getenv("ProgramFiles(x86)", r"C:\Program Files (x86)"),
            os.getenv("ProgramW6432", r"C:\Program Files"),
        ]
        if value
    ]
    if any(_is_same_or_child(target, root) for root in roots):
        return True
    lowered = str(target).casefold()
    markers = ("c:\\windows\\", "c:\\program files\\", "c:\\program files (x86)\\")
    return any(lowered.startswith(marker.casefold()) for marker in markers)


def _decision_key(path: str | Path) -> str:
    try:
        return str(Path(path).resolve()).casefold()
    except OSError:
        return str(Path(path)).casefold()


class QuarantineManager:
    def __init__(self) -> None:
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        SYSTEM_QUARANTINE_DECISIONS_FILE.parent.mkdir(parents=True, exist_ok=True)

    def quarantine_file(
        self,
        path: str,
        reason: str,
        score: int,
        *,
        allow_system_file: bool = False,
        sha256: str = "",
    ) -> dict | None:
        source = Path(path)
        if not source.exists() or source.is_dir():
            return None
        if is_system_managed_path(source) and not allow_system_file:
            return None
        if not sha256:
            try:
                sha256 = calculate_file_sha256(source)
            except OSError:
                sha256 = ""
        entry_id = uuid4().hex
        payload_path = QUARANTINE_DIR / f"{entry_id}.bin"
        metadata_path = QUARANTINE_DIR / f"{entry_id}.json"
        try:
            shutil.move(str(source), str(payload_path))
        except OSError:
            return None
        metadata = {
            "id": entry_id,
            "original_path": str(source),
            "payload_path": str(payload_path),
            "original_name": source.name,
            "reason": reason,
            "score": score,
            "sha256": sha256,
            "quarantined_at": datetime.now().isoformat(timespec="seconds"),
        }
        metadata_path.write_text(json.dumps(metadata, indent=2, ensure_ascii=True), encoding="utf-8")
        return metadata

    def remembered_system_decision(self, path: str, sha256: str) -> str | None:
        if not sha256:
            return None
        item = self._load_system_decisions().get(_decision_key(path))
        if not item or item.get("sha256") != sha256:
            return None
        decision = item.get("decision")
        if decision in {SYSTEM_DECISION_ALLOW, SYSTEM_DECISION_DENY}:
            return str(decision)
        return None

    def remember_system_decision(self, path: str, sha256: str, decision: str) -> None:
        if decision not in {SYSTEM_DECISION_ALLOW, SYSTEM_DECISION_DENY} or not sha256:
            return
        decisions = self._load_system_decisions()
        decisions[_decision_key(path)] = {
            "path": str(Path(path)),
            "sha256": sha256,
            "decision": decision,
            "decided_at": datetime.now().isoformat(timespec="seconds"),
        }
        self._save_system_decisions(decisions)

    def list_entries(self) -> list[dict]:
        entries: list[dict] = []
        for metadata_file in sorted(QUARANTINE_DIR.glob("*.json"), reverse=True):
            try:
                entries.append(json.loads(metadata_file.read_text(encoding="utf-8")))
            except json.JSONDecodeError:
                continue
        return entries

    def restore(self, entry_id: str) -> bool:
        metadata_path = QUARANTINE_DIR / f"{entry_id}.json"
        payload_path = QUARANTINE_DIR / f"{entry_id}.bin"
        if not metadata_path.exists() or not payload_path.exists():
            return False
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        original_path = Path(metadata["original_path"])
        original_path.parent.mkdir(parents=True, exist_ok=True)
        destination = original_path
        counter = 1
        while destination.exists():
            destination = original_path.with_name(f"{original_path.stem}_restored_{counter}{original_path.suffix}")
            counter += 1
        shutil.move(str(payload_path), str(destination))
        metadata_path.unlink(missing_ok=True)
        return True

    def delete(self, entry_id: str) -> bool:
        metadata_path = QUARANTINE_DIR / f"{entry_id}.json"
        payload_path = QUARANTINE_DIR / f"{entry_id}.bin"
        deleted = False
        if payload_path.exists():
            payload_path.unlink()
            deleted = True
        if metadata_path.exists():
            metadata_path.unlink()
            deleted = True
        return deleted

    def _load_system_decisions(self) -> dict[str, dict]:
        if not SYSTEM_QUARANTINE_DECISIONS_FILE.exists():
            return {}
        try:
            payload = json.loads(SYSTEM_QUARANTINE_DECISIONS_FILE.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
        if not isinstance(payload, dict):
            return {}
        return {str(key): value for key, value in payload.items() if isinstance(value, dict)}

    def _save_system_decisions(self, decisions: dict[str, dict]) -> None:
        temp_path = SYSTEM_QUARANTINE_DECISIONS_FILE.with_name(
            f"{SYSTEM_QUARANTINE_DECISIONS_FILE.name}.{uuid4().hex}.tmp"
        )
        try:
            temp_path.write_text(json.dumps(decisions, indent=2, ensure_ascii=True), encoding="utf-8")
            temp_path.replace(SYSTEM_QUARANTINE_DECISIONS_FILE)
        except OSError:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass
