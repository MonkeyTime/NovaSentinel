from __future__ import annotations

import json
import shutil
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from novaguard.config import QUARANTINE_DIR


class QuarantineManager:
    def __init__(self) -> None:
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

    def quarantine_file(self, path: str, reason: str, score: int) -> dict | None:
        source = Path(path)
        if not source.exists() or source.is_dir():
            return None
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
            "quarantined_at": datetime.now().isoformat(timespec="seconds"),
        }
        metadata_path.write_text(json.dumps(metadata, indent=2, ensure_ascii=True), encoding="utf-8")
        return metadata

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
