from __future__ import annotations

import hashlib
import shutil
import time
from collections import Counter
from collections import deque
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from novaguard.config import INCIDENTS_FILE, RECOVERY_DIR, load_json_list, save_json_list
from novaguard.models import AppSettings, EventRecord


EventCallback = Callable[[EventRecord], None]
EmergencyCallback = Callable[[str, str, list[str] | None], None]

SENSITIVE_DOCUMENT_EXTENSIONS = {
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".pdf",
    ".jpg",
    ".jpeg",
    ".png",
    ".zip",
    ".7z",
    ".txt",
}

BURST_WINDOW_SECONDS = 12
BURST_THRESHOLD = 12
PANIC_COOLDOWN_SECONDS = 15
MAX_RECOVERY_FILE_SIZE = 25 * 1024 * 1024
MAX_INCIDENT_RECOVERY_FILES = 24
BEHAVIOR_MODEL_VERSION = "ransomware-behavior-score-v2"


class RansomwareGuard:
    def __init__(
        self,
        settings: AppSettings,
        on_event: EventCallback,
        emergency_callback: EmergencyCallback,
    ) -> None:
        self.settings = settings
        self.on_event = on_event
        self.emergency_callback = emergency_callback
        self.activity: deque[tuple[float, str]] = deque(maxlen=128)
        self.recovery_candidates: dict[str, dict] = {}
        self.last_panic_trigger_at = 0.0
        self.incidents: list[dict] = load_json_list(INCIDENTS_FILE)

    def record_file_activity(self, path: str) -> None:
        if not self.settings.ransomware_guard_enabled:
            return
        target = Path(path)
        if target.suffix.lower() not in SENSITIVE_DOCUMENT_EXTENSIONS:
            return
        now = time.time()
        self.activity.append((now, str(target)))
        self._capture_recovery_candidate(target)
        recent_paths = self._recent_paths(now)
        if len(recent_paths) >= BURST_THRESHOLD and now - self.last_panic_trigger_at > PANIC_COOLDOWN_SECONDS:
            self.last_panic_trigger_at = now
            incident = self._create_incident(
                reason="ransomware_burst",
                trigger_path=str(target),
                related_paths=recent_paths,
                evidence=[
                    f"{len(recent_paths)} sensitive files changed inside {BURST_WINDOW_SECONDS}s",
                    "rapid document modification burst",
                ],
                containment=True,
            )
            self.on_event(
                EventRecord(
                    timestamp=incident["timestamp"],
                    level="critical",
                    title="Ransomware-like modification burst",
                    description="NovaSentinel detected a rapid burst of document modifications and triggered containment.",
                    path=str(target),
                )
            )
            self.emergency_callback(str(target), "ransomware_burst", recent_paths)

    def record_canary_touch(self, path: str) -> None:
        if not self.settings.ransomware_guard_enabled:
            return
        incident = self._create_incident(
            reason="canary_touched",
            trigger_path=path,
            related_paths=[path],
            evidence=["ransomware canary file changed"],
            containment=True,
        )
        self.on_event(
            EventRecord(
                timestamp=incident["timestamp"],
                level="critical",
                title="Canary file touched",
                description="A ransomware canary changed and NovaSentinel triggered containment.",
                path=path,
            )
        )
        self.emergency_callback(path, "canary_touched", [path])

    def manual_panic(self) -> dict:
        incident = self._create_incident(
            reason="manual_panic",
            trigger_path="",
            related_paths=self._recent_paths(time.time()),
            evidence=["manual panic mode requested from NovaSentinel"],
            containment=True,
        )
        self.on_event(
            EventRecord(
                timestamp=incident["timestamp"],
                level="critical",
                title="Manual panic mode",
                description="NovaSentinel panic mode was manually triggered.",
            )
        )
        self.emergency_callback("", "manual_panic", [])
        return incident

    def list_incidents(self) -> list[dict]:
        self.incidents = load_json_list(INCIDENTS_FILE)
        return list(self.incidents[-120:])

    def refresh_settings(self, settings: AppSettings) -> None:
        self.settings = settings

    def _recent_paths(self, now: float) -> list[str]:
        paths: list[str] = []
        for stamp, path in self.activity:
            if now - stamp <= BURST_WINDOW_SECONDS and path not in paths:
                paths.append(path)
        return paths

    def _capture_recovery_candidate(self, path: Path) -> None:
        if str(path) in self.recovery_candidates:
            return
        if not path.exists() or path.is_dir():
            return
        try:
            size = path.stat().st_size
        except OSError:
            return
        if size > MAX_RECOVERY_FILE_SIZE:
            return
        recovery_path = self._recovery_path_for(path)
        try:
            recovery_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, recovery_path)
        except OSError:
            return
        self.recovery_candidates[str(path)] = {
            "original_path": str(path),
            "recovery_path": str(recovery_path),
            "captured_at": datetime.now().isoformat(timespec="seconds"),
            "sha256": self._sha256(recovery_path),
            "file_size": size,
        }

    def _create_incident(
        self,
        reason: str,
        trigger_path: str,
        related_paths: list[str],
        evidence: list[str],
        containment: bool,
    ) -> dict:
        incident_id = uuid4().hex
        timestamp = datetime.now().isoformat(timespec="seconds")
        recovery_files = [
            self.recovery_candidates[path]
            for path in related_paths
            if path in self.recovery_candidates
        ][:MAX_INCIDENT_RECOVERY_FILES]
        behavior = self._build_behavior_profile(reason, related_paths, recovery_files)
        evidence = list(evidence)
        evidence.append(
            f"behavior score {behavior['score']}/100 ({behavior['confidence']} confidence)"
        )
        if behavior["signals"]["directory_count"] > 1:
            evidence.append(f"{behavior['signals']['directory_count']} distinct folders touched")
        if behavior["signals"]["extension_count"] > 1:
            evidence.append(f"{behavior['signals']['extension_count']} sensitive extension families touched")
        timeline = [
            {"time": timestamp, "step": "signal", "detail": evidence[0] if evidence else reason},
            {"time": timestamp, "step": "recovery", "detail": f"{len(recovery_files)} file copy/copies available in recovery vault"},
            {"time": timestamp, "step": "scoring", "detail": f"{BEHAVIOR_MODEL_VERSION}: {behavior['score']}/100, confidence {behavior['confidence']}"},
        ]
        if containment:
            timeline.append({"time": timestamp, "step": "containment", "detail": "panic mode requested for related processes and sensitive folders"})
        incident = {
            "id": incident_id,
            "timestamp": timestamp,
            "reason": reason,
            "severity": "critical",
            "behavior_model": BEHAVIOR_MODEL_VERSION,
            "behavior_score": behavior["score"],
            "confidence": behavior["confidence"],
            "signals": behavior["signals"],
            "tags": behavior["tags"],
            "trigger_path": trigger_path,
            "related_paths": related_paths,
            "evidence": evidence,
            "recovery_files": recovery_files,
            "timeline": timeline,
            "actions": ["panic_mode_requested"] if containment else [],
            "status": "contained" if containment else "observed",
        }
        self.incidents.append(incident)
        self.incidents = self.incidents[-300:]
        save_json_list(INCIDENTS_FILE, self.incidents)
        return incident

    def _build_behavior_profile(
        self,
        reason: str,
        related_paths: list[str],
        recovery_files: list[dict],
    ) -> dict:
        paths = [Path(path) for path in related_paths if path]
        directories = {str(path.parent).lower() for path in paths}
        extensions = Counter(path.suffix.lower() or "<none>" for path in paths)
        timestamps = [
            stamp
            for stamp, activity_path in self.activity
            if activity_path in related_paths
        ]
        window_span = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0.0
        burst_rate = len(related_paths) / max(window_span, 1.0) if related_paths else 0.0
        recovery_coverage = int((len(recovery_files) / len(related_paths)) * 100) if related_paths else 0
        protected_root_hits = self._protected_root_hits(related_paths)
        signals = {
            "sensitive_file_count": len(related_paths),
            "directory_count": len(directories),
            "extension_count": len(extensions),
            "top_extensions": [extension for extension, _count in extensions.most_common(5)],
            "burst_window_seconds": BURST_WINDOW_SECONDS,
            "burst_rate_per_second": round(burst_rate, 2),
            "recovery_coverage_percent": recovery_coverage,
            "protected_root_hits": protected_root_hits,
        }
        score = self._behavior_score(reason, signals)
        return {
            "score": score,
            "confidence": self._confidence_for(reason, score),
            "signals": signals,
            "tags": self._tags_for(reason, score, signals),
        }

    def _behavior_score(self, reason: str, signals: dict) -> int:
        if reason == "canary_touched":
            return 98
        if reason == "manual_panic":
            return 45

        file_count = int(signals["sensitive_file_count"])
        directory_count = int(signals["directory_count"])
        extension_count = int(signals["extension_count"])
        burst_rate = float(signals["burst_rate_per_second"])
        recovery_coverage = int(signals["recovery_coverage_percent"])
        protected_root_hits = int(signals["protected_root_hits"])

        score = 35
        score += min(25, int((file_count / max(BURST_THRESHOLD, 1)) * 20))
        score += min(15, directory_count * 5)
        score += min(10, extension_count * 3)
        score += 15 if burst_rate >= 2 else 10 if burst_rate >= 1 else 5
        score += 5 if recovery_coverage >= 50 else 0
        score += min(10, protected_root_hits * 3)
        return max(0, min(100, score))

    def _confidence_for(self, reason: str, score: int) -> str:
        if reason == "manual_panic":
            return "operator"
        if reason == "canary_touched" or score >= 80:
            return "high"
        if score >= 60:
            return "medium"
        return "low"

    def _tags_for(self, reason: str, score: int, signals: dict) -> list[str]:
        tags = ["User-space telemetry", "Explainable containment"]
        if reason == "ransomware_burst":
            tags.extend(["MITRE T1486 impact pattern", "Modification burst"])
        elif reason == "canary_touched":
            tags.extend(["Canary integrity change", "High-confidence signal"])
        elif reason == "manual_panic":
            tags.append("Operator panic request")
        if int(signals["recovery_coverage_percent"]) > 0:
            tags.append("Recovery evidence available")
        if score >= 80:
            tags.append("High behavior score")
        return tags

    def _protected_root_hits(self, related_paths: list[str]) -> int:
        roots = [str(Path(root)).lower() for root in self.settings.scan_roots if root]
        hits = 0
        for path in related_paths:
            lowered = str(Path(path)).lower()
            if any(lowered.startswith(root) for root in roots):
                hits += 1
        return hits

    def _recovery_path_for(self, path: Path) -> Path:
        digest = hashlib.sha256(str(path).encode("utf-8", errors="ignore")).hexdigest()[:16]
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        safe_name = "".join(char if char.isalnum() or char in ".-_" else "_" for char in path.name)
        return RECOVERY_DIR / f"{timestamp}-{digest}-{safe_name}"

    def _sha256(self, path: Path) -> str:
        digest = hashlib.sha256()
        try:
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
        except OSError:
            return ""
        return digest.hexdigest()
