from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class DetectionHit:
    category: str
    score: int
    explanation: str
    evidence: str
    source: str = "heuristic"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    path: str
    score: int
    severity: str
    malicious: bool
    engine: str
    sha256: str
    file_size: int
    scanned_at: str
    hits: list[DetectionHit] = field(default_factory=list)
    action_taken: str = "none"
    post_alert: dict[str, Any] | None = None
    attack: dict[str, Any] | None = None
    xai: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["hits"] = [hit.to_dict() for hit in self.hits]
        return payload


@dataclass
class EventRecord:
    timestamp: str
    level: str
    title: str
    description: str
    path: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AppSettings:
    realtime_enabled: bool = True
    process_guard_enabled: bool = True
    ransomware_guard_enabled: bool = True
    automatic_quarantine: bool = True
    scan_roots: list[str] = field(default_factory=list)
    scan_exclusions: list[str] = field(default_factory=list)
    max_file_size_mb: int = 64
    recent_scan_target: str = ""
    window_geometry: str = ""
    language: str = "en"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
