from __future__ import annotations

import threading
import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

import psutil

from novaguard.config import STATE_DIR
from novaguard.core.lockdown import FREEZE_DURATION_SECONDS, FolderLockdownManager
from novaguard.core.scanner import is_temp_path
from novaguard.core.heuristics import analyze_file, classify_severity
from novaguard.models import AppSettings, DetectionHit, EventRecord, ScanResult


EventCallback = Callable[[EventRecord], None]
ResultCallback = Callable[[ScanResult], None]

CMDLINE_MARKERS = {
    "powershell": 12,
    "-enc": 26,
    "frombase64string": 18,
    "downloadstring": 18,
    "invoke-expression": 18,
    "vssadmin": 24,
    "bcdedit": 16,
    "regsvr32": 14,
    "rundll32": 12,
    "mshta": 18,
    "certutil": 16,
}

WSL_PROCESS_NAMES = {
    "wsl.exe",
    "wslhost.exe",
    "bash.exe",
    "ubuntu.exe",
    "debian.exe",
    "kali.exe",
    "opensuse.exe",
}

WSL_WINDOWS_MOUNT_MARKERS = {
    "/mnt/c/": 32,
    "/mnt/c/users/": 36,
    "\\users\\": 12,
    "\\documents": 12,
    "\\desktop": 12,
    "\\downloads": 12,
}

WSL_ENCRYPTOR_MARKERS = {
    "openssl enc": 24,
    "gpg -c": 20,
    "age -e": 22,
    "cryptsetup": 24,
    "find /mnt/c": 18,
    " -exec ": 14,
    "rm -rf /mnt/c": 28,
    "shred ": 20,
}


class ProcessGuard:
    def __init__(
        self,
        settings: AppSettings,
        on_event: EventCallback,
        on_result: ResultCallback,
        quarantine_callback: Callable[[str, str, int], dict | None],
        lockdown_manager: FolderLockdownManager | None = None,
    ) -> None:
        self.settings = settings
        self.on_event = on_event
        self.on_result = on_result
        self.quarantine_callback = quarantine_callback
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.seen_pids: set[int] = set()
        self.suspicious_processes: dict[int, dict] = {}
        self.panic_mode_until = 0.0
        self.lockdown = lockdown_manager or FolderLockdownManager(on_event)

    def start(self) -> None:
        if self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._run, name="NovaSentinelProcessGuard", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        self.lockdown.release()

    def emergency_contain(self, trigger_path: str = "", reason: str = "panic mode", related_paths: list[str] | None = None) -> None:
        if not self.settings.ransomware_guard_enabled:
            return
        self.panic_mode_until = time.time() + FREEZE_DURATION_SECONDS
        frozen_roots = self.lockdown.freeze(self._sensitive_roots())
        if frozen_roots:
            self.on_event(
                EventRecord(
                    timestamp=datetime.now().isoformat(timespec="seconds"),
                    level="critical",
                    title="Sensitive folders frozen",
                    description=f"NovaSentinel temporarily locked {len(frozen_roots)} folder(s) against writes during the ransomware incident window.",
                    path=trigger_path,
                )
            )
        targets = [] if reason == "manual_panic" else self._collect_related_processes(trigger_path, related_paths or [])
        reviewed = len(targets)
        terminated = 0
        for process, details in targets:
            if self._should_stop_during_containment(details) and self._terminate_and_quarantine(process, details, reason):
                terminated += 1
        if reason == "manual_panic":
            description = (
                "NovaSentinel entered manual panic mode and temporarily locked protected folders. "
                "Running apps were left alone; new high-risk launches are watched during the incident window."
            )
        else:
            description = (
                f"NovaSentinel entered panic mode, reviewed {reviewed} related process(es) "
                f"and terminated {terminated} high-risk process(es)."
            )
        self.on_event(
            EventRecord(
                timestamp=datetime.now().isoformat(timespec="seconds"),
                level="critical",
                title="Panic mode activated",
                description=description,
                path=trigger_path,
            )
        )

    def _run(self) -> None:
        while not self.stop_event.is_set():
            if not self.settings.process_guard_enabled:
                time.sleep(2.0)
                continue
            for process in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
                pid = process.info.get("pid")
                if not pid or pid in self.seen_pids:
                    continue
                self.seen_pids.add(pid)
                exe = process.info.get("exe") or ""
                cmdline = " ".join(process.info.get("cmdline") or [])
                risk = 0
                evidence: list[str] = []
                lowered = cmdline.lower()
                for token, score in CMDLINE_MARKERS.items():
                    if token in lowered:
                        risk += score
                        evidence.append(token)
                wsl_risk, wsl_evidence = self._wsl_behavior_risk(process.info.get("name") or "", exe, cmdline)
                risk += wsl_risk
                evidence.extend(wsl_evidence)
                if not exe or not Path(exe).exists():
                    continue
                result = analyze_file(exe, max_file_size_mb=self.settings.max_file_size_mb)
                if not result:
                    continue
                result.score = min(100, result.score + risk)
                result.severity, result.malicious = classify_severity(result.score)
                if evidence:
                    result.hits.append(
                        DetectionHit(
                            category="command-line",
                            score=min(risk, 30),
                            explanation="The process command line contains markers linked to obfuscation, staging or shadow-copy tampering.",
                            evidence=", ".join(evidence),
                            source="behavior",
                        )
                    )
                if wsl_evidence:
                    result.hits.append(
                        DetectionHit(
                            category="wsl-abuse",
                            score=min(wsl_risk, 40),
                            explanation="WSL/Linux tooling is accessing Windows user data with command patterns commonly seen in cross-platform ransomware staging.",
                            evidence=", ".join(wsl_evidence),
                            source="behavior",
                        )
                    )
                self.on_result(result)
                if result.score >= 48 or evidence:
                    self._remember_process(process, result.score, evidence)
                if result.score >= 72:
                    self.on_event(
                        EventRecord(
                            timestamp=result.scanned_at,
                            level="warning",
                            title="Suspicious process launch",
                            description=f"{process.info.get('name') or 'process'} scored {result.score}/100.",
                            path=exe,
                        )
                    )
                if self._panic_mode_active() and self._should_block_in_panic(exe, result.score, risk):
                    if self._terminate_and_quarantine(process, self.suspicious_processes.get(pid, {}), "panic_mode"):
                        self.on_event(
                            EventRecord(
                                timestamp=result.scanned_at,
                                level="critical",
                                title="Panic mode blocked risky execution",
                                description=f"{process.info.get('name') or 'process'} was terminated during the ransomware incident window.",
                                path=exe,
                            )
                        )
                if result.score >= 92 and self.settings.automatic_quarantine and self._should_auto_quarantine_process(exe):
                    try:
                        process.terminate()
                    except (psutil.Error, OSError):
                        pass
                    self.quarantine_callback(exe, "process_guard", result.score)
            time.sleep(3.0)

    def _panic_mode_active(self) -> bool:
        return time.time() <= self.panic_mode_until

    def _remember_process(self, process: psutil.Process, score: int, evidence: list[str]) -> None:
        pid = process.info.get("pid")
        if not pid:
            return
        exe = process.info.get("exe") or ""
        cmdline = " ".join(process.info.get("cmdline") or [])
        self.suspicious_processes[pid] = {
            "pid": pid,
            "exe": exe,
            "score": score,
            "cmdline": cmdline,
            "evidence": list(evidence),
            "seen_at": time.time(),
        }

    def _collect_related_processes(self, trigger_path: str, related_paths: list[str]) -> list[tuple[psutil.Process, dict]]:
        paths = [Path(path) for path in [trigger_path, *related_paths] if path]
        targets: dict[int, tuple[psutil.Process, dict]] = {}
        for process in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
            pid = process.info.get("pid")
            if not pid:
                continue
            details = self.suspicious_processes.get(pid)
            if not details:
                details = self._quick_process_details(process)
            if not details:
                continue
            related = details.get("score", 0) >= 48
            if paths:
                related = related and self._process_touches_paths(process, paths)
            if related or details.get("score", 0) >= 72:
                targets[pid] = (process, details)
        return sorted(targets.values(), key=lambda item: item[1].get("score", 0), reverse=True)

    def _quick_process_details(self, process: psutil.Process) -> dict | None:
        pid = process.info.get("pid")
        exe = process.info.get("exe") or ""
        if not pid or not exe:
            return None
        cmdline = " ".join(process.info.get("cmdline") or [])
        lowered = cmdline.lower()
        risk = sum(score for token, score in CMDLINE_MARKERS.items() if token in lowered)
        wsl_risk, wsl_evidence = self._wsl_behavior_risk(process.info.get("name") or "", exe, cmdline)
        risk += wsl_risk
        if self._is_user_writable_risk_path(Path(exe)):
            risk += 18
        if risk < 24:
            return None
        evidence = [token for token in CMDLINE_MARKERS if token in lowered]
        evidence.extend(wsl_evidence)
        details = {
            "pid": pid,
            "exe": exe,
            "score": min(risk, 100),
            "cmdline": cmdline,
            "evidence": evidence,
            "seen_at": time.time(),
        }
        self.suspicious_processes[pid] = details
        return details

    def _process_touches_paths(self, process: psutil.Process, paths: list[Path]) -> bool:
        try:
            open_files = process.open_files()
        except (psutil.Error, OSError):
            open_files = []
        for opened in open_files:
            opened_path = Path(opened.path)
            if any(self._is_same_or_child(opened_path, candidate.parent if candidate.is_file() else candidate) for candidate in paths):
                return True
        cmdline = " ".join(process.info.get("cmdline") or []).lower()
        exe = (process.info.get("exe") or "").lower()
        for candidate in paths:
            marker = str(candidate.parent if candidate.is_file() else candidate).lower()
            if marker and (marker in cmdline or marker in exe):
                return True
        return False

    def _terminate_and_quarantine(self, process: psutil.Process, details: dict, reason: str) -> bool:
        pid = process.info.get("pid")
        exe = (details.get("exe") or process.info.get("exe") or "").strip()
        terminated = False
        try:
            process.terminate()
            terminated = True
            process.wait(timeout=2)
        except (psutil.Error, OSError):
            pass
        if pid:
            self.suspicious_processes.pop(pid, None)
        if exe and Path(exe).exists() and self.settings.automatic_quarantine and self._should_auto_quarantine_process(exe):
            self.quarantine_callback(exe, reason, int(details.get("score", 0)))
        return terminated

    def _should_block_in_panic(self, exe: str, score: int, cmdline_risk: int) -> bool:
        target = Path(exe)
        if score >= 72 or cmdline_risk >= 18:
            return True
        if score >= 48 and self._is_user_writable_risk_path(target):
            return True
        return False

    def _should_stop_during_containment(self, details: dict) -> bool:
        try:
            score = int(details.get("score", 0))
        except (TypeError, ValueError):
            score = 0
        evidence = [str(item).lower() for item in details.get("evidence", [])]
        if score >= 92:
            return True
        if score >= 72 and evidence:
            return True
        return False

    def _wsl_behavior_risk(self, process_name: str, exe: str, cmdline: str) -> tuple[int, list[str]]:
        lowered_name = process_name.lower()
        lowered_exe = exe.lower()
        lowered_cmdline = cmdline.lower().replace("\\", "/")
        is_wsl = (
            lowered_name in WSL_PROCESS_NAMES
            or any(f"/{name}" in lowered_exe.replace("\\", "/") for name in WSL_PROCESS_NAMES)
            or "wsl.exe" in lowered_cmdline
        )
        if not is_wsl:
            return 0, []

        risk = 0
        evidence: list[str] = []
        for marker, score in WSL_WINDOWS_MOUNT_MARKERS.items():
            normalized_marker = marker.lower().replace("\\", "/")
            if normalized_marker in lowered_cmdline:
                risk += score
                evidence.append(f"wsl-windows-mount:{marker}")
        for marker, score in WSL_ENCRYPTOR_MARKERS.items():
            if marker in lowered_cmdline:
                risk += score
                evidence.append(f"wsl-linux-encryptor:{marker}")
        if evidence and any("/documents" in item or "/desktop" in item or "/downloads" in item or "/mnt/c/users/" in item for item in evidence):
            risk += 8
        return min(risk, 80), evidence

    def _should_auto_quarantine_process(self, exe: str) -> bool:
        target = Path(exe)
        if self._is_system_managed_path(target):
            return False
        return True

    def _is_system_managed_path(self, target: Path) -> bool:
        lowered = str(target).lower()
        system_markers = [
            "c:\\windows\\",
            "c:\\program files\\",
            "c:\\program files (x86)\\",
        ]
        return any(marker in lowered for marker in system_markers)

    def _is_user_writable_risk_path(self, target: Path) -> bool:
        lowered = str(target).lower()
        markers = [r"\downloads", r"\desktop", r"\appdata\local\temp", r"\startup", r"\public\\"]
        if any(marker in lowered for marker in markers):
            return True
        return is_temp_path(target)

    def _sensitive_roots(self) -> list[str]:
        home = Path.home()
        allowed: list[str] = []
        for root in self.settings.scan_roots:
            path = Path(root)
            if not path.exists():
                continue
            try:
                resolved = path.resolve()
            except OSError:
                resolved = path
            lowered = str(resolved).lower()
            if str(STATE_DIR).lower() in lowered or "\\appdata\\" in lowered or is_temp_path(resolved):
                continue
            if self._is_same_or_child(resolved, home):
                allowed.append(str(resolved))
        return allowed

    def _is_same_or_child(self, path: Path, root: Path) -> bool:
        try:
            return path.resolve().is_relative_to(root.resolve())
        except OSError:
            return False
