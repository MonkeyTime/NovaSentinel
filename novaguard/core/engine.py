from __future__ import annotations

import ctypes
import string
import threading
import time
from datetime import datetime
from pathlib import Path

from novaguard.bootstrap import ensure_bootstrap
from novaguard.config import EVENTS_FILE, HISTORY_FILE, load_json_list, load_settings, save_json_list, save_settings
from novaguard.core.post_alert import collect_post_alert_context
from novaguard.core.process_guard import ProcessGuard
from novaguard.core.quarantine import QuarantineManager
from novaguard.core.ransomware_guard import RansomwareGuard
from novaguard.core.realtime import RealtimeProtector
from novaguard.core.scanner import Scanner, iter_files
from novaguard.core.telemetry import collect_telemetry_status
from novaguard.models import AppSettings, EventRecord, ScanResult


UNKNOWN_SCAN_PROGRESS_FRACTION = 0.02
DISCOVERY_THROTTLE_BATCH = 512
DISCOVERY_THROTTLE_SECONDS = 0.01


class NovaSentinelEngine:
    def __init__(self) -> None:
        ensure_bootstrap()
        self.settings: AppSettings = load_settings()
        self.scanner = Scanner(self.settings)
        self.quarantine = QuarantineManager()
        self.history: list[dict] = load_json_list(HISTORY_FILE)
        self.events: list[dict] = load_json_list(EVENTS_FILE)
        self.current_scan_threats: list[dict] = []
        self.status_lock = threading.Lock()
        self.telemetry_lock = threading.Lock()
        self.telemetry_refreshing = False
        self.telemetry_checked_at = 0.0
        self.telemetry_status: dict = {
            "collected_at": "",
            "platform": "Windows",
            "supported": True,
            "summary": "Telemetry health check pending.",
            "services": {},
        }
        self.scan_cancel_event = threading.Event()
        self.scan_session_id = 0
        self.state = {
            "scan_in_progress": False,
            "scan_cancel_requested": False,
            "scan_label": "Idle",
            "scan_progress": 0.0,
            "files_scanned": 0,
            "scan_total_files": 0,
            "threats_found": 0,
            "last_scan_summary": "No scan yet",
        }
        self.process_guard = ProcessGuard(
            settings=self.settings,
            on_event=self.record_event,
            on_result=self.record_result,
            quarantine_callback=self.quarantine.quarantine_file,
        )
        self.ransomware_guard = RansomwareGuard(
            settings=self.settings,
            on_event=self.record_event,
            emergency_callback=self.process_guard.emergency_contain,
        )
        self.realtime = RealtimeProtector(
            settings=self.settings,
            on_event=self.record_event,
            on_result=self.record_result,
            quarantine_callback=self.quarantine.quarantine_file,
            ransomware_guard=self.ransomware_guard,
        )

    def start_background_services(self) -> None:
        self.realtime.start()
        self.process_guard.start()
        self.record_event(
            EventRecord(
                timestamp=datetime.now().isoformat(timespec="seconds"),
                level="info",
                title="Protection started",
                description="Real-time protection and background monitoring are active.",
            )
        )

    def stop_background_services(self) -> None:
        self.realtime.stop()
        self.process_guard.stop()

    def refresh_runtime(self) -> None:
        self.settings = load_settings()
        self.scanner.settings = self.settings
        self.realtime.settings = self.settings
        self.process_guard.settings = self.settings
        self.ransomware_guard.refresh_settings(self.settings)

    def update_settings(self, settings: AppSettings) -> None:
        self.settings = settings
        save_settings(settings)
        self.refresh_runtime()
        self.record_event(
            EventRecord(
                timestamp=datetime.now().isoformat(timespec="seconds"),
                level="info",
                title="Settings updated",
                description="Protection settings were saved.",
            )
        )

    def update_window_geometry(self, geometry: str) -> None:
        self.settings.window_geometry = geometry
        save_settings(self.settings)

    def get_snapshot(self) -> dict:
        self._maybe_refresh_telemetry()
        with self.status_lock:
            with self.telemetry_lock:
                telemetry = dict(self.telemetry_status)
            return {
                "state": dict(self.state),
                "history": list(self.history[-80:]),
                "events": list(self.events[-120:]),
                "quarantine": self.quarantine.list_entries(),
                "settings": self.settings,
                "current_scan_threats": list(self.current_scan_threats),
                "incidents": self.ransomware_guard.list_incidents(),
                "telemetry": telemetry,
            }

    def panic_mode(self) -> None:
        self.ransomware_guard.manual_panic()

    def record_result(self, result: ScanResult) -> None:
        self._enrich_post_alert(result, "result")
        item = result.to_dict()
        self.history.append(item)
        self.history = self.history[-400:]
        save_json_list(HISTORY_FILE, self.history)

    def record_event(self, event: EventRecord) -> None:
        item = event.to_dict()
        self.events.append(item)
        self.events = self.events[-500:]
        save_json_list(EVENTS_FILE, self.events)

    def quick_scan(self) -> None:
        roots = [root for root in self.settings.scan_roots if Path(root).exists()]
        self._spawn_scan("Quick scan", roots)

    def full_scan(self) -> None:
        self._spawn_scan("Full scan", self._discover_fixed_drives())

    def custom_scan(self, target: str) -> None:
        if not target:
            return
        self.settings.recent_scan_target = target
        save_settings(self.settings)
        self._spawn_scan("Custom scan", [target])

    def cancel_scan(self) -> bool:
        with self.status_lock:
            if not self.state["scan_in_progress"]:
                return False
            if self.state["scan_cancel_requested"]:
                return True
            self.state["scan_cancel_requested"] = True
            self.state["scan_label"] = "Stopping scan..."
        self.scan_cancel_event.set()
        self.record_event(
            EventRecord(
                timestamp=datetime.now().isoformat(timespec="seconds"),
                level="info",
                title="Scan stop requested",
                description="The active scan is being stopped safely.",
            )
        )
        return True

    def quarantine_current_threat(self, path: str) -> tuple[bool, str]:
        threat = self._find_current_threat(path)
        if not threat:
            return False, "Threat not found in the current scan list."
        if threat.get("action_taken") == "quarantined":
            return True, "Threat is already in quarantine."
        if not Path(path).exists():
            self._update_current_threat_action(path, "missing")
            return False, "The file is no longer present on disk."
        metadata = self.quarantine.quarantine_file(path, "manual_review", int(threat.get("score", 0)))
        if not metadata:
            return False, "Unable to quarantine this file."
        self._update_current_threat_action(path, "quarantined")
        self._update_history_action(path, "quarantined")
        self.record_event(
            EventRecord(
                timestamp=datetime.now().isoformat(timespec="seconds"),
                level="warning",
                title="Threat quarantined",
                description=f"Manual review isolated {Path(path).name}.",
                path=path,
            )
        )
        return True, "Threat moved to quarantine."

    def ignore_current_threat(self, path: str) -> tuple[bool, str]:
        threat = self._find_current_threat(path)
        if not threat:
            return False, "Threat not found in the current scan list."
        self._update_current_threat_action(path, "ignored")
        self._update_history_action(path, "ignored")
        self.record_event(
            EventRecord(
                timestamp=datetime.now().isoformat(timespec="seconds"),
                level="info",
                title="Threat ignored",
                description=f"Manual review marked {Path(path).name} as no action.",
                path=path,
            )
        )
        return True, "Threat marked as no action."

    def _spawn_scan(self, label: str, targets: list[str]) -> None:
        with self.status_lock:
            if self.state["scan_in_progress"]:
                return
            self.scan_cancel_event.clear()
            self.state["scan_in_progress"] = True
            self.state["scan_cancel_requested"] = False
        thread = threading.Thread(target=self._run_scan, args=(label, targets), daemon=True)
        thread.start()

    def _run_scan(self, label: str, targets: list[str]) -> None:
        with self.status_lock:
            self.scan_session_id += 1
            scan_session_id = self.scan_session_id
            self.state["scan_in_progress"] = True
            self.state["scan_label"] = label
            self.state["scan_cancel_requested"] = False
            self.state["scan_progress"] = 0.0
            self.state["files_scanned"] = 0
            self.state["scan_total_files"] = 0
            self.state["threats_found"] = 0
            self.current_scan_threats = []
        session_results = 0
        scan_failed = False
        scan_cancelled = False
        failure_reason = ""
        try:
            known_total_scan_handled = False
            if label == "Quick scan" and hasattr(self.scanner, "scan_files"):
                known_total_scan_handled = True
                files = self._discover_scan_files(label, targets)
                if self.scan_cancel_event.is_set():
                    scan_cancelled = True
                else:
                    results = self.scanner.scan_files(
                        files,
                        progress_callback=self._known_total_progress_callback(label, len(files)),
                        result_callback=self._scan_result_callback,
                        error_callback=self._scan_error_callback,
                        cancel_callback=self.scan_cancel_event.is_set,
                    )
                    session_results += len(results)
                    if self.scan_cancel_event.is_set():
                        scan_cancelled = True
                    else:
                        self._quarantine_scan_results(results)
            if not known_total_scan_handled:
                self._start_background_total_counter(label, targets, scan_session_id)
                total_targets = max(len(targets), 1)
                for target_index, target in enumerate(targets, start=1):
                    if self.scan_cancel_event.is_set():
                        scan_cancelled = True
                        break
                    results = self.scanner.scan_target(
                        target,
                        progress_callback=self._progress_callback(label, target_index, total_targets),
                        result_callback=self._scan_result_callback,
                        error_callback=self._scan_error_callback,
                        cancel_callback=self.scan_cancel_event.is_set,
                    )
                    session_results += len(results)
                    if self.scan_cancel_event.is_set():
                        scan_cancelled = True
                        break
                    self._quarantine_scan_results(results)
        except Exception as exc:
            scan_failed = True
            failure_reason = str(exc)
            self.record_event(
                EventRecord(
                    timestamp=datetime.now().isoformat(timespec="seconds"),
                    level="error",
                    title=f"{label} failed",
                    description=f"Scan aborted because of an unexpected error: {exc}",
                )
            )
        finally:
            with self.status_lock:
                found = self.state["threats_found"]
                scanned = self.state["files_scanned"]
                self.state["scan_in_progress"] = False
                self.state["scan_cancel_requested"] = False
                self.state["scan_progress"] = 0.0 if scan_failed or scan_cancelled else 1.0
                if scan_failed:
                    self.state["last_scan_summary"] = f"{label} failed after {scanned} files: {failure_reason}"
                elif scan_cancelled:
                    self.state["last_scan_summary"] = f"{label} stopped: {scanned} files, {found} threats."
                else:
                    self.state["last_scan_summary"] = f"{label} completed: {scanned} files, {found} threats."
                self.state["scan_label"] = "Idle"
                self.state["files_scanned"] = 0
                self.state["scan_total_files"] = 0
                self.state["threats_found"] = 0
        if scan_cancelled:
            self.record_event(
                EventRecord(
                    timestamp=datetime.now().isoformat(timespec="seconds"),
                    level="info",
                    title=f"{label} stopped",
                    description=f"{scanned} files scanned before stop, {found} threats flagged.",
                )
            )
        elif not scan_failed:
            self.record_event(
                EventRecord(
                    timestamp=datetime.now().isoformat(timespec="seconds"),
                    level="info",
                    title=f"{label} completed",
                    description=f"{session_results} files scored, {found} threats flagged.",
                )
            )

    def _discover_scan_files(self, label: str, targets: list[str]) -> list[Path]:
        files: list[Path] = []
        with self.status_lock:
            self.state["scan_label"] = f"{label}: discovering files"
            self.state["scan_progress"] = UNKNOWN_SCAN_PROGRESS_FRACTION
        for target in targets:
            if self.scan_cancel_event.is_set():
                break
            root = Path(target)
            if not root.exists():
                continue
            try:
                for path in iter_files(root, self.settings.scan_exclusions, self.settings.scan_roots):
                    if self.scan_cancel_event.is_set():
                        break
                    files.append(path)
            except OSError as exc:
                self._scan_error_callback(str(root), str(exc))
        return files

    def _start_background_total_counter(self, label: str, targets: list[str], scan_session_id: int) -> None:
        thread = threading.Thread(
            target=self._count_scan_files_worker,
            args=(label, list(targets), scan_session_id),
            name=f"NovaSentinel{label.replace(' ', '')}Counter",
            daemon=True,
        )
        thread.start()

    def _count_scan_files_worker(self, label: str, targets: list[str], scan_session_id: int) -> None:
        total = 0
        try:
            for target in targets:
                if self.scan_cancel_event.is_set() or not self._is_active_scan_session(scan_session_id):
                    return
                root = Path(target)
                if not root.exists():
                    continue
                try:
                    for _path in iter_files(root, self.settings.scan_exclusions, self.settings.scan_roots):
                        if self.scan_cancel_event.is_set():
                            return
                        total += 1
                        if total % DISCOVERY_THROTTLE_BATCH == 0:
                            if not self._is_active_scan_session(scan_session_id):
                                return
                            time.sleep(DISCOVERY_THROTTLE_SECONDS)
                except OSError as exc:
                    self._scan_error_callback(str(root), str(exc))
        finally:
            with self.status_lock:
                if self.state["scan_in_progress"] and self.scan_session_id == scan_session_id:
                    self.state["scan_total_files"] = total
                    scanned = self.state["files_scanned"]
                    if total > 0:
                        self.state["scan_progress"] = min(scanned / total, 0.99)

    def _is_active_scan_session(self, scan_session_id: int) -> bool:
        with self.status_lock:
            return self.state["scan_in_progress"] and self.scan_session_id == scan_session_id

    def _quarantine_scan_results(self, results: list[ScanResult]) -> None:
        for result in results:
            if result.malicious and self.settings.automatic_quarantine and Path(result.path).exists():
                metadata = self.quarantine.quarantine_file(result.path, "manual_scan", result.score)
                if metadata:
                    result.action_taken = "quarantined"
                    self._update_current_threat_action(result.path, "quarantined")
                    self._update_history_action(result.path, "quarantined")
                    self.record_event(
                        EventRecord(
                            timestamp=result.scanned_at,
                            level="warning",
                            title="Threat quarantined",
                            description=f"Manual scan isolated {Path(result.path).name}.",
                            path=result.path,
                        )
                    )

    def _known_total_progress_callback(self, label: str, total_files: int):
        def _callback(current_path: str, file_index: int, _total_files: int) -> None:
            portion = file_index / max(total_files, 1)
            with self.status_lock:
                self.state["scan_label"] = f"{label}: {Path(current_path).name}"
                self.state["scan_progress"] = portion
                self.state["files_scanned"] += 1
                self.state["scan_total_files"] = total_files

        return _callback

    def _progress_callback(self, label: str, target_index: int, total_targets: int):
        def _callback(current_path: str, file_index: int, total_files: int) -> None:
            with self.status_lock:
                scanned = self.state["files_scanned"] + 1
                known_total = self.state.get("scan_total_files", 0)
                if known_total > 0:
                    portion = min(scanned / max(known_total, 1), 0.99)
                else:
                    if total_files <= 0:
                        target_progress = UNKNOWN_SCAN_PROGRESS_FRACTION
                    else:
                        target_progress = file_index / max(total_files, 1)
                    portion = (target_index - 1 + target_progress) / max(total_targets, 1)
                self.state["scan_label"] = f"{label}: {Path(current_path).name}"
                self.state["scan_progress"] = portion
                self.state["files_scanned"] = scanned

        return _callback

    def _scan_error_callback(self, path: str, error: str) -> None:
        self.record_event(
            EventRecord(
                timestamp=datetime.now().isoformat(timespec="seconds"),
                level="warning",
                title="Scan skipped item",
                description=f"{Path(path).name or path}: {error}",
                path=path,
            )
        )

    def _scan_result_callback(self, result: ScanResult) -> None:
        self.record_result(result)
        if result.malicious:
            with self.status_lock:
                self.state["threats_found"] += 1
            self._track_current_scan_threat(result)

    def _enrich_post_alert(self, result: ScanResult, reason: str) -> None:
        if result.post_alert is not None:
            return
        if not result.malicious and result.score < 72:
            return
        result.post_alert = collect_post_alert_context(result.path, result.score, reason)

    def _track_current_scan_threat(self, result: ScanResult) -> None:
        item = result.to_dict()
        item["threat_label"] = self._threat_label_for_result(result)
        with self.status_lock:
            for index, existing in enumerate(self.current_scan_threats):
                if existing["path"] == item["path"]:
                    action_taken = existing.get("action_taken", item.get("action_taken", "none"))
                    item["action_taken"] = action_taken
                    self.current_scan_threats[index] = item
                    break
            else:
                self.current_scan_threats.append(item)

    def _find_current_threat(self, path: str) -> dict | None:
        with self.status_lock:
            for threat in self.current_scan_threats:
                if threat["path"] == path:
                    return dict(threat)
        return None

    def _update_current_threat_action(self, path: str, action: str) -> None:
        with self.status_lock:
            for threat in self.current_scan_threats:
                if threat["path"] == path:
                    threat["action_taken"] = action
                    return

    def _update_history_action(self, path: str, action: str) -> None:
        changed = False
        for item in reversed(self.history):
            if item.get("path") == path:
                item["action_taken"] = action
                changed = True
                break
        if changed:
            save_json_list(HISTORY_FILE, self.history)

    def _threat_label_for_result(self, result: ScanResult) -> str:
        if result.malicious:
            return "Confirmed threat"
        if result.severity == "critical":
            return "Critical anomaly"
        if result.severity == "high":
            return "High-risk anomaly"
        return "Suspicious file"

    def _discover_fixed_drives(self) -> list[str]:
        drives: list[str] = []
        if hasattr(ctypes, "windll"):
            buffer = ctypes.create_unicode_buffer(256)
            ctypes.windll.kernel32.GetLogicalDriveStringsW(ctypes.sizeof(buffer), buffer)
            for drive in buffer.value.split("\x00"):
                if not drive:
                    continue
                drive_type = ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(drive))
                if drive_type == 3:
                    drives.append(drive)
        if not drives:
            for letter in string.ascii_uppercase:
                candidate = Path(f"{letter}:\\")
                if candidate.exists():
                    drives.append(str(candidate))
        return drives[:4]

    def _maybe_refresh_telemetry(self) -> None:
        now = time.time()
        with self.telemetry_lock:
            if self.telemetry_refreshing or now - self.telemetry_checked_at < 300:
                return
            self.telemetry_refreshing = True
        thread = threading.Thread(target=self._refresh_telemetry_worker, name="NovaSentinelTelemetryHealth", daemon=True)
        thread.start()

    def _refresh_telemetry_worker(self) -> None:
        try:
            status = collect_telemetry_status()
        except Exception as exc:
            status = {
                "collected_at": datetime.now().isoformat(timespec="seconds"),
                "platform": "Windows",
                "supported": False,
                "summary": f"Telemetry health check failed: {exc}",
                "services": {},
            }
        with self.telemetry_lock:
            self.telemetry_status = status
            self.telemetry_checked_at = time.time()
            self.telemetry_refreshing = False
