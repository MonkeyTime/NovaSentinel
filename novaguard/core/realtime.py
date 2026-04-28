from __future__ import annotations

import queue
import threading
import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer
from watchdog.observers.polling import PollingObserver

from novaguard.config import CANARY_DIR
from novaguard.core.ransomware_guard import RansomwareGuard
from novaguard.core.scanner import is_excluded, is_runtime_state_path, is_temp_path, scan_file_resiliently
from novaguard.models import AppSettings, EventRecord, ScanResult


EventCallback = Callable[[EventRecord], None]
ResultCallback = Callable[[ScanResult], None]


class RealtimeProtector:
    def __init__(
        self,
        settings: AppSettings,
        on_event: EventCallback,
        on_result: ResultCallback,
        quarantine_callback: Callable[[str, str, int], dict | None],
        ransomware_guard: RansomwareGuard,
    ) -> None:
        self.settings = settings
        self.on_event = on_event
        self.on_result = on_result
        self.quarantine_callback = quarantine_callback
        self.ransomware_guard = ransomware_guard
        self.observers: list[Observer] = []
        self.queue: queue.Queue[str] = queue.Queue()
        self.stop_event = threading.Event()
        self.worker: threading.Thread | None = None
        self.last_scanned: dict[str, float] = {}
        self.retry_counts: dict[str, int] = {}

    def start(self) -> None:
        if self.observers:
            return
        self.stop_event.clear()
        handler = _RealtimeHandler(self.queue, self._register_sensitive_activity, self._should_process_path)
        standard_observer = Observer()
        temp_observer = PollingObserver(timeout=1.5)
        standard_scheduled = False
        temp_scheduled = False

        for root in self.settings.scan_roots:
            path = Path(root)
            if not path.exists():
                continue
            try:
                if is_temp_path(path):
                    temp_observer.schedule(handler, str(path), recursive=True)
                    temp_scheduled = True
                else:
                    standard_observer.schedule(handler, str(path), recursive=True)
                    standard_scheduled = True
            except OSError as exc:
                self.on_event(
                    EventRecord(
                        timestamp=datetime.now().isoformat(timespec="seconds"),
                        level="warning",
                        title="Watcher unavailable",
                        description=f"{path}: {exc}",
                        path=str(path),
                    )
                )

        if CANARY_DIR.exists():
            standard_observer.schedule(handler, str(CANARY_DIR), recursive=True)
            standard_scheduled = True

        if standard_scheduled:
            try:
                standard_observer.start()
                self.observers.append(standard_observer)
            except OSError as exc:
                self.on_event(
                    EventRecord(
                        timestamp=datetime.now().isoformat(timespec="seconds"),
                        level="warning",
                        title="Watcher unavailable",
                        description=f"Native watcher startup failed: {exc}",
                    )
                )
        if temp_scheduled:
            try:
                temp_observer.start()
                self.observers.append(temp_observer)
            except OSError as exc:
                self.on_event(
                    EventRecord(
                        timestamp=datetime.now().isoformat(timespec="seconds"),
                        level="warning",
                        title="Watcher unavailable",
                        description=f"Temp polling watcher startup failed: {exc}",
                    )
                )
        self.worker = threading.Thread(target=self._worker_loop, name="NovaSentinelRealtime", daemon=True)
        self.worker.start()

    def stop(self) -> None:
        self.stop_event.set()
        for observer in self.observers:
            observer.stop()
        for observer in self.observers:
            observer.join(timeout=5)
        self.observers = []

    def _register_sensitive_activity(self, path: str, event_kind: str = "modified") -> None:
        if not self._should_process_path(path):
            return
        self.ransomware_guard.record_file_activity(path, event_kind=event_kind)

    def _worker_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                path = self.queue.get(timeout=1.0)
            except queue.Empty:
                continue
            if not self.settings.realtime_enabled:
                continue
            if not self._should_process_path(path):
                continue
            now = time.time()
            previous = self.last_scanned.get(path, 0.0)
            if now - previous < 2.0:
                continue
            result, error = scan_file_resiliently(Path(path), max_file_size_mb=self.settings.max_file_size_mb)
            self.last_scanned[path] = now
            if error:
                self._handle_scan_error(path, error)
                continue
            if not result:
                continue
            self.retry_counts.pop(path, None)
            self.on_result(result)
            if result.malicious and self.settings.automatic_quarantine:
                metadata = self.quarantine_callback(path, "realtime_protection", result.score)
                if metadata:
                    result.action_taken = "quarantined"
                    self.on_event(
                        EventRecord(
                            timestamp=result.scanned_at,
                            level="warning",
                            title="Threat quarantined",
                            description=f"Real-time protection isolated {Path(path).name}.",
                            path=path,
                        )
                    )
            try:
                if Path(path).resolve().is_relative_to(CANARY_DIR.resolve()):
                    self.ransomware_guard.record_canary_touch(path)
            except OSError:
                pass

    def _handle_scan_error(self, path: str, error: str) -> None:
        if is_temp_path(Path(path)):
            attempts = self.retry_counts.get(path, 0) + 1
            self.retry_counts[path] = attempts
            if attempts <= 3 and not self.stop_event.is_set():
                timer = threading.Timer(2.0 * attempts, lambda: self.queue.put(path))
                timer.daemon = True
                timer.start()
                return
        self.on_event(
            EventRecord(
                timestamp=datetime.now().isoformat(timespec="seconds"),
                level="warning",
                title="Temp scan delayed",
                description=f"{Path(path).name or path}: {error}",
                path=path,
            )
        )

    def _should_process_path(self, path: str) -> bool:
        target = Path(path)
        if is_runtime_state_path(target):
            return False
        return not is_excluded(target, self.settings.scan_exclusions, self.settings.scan_roots)


class _RealtimeHandler(FileSystemEventHandler):
    def __init__(
        self,
        event_queue: queue.Queue[str],
        activity_callback: Callable[[str, str], None],
        path_filter: Callable[[str], bool],
    ) -> None:
        self.event_queue = event_queue
        self.activity_callback = activity_callback
        self.path_filter = path_filter

    def on_created(self, event: FileSystemEvent) -> None:
        self._handle(event, "created")

    def on_modified(self, event: FileSystemEvent) -> None:
        self._handle(event, "modified")

    def on_moved(self, event: FileSystemEvent) -> None:
        destination = getattr(event, "dest_path", "")
        if destination:
            self._push(destination, "moved")

    def _handle(self, event: FileSystemEvent, event_kind: str) -> None:
        self._push(event.src_path, event_kind)

    def _push(self, path: str, event_kind: str) -> None:
        if not self.path_filter(path):
            return
        target = Path(path)
        try:
            if target.is_dir():
                return
        except OSError:
            return
        self.event_queue.put(path)
        self.activity_callback(path, event_kind)
