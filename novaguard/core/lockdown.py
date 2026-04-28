from __future__ import annotations

import getpass
import json
import subprocess
import threading
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from novaguard.config import LOCKDOWN_STATE_FILE, ensure_runtime_dirs
from novaguard.models import EventRecord


EventCallback = Callable[[EventRecord], None]
FREEZE_DURATION_SECONDS = 90
DENY_RULE = "(OI)(CI)(WD,AD,WEA,WA,DC)"
NO_WINDOW_FLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class FolderLockdownManager:
    def __init__(self, on_event: EventCallback) -> None:
        self.on_event = on_event
        self.lock = threading.Lock()
        self.release_timer: threading.Timer | None = None
        self.active_roots: set[str] = set()
        self.username = getpass.getuser()
        self._recover_stale_lockdown()

    def freeze(self, roots: list[str], duration_seconds: int = FREEZE_DURATION_SECONDS) -> list[str]:
        ensure_runtime_dirs()
        frozen: list[str] = []
        normalized = [str(Path(root)) for root in roots if Path(root).exists()]
        with self.lock:
            for root in normalized:
                if root in self.active_roots:
                    frozen.append(root)
                    continue
                if self._apply_deny(Path(root)):
                    self.active_roots.add(root)
                    frozen.append(root)
            self._persist_state()
            self._schedule_release(duration_seconds)
        return frozen

    def release(self) -> list[str]:
        released: list[str] = []
        with self.lock:
            if self.release_timer:
                self.release_timer.cancel()
                self.release_timer = None
            for root in list(self.active_roots):
                if self._remove_deny(Path(root)):
                    released.append(root)
            self.active_roots.clear()
            self._clear_state()
        if released:
            self.on_event(
                EventRecord(
                    timestamp=datetime.now().isoformat(timespec="seconds"),
                    level="info",
                    title="Folder freeze released",
                    description=f"NovaSentinel restored write access to {len(released)} sensitive folder(s).",
                )
            )
        return released

    def _schedule_release(self, duration_seconds: int) -> None:
        if self.release_timer:
            self.release_timer.cancel()
        self.release_timer = threading.Timer(duration_seconds, self.release)
        self.release_timer.daemon = True
        self.release_timer.start()

    def _persist_state(self) -> None:
        ensure_runtime_dirs()
        payload = {
            "username": self.username,
            "roots": sorted(self.active_roots),
            "saved_at": datetime.now().isoformat(timespec="seconds"),
        }
        LOCKDOWN_STATE_FILE.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")

    def _clear_state(self) -> None:
        LOCKDOWN_STATE_FILE.unlink(missing_ok=True)

    def _recover_stale_lockdown(self) -> None:
        ensure_runtime_dirs()
        if not LOCKDOWN_STATE_FILE.exists():
            return
        try:
            payload = json.loads(LOCKDOWN_STATE_FILE.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            LOCKDOWN_STATE_FILE.unlink(missing_ok=True)
            return
        username = payload.get("username") or self.username
        roots = [Path(item) for item in payload.get("roots", [])]
        for root in roots:
            self._remove_deny(root, username=username)
        LOCKDOWN_STATE_FILE.unlink(missing_ok=True)
        if roots:
            self.on_event(
                EventRecord(
                    timestamp=datetime.now().isoformat(timespec="seconds"),
                    level="info",
                    title="Recovered stale folder freeze",
                    description=f"NovaSentinel removed lingering write locks from {len(roots)} folder(s) after restart.",
                )
            )

    def _apply_deny(self, root: Path) -> bool:
        try:
            result = subprocess.run(
                ["icacls", str(root), "/deny", f"{self.username}:{DENY_RULE}"],
                capture_output=True,
                text=True,
                check=False,
                timeout=20,
                creationflags=NO_WINDOW_FLAGS,
            )
        except OSError as exc:
            self._emit_lockdown_warning(root, f"unable to freeze folder: {exc}")
            return False
        if result.returncode != 0:
            self._emit_lockdown_warning(root, result.stderr.strip() or result.stdout.strip() or "icacls failed")
            return False
        return True

    def _remove_deny(self, root: Path, username: str | None = None) -> bool:
        if not root.exists():
            return True
        try:
            result = subprocess.run(
                ["icacls", str(root), "/remove:d", username or self.username],
                capture_output=True,
                text=True,
                check=False,
                timeout=20,
                creationflags=NO_WINDOW_FLAGS,
            )
        except OSError as exc:
            self._emit_lockdown_warning(root, f"unable to release folder freeze: {exc}")
            return False
        if result.returncode != 0:
            self._emit_lockdown_warning(root, result.stderr.strip() or result.stdout.strip() or "icacls release failed")
            return False
        return True

    def _emit_lockdown_warning(self, root: Path, details: str) -> None:
        self.on_event(
            EventRecord(
                timestamp=datetime.now().isoformat(timespec="seconds"),
                level="warning",
                title="Folder freeze warning",
                description=f"{root}: {details}",
                path=str(root),
            )
        )
