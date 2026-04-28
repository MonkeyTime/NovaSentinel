from __future__ import annotations

import os
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from collections.abc import Callable, Iterable
from pathlib import Path

import novaguard.config as config
from novaguard.core.heuristics import analyze_file
from novaguard.models import AppSettings, ScanResult


ProgressCallback = Callable[[str, int, int], None]
ResultCallback = Callable[[ScanResult], None]
ErrorCallback = Callable[[str, str], None]
CancelCallback = Callable[[], bool]
TEMP_RETRY_DELAYS = (0.15, 0.35, 0.75, 1.5)
MAX_SCAN_WORKERS = 8
PENDING_TASKS_PER_WORKER = 3
UNKNOWN_PROGRESS_TOTAL = 0
SKIPPED_DIR_NAMES = {"__pycache__", ".pytest_cache", ".mypy_cache"}
SKIPPED_FILE_SUFFIXES = {".pyc", ".pyo"}
RUNTIME_STATE_BASE_FILENAMES = {
    "settings.json",
    "history.json",
    "events.json",
    "incidents.json",
    "lockdown_state.json",
}


def _is_same_or_child(path: Path, root: Path) -> bool:
    try:
        return path.resolve().is_relative_to(root.resolve())
    except (OSError, ValueError):
        return False


def is_app_owned_path(path: Path) -> bool:
    return _is_same_or_child(path, config.STATE_DIR)


def _is_json_temp_name(name: str, base_name: str) -> bool:
    if name == f"{base_name}.tmp":
        return True
    if not name.startswith(f"{base_name}.") or not name.endswith(".tmp"):
        return False
    parts = name[len(base_name) + 1:-4].split(".")
    return bool(parts) and all(part.isdigit() for part in parts)


def is_runtime_state_file_name(path: Path) -> bool:
    name = path.name.casefold()
    for base_name in RUNTIME_STATE_BASE_FILENAMES:
        if name == base_name or name == f"{base_name}.bak" or _is_json_temp_name(name, base_name):
            return True
    return False


def is_runtime_state_path(path: Path) -> bool:
    return is_app_owned_path(path) and is_runtime_state_file_name(path)


def is_excluded(path: Path, exclusions: list[str], inclusions: list[str] | None = None) -> bool:
    if is_runtime_state_path(path):
        return True
    lowered = str(path).lower()
    for exclusion in exclusions:
        exclusion_lowered = exclusion.lower()
        if not lowered.startswith(exclusion_lowered):
            continue
        if inclusions:
            for inclusion in inclusions:
                inclusion_lowered = inclusion.lower()
                if inclusion_lowered.startswith(exclusion_lowered) and lowered.startswith(inclusion_lowered):
                    return False
        return True
    return False


def iter_files(target: Path, exclusions: list[str], inclusions: list[str] | None = None) -> Iterable[Path]:
    if is_runtime_state_path(target):
        return
    if target.is_file():
        if target.suffix.lower() in SKIPPED_FILE_SUFFIXES:
            return
        yield target
        return
    for root, dirs, files in os.walk(target, topdown=True, followlinks=False):
        root_path = Path(root)
        dirs[:] = [
            name for name in dirs
            if name.lower() not in SKIPPED_DIR_NAMES and not is_excluded(root_path / name, exclusions, inclusions)
        ]
        for name in files:
            path = root_path / name
            if path.suffix.lower() in SKIPPED_FILE_SUFFIXES:
                continue
            if is_excluded(path, exclusions, inclusions):
                continue
            yield path


def temp_roots() -> list[Path]:
    local_appdata = Path(os.getenv("LOCALAPPDATA", str(Path.home() / "AppData" / "Local")))
    windows_dir = Path(os.getenv("SystemRoot", r"C:\Windows"))
    candidates = [
        Path(os.getenv("TEMP", str(local_appdata / "Temp"))),
        Path(os.getenv("TMP", str(local_appdata / "Temp"))),
        local_appdata / "Temp",
        windows_dir / "Temp",
    ]
    roots: list[Path] = []
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            resolved = candidate
        if resolved.exists() and resolved not in roots:
            roots.append(resolved)
    return roots


def is_temp_path(path: Path) -> bool:
    try:
        resolved = path.resolve()
    except OSError:
        resolved = path
    return any(str(resolved).lower().startswith(str(root).lower()) for root in temp_roots())


def is_read_locked(path: Path) -> tuple[bool, str]:
    try:
        with path.open("rb") as handle:
            handle.read(1)
        return False, ""
    except OSError as exc:
        return True, str(exc)


def is_file_in_use_error(error: str) -> bool:
    lowered = error.casefold()
    markers = (
        "winerror 32",
        "sharing violation",
        "used by another process",
        "being used by another process",
        "utilise par un autre processus",
        "utilisé par un autre processus",
        "le processus ne peut pas acceder au fichier",
        "le processus ne peut pas accéder au fichier",
    )
    return any(marker in lowered for marker in markers)


def scan_file_resiliently(path: Path, max_file_size_mb: int) -> tuple[ScanResult | None, str]:
    if is_runtime_state_path(path):
        return None, ""
    last_error = ""
    attempts = 1 + (len(TEMP_RETRY_DELAYS) if is_temp_path(path) else 0)
    for attempt in range(attempts):
        try:
            result = analyze_file(path, max_file_size_mb=max_file_size_mb)
        except OSError as exc:
            result = None
            last_error = str(exc)
            if is_file_in_use_error(last_error) and not is_temp_path(path):
                return None, ""
        except Exception as exc:
            return None, f"Unexpected scan error: {exc}"
        else:
            if result is not None:
                return result, ""
            if not path.exists():
                return None, ""
            locked, error = is_read_locked(path)
            if not locked:
                return None, ""
            if is_file_in_use_error(error):
                if not is_temp_path(path) or attempt >= attempts - 1:
                    return None, ""
            last_error = error
        if attempt < attempts - 1:
            time.sleep(TEMP_RETRY_DELAYS[attempt])
    if is_file_in_use_error(last_error):
        return None, ""
    return None, last_error


def default_scan_worker_count() -> int:
    cpu_count = os.cpu_count() or 2
    return max(1, min(MAX_SCAN_WORKERS, cpu_count * 2))


def scan_worker_count(file_count: int | None = None) -> int:
    if file_count is None:
        return default_scan_worker_count()
    if file_count <= 1:
        return 1
    return max(1, min(file_count, default_scan_worker_count()))


class Scanner:
    def __init__(self, settings: AppSettings) -> None:
        self.settings = settings

    def scan_target(
        self,
        target: str,
        progress_callback: ProgressCallback | None = None,
        result_callback: ResultCallback | None = None,
        error_callback: ErrorCallback | None = None,
        cancel_callback: CancelCallback | None = None,
    ) -> list[ScanResult]:
        root = Path(target)
        if not root.exists():
            return []
        files = iter_files(root, self.settings.scan_exclusions, self.settings.scan_roots)
        return self._scan_files_streaming(files, root, progress_callback, result_callback, error_callback, cancel_callback)

    def scan_files(
        self,
        files: list[Path],
        progress_callback: ProgressCallback | None = None,
        result_callback: ResultCallback | None = None,
        error_callback: ErrorCallback | None = None,
        cancel_callback: CancelCallback | None = None,
    ) -> list[ScanResult]:
        scan_files = [path for path in files if not is_runtime_state_path(path)]
        return self._scan_files_streaming(
            scan_files,
            Path(""),
            progress_callback,
            result_callback,
            error_callback,
            cancel_callback,
            known_total=len(scan_files),
        )

    def _scan_files_streaming(
        self,
        files: Iterable[Path],
        root: Path,
        progress_callback: ProgressCallback | None,
        result_callback: ResultCallback | None,
        error_callback: ErrorCallback | None,
        cancel_callback: CancelCallback | None,
        known_total: int | None = None,
    ) -> list[ScanResult]:
        results: list[ScanResult] = []
        workers = scan_worker_count()
        completed = 0
        file_iter = iter(files)
        pending = {}
        discovery_done = known_total is not None
        discovered = 0
        max_pending = max(workers, workers * PENDING_TASKS_PER_WORKER)

        def submit_next(executor: ThreadPoolExecutor) -> bool:
            nonlocal discovered, discovery_done
            while True:
                try:
                    file_path = next(file_iter)
                except StopIteration:
                    discovery_done = True
                    return False
                except OSError as exc:
                    discovery_done = True
                    if error_callback:
                        error_callback(str(root), str(exc))
                    return False
                if not is_runtime_state_path(file_path):
                    break
            discovered += 1
            future = executor.submit(scan_file_resiliently, file_path, self.settings.max_file_size_mb)
            pending[future] = file_path
            return True

        executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="NovaSentinelScan")
        try:
            for _ in range(max_pending):
                if cancel_callback and cancel_callback():
                    break
                if not submit_next(executor):
                    break

            while pending:
                if cancel_callback and cancel_callback():
                    for future in pending:
                        future.cancel()
                    break
                done, _ = wait(pending, timeout=0.1, return_when=FIRST_COMPLETED)
                if not done:
                    continue
                for future in done:
                    file_path = pending.pop(future)
                    completed += 1
                    if progress_callback:
                        display_total = known_total or max(completed, discovered, 1) if discovery_done else UNKNOWN_PROGRESS_TOTAL
                        progress_callback(str(file_path), completed, display_total)
                    if future.cancelled():
                        continue
                    try:
                        result, error = future.result()
                    except Exception as exc:
                        result = None
                        error = f"Unexpected scan worker error: {exc}"
                    if error:
                        if error_callback:
                            error_callback(str(file_path), error)
                    elif result:
                        results.append(result)
                        if result_callback:
                            result_callback(result)
                    if not (cancel_callback and cancel_callback()):
                        while len(pending) < max_pending and submit_next(executor):
                            pass
        finally:
            executor.shutdown(wait=False, cancel_futures=True)
        return results
