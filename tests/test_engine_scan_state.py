from __future__ import annotations

import threading
from datetime import datetime
from pathlib import Path

import novaguard.core.engine as engine_module
from novaguard.core.engine import UNKNOWN_SCAN_PROGRESS_FRACTION
from novaguard.core.engine import NovaSentinelEngine
import novaguard.core.quarantine as quarantine_module
from novaguard.core.quarantine import QuarantineManager, calculate_file_sha256
from novaguard.models import AppSettings, DetectionHit, ScanResult


def _engine_without_services() -> NovaSentinelEngine:
    engine = NovaSentinelEngine.__new__(NovaSentinelEngine)
    engine.history = []
    engine.events = []
    engine.current_scan_threats = []
    engine.status_lock = threading.Lock()
    engine.scan_cancel_event = threading.Event()
    engine.scan_session_id = 0
    engine.state = {
        "scan_in_progress": False,
        "scan_cancel_requested": False,
        "scan_label": "Idle",
        "scan_progress": 0.0,
        "files_scanned": 0,
        "scan_total_files": 0,
        "threats_found": 0,
        "last_scan_summary": "No scan yet",
    }
    engine.settings = AppSettings(automatic_quarantine=False)
    return engine


def _malicious_result(path: str = r"C:\Temp\dropper.ps1") -> ScanResult:
    return ScanResult(
        path=path,
        score=95,
        severity="critical",
        malicious=True,
        engine="heuristic",
        sha256="abc",
        file_size=12,
        scanned_at=datetime.now().isoformat(timespec="seconds"),
        hits=[DetectionHit("script", 95, "suspicious script", "powershell")],
    )


def test_realtime_result_does_not_pollute_scan_center_counter(monkeypatch):
    monkeypatch.setattr(engine_module, "save_json_list", lambda path, items: None)
    monkeypatch.setattr(engine_module, "collect_post_alert_context", lambda path, score, reason: {"matched_process_count": 0})
    engine = _engine_without_services()

    engine.record_result(_malicious_result())

    assert engine.state["threats_found"] == 0
    assert engine.state["files_scanned"] == 0
    assert len(engine.history) == 1
    assert engine.history[0]["post_alert"] == {"matched_process_count": 0}


def test_finished_scan_resets_dynamic_counters_but_keeps_summary(monkeypatch):
    monkeypatch.setattr(engine_module, "save_json_list", lambda path, items: None)
    monkeypatch.setattr(engine_module, "collect_post_alert_context", lambda path, score, reason: {"matched_process_count": 1})
    engine = _engine_without_services()
    result = _malicious_result(r"C:\Temp\scan-threat.ps1")

    class FakeScanner:
        def scan_target(self, target, progress_callback, result_callback, error_callback, cancel_callback=None):
            progress_callback(result.path, 1, 1)
            result_callback(result)
            return [result]

    engine.scanner = FakeScanner()

    engine._run_scan("Quick scan", [r"C:\Temp"])

    assert engine.state["scan_in_progress"] is False
    assert engine.state["files_scanned"] == 0
    assert engine.state["threats_found"] == 0
    assert engine.state["last_scan_summary"] == "Quick scan completed: 1 files, 1 threats."
    assert len(engine.current_scan_threats) == 1
    assert engine.current_scan_threats[0]["post_alert"] == {"matched_process_count": 1}


def test_scan_can_be_stopped_safely(monkeypatch):
    monkeypatch.setattr(engine_module, "save_json_list", lambda path, items: None)
    engine = _engine_without_services()

    class FakeScanner:
        def scan_target(self, target, progress_callback, result_callback, error_callback, cancel_callback=None):
            progress_callback(r"C:\Temp\first.txt", 1, 3)
            assert engine.cancel_scan() is True
            assert cancel_callback and cancel_callback() is True
            return []

    engine.scanner = FakeScanner()

    engine._run_scan("Quick scan", [r"C:\Temp"])

    assert engine.state["scan_in_progress"] is False
    assert engine.state["scan_cancel_requested"] is False
    assert engine.state["files_scanned"] == 0
    assert engine.state["threats_found"] == 0
    assert engine.state["scan_progress"] == 0.0
    assert engine.state["last_scan_summary"] == "Quick scan stopped: 1 files, 0 threats."
    assert any(event["title"] == "Quick scan stopped" for event in engine.events)


def test_unknown_total_progress_shows_small_fixed_indicator():
    engine = _engine_without_services()
    callback = engine._progress_callback("Full scan", 1, 1)

    callback(r"C:\Temp\discovering.txt", 500, 0)

    assert engine.state["scan_progress"] == UNKNOWN_SCAN_PROGRESS_FRACTION
    assert engine.state["files_scanned"] == 1


def test_background_total_counter_updates_streaming_scan_progress(monkeypatch, tmp_path):
    monkeypatch.setattr(engine_module, "save_json_list", lambda path, items: None)
    monkeypatch.setattr(engine_module.time, "sleep", lambda _seconds: None)
    engine = _engine_without_services()
    root = tmp_path / "full"
    root.mkdir()
    files = [root / f"sample-{index}.txt" for index in range(5)]
    for path in files:
        path.write_text("hello", encoding="utf-8")

    with engine.status_lock:
        engine.state["scan_in_progress"] = True
        engine.state["files_scanned"] = 2
        engine.scan_session_id = 1

    engine._count_scan_files_worker("Full scan", [str(root)], 1)

    assert engine.state["scan_total_files"] == 5
    assert engine.state["scan_progress"] == 2 / 5

    callback = engine._progress_callback("Full scan", 1, 1)
    callback(str(files[2]), 3, 0)

    assert engine.state["files_scanned"] == 3
    assert engine.state["scan_progress"] == 3 / 5


def test_quick_scan_uses_global_known_file_total(monkeypatch, tmp_path):
    monkeypatch.setattr(engine_module, "save_json_list", lambda path, items: None)
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    files = [
        first_root / "one.txt",
        first_root / "two.txt",
        second_root / "three.txt",
    ]
    for path in files:
        path.write_text("hello", encoding="utf-8")
    pre_scan_progress: list[float] = []
    scan_progress: list[float] = []

    def fake_iter_files(root: Path, exclusions, inclusions=None):
        if root == first_root:
            yield files[0]
            yield files[1]
        elif root == second_root:
            yield files[2]

    monkeypatch.setattr(engine_module, "iter_files", fake_iter_files)

    engine = _engine_without_services()

    class FakeScanner:
        def scan_files(self, discovered_files, progress_callback, result_callback, error_callback, cancel_callback=None):
            pre_scan_progress.append(engine.state["scan_progress"])
            assert discovered_files == files
            progress_callback(str(discovered_files[0]), 1, len(discovered_files))
            scan_progress.append(engine.state["scan_progress"])
            progress_callback(str(discovered_files[-1]), 3, len(discovered_files))
            scan_progress.append(engine.state["scan_progress"])
            return []

    engine.scanner = FakeScanner()
    engine._run_scan("Quick scan", [str(first_root), str(second_root)])

    assert pre_scan_progress == [UNKNOWN_SCAN_PROGRESS_FRACTION]
    assert scan_progress == [1 / 3, 1.0]
    assert engine.state["last_scan_summary"] == "Quick scan completed: 2 files, 0 threats."


def test_full_scan_starts_streaming_without_full_discovery(monkeypatch, tmp_path):
    monkeypatch.setattr(engine_module, "save_json_list", lambda path, items: None)
    engine = _engine_without_services()
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    calls: list[tuple[str, str]] = []
    counters: list[tuple[str, list[str], int]] = []

    def fake_iter_files(root: Path, exclusions, inclusions=None):
        raise AssertionError("Full scan should not pre-discover every file")

    class FakeScanner:
        def scan_files(self, *args, **kwargs):
            raise AssertionError("Full scan should use streaming scan_target")

        def scan_target(self, target, progress_callback, result_callback, error_callback, cancel_callback=None):
            calls.append(("scan_target", target))
            progress_callback(str(Path(target) / "sample.txt"), 1, 0)
            return []

    monkeypatch.setattr(engine_module, "iter_files", fake_iter_files)
    engine.scanner = FakeScanner()
    monkeypatch.setattr(
        engine,
        "_start_background_total_counter",
        lambda label, targets, scan_session_id: counters.append((label, list(targets), scan_session_id)),
    )

    engine._run_scan("Full scan", [str(first_root), str(second_root)])

    assert counters == [("Full scan", [str(first_root), str(second_root)], 1)]
    assert calls == [("scan_target", str(first_root)), ("scan_target", str(second_root))]
    assert engine.state["last_scan_summary"] == "Full scan completed: 2 files, 0 threats."


def test_quarantine_manager_blocks_system_file_without_explicit_approval(monkeypatch, tmp_path):
    system_root = tmp_path / "Windows"
    quarantine_dir = tmp_path / "quarantine"
    system_root.mkdir()
    target = system_root / "system-tool.exe"
    target.write_text("suspicious", encoding="utf-8")
    monkeypatch.setenv("SystemRoot", str(system_root))
    monkeypatch.setattr(quarantine_module, "QUARANTINE_DIR", quarantine_dir)
    monkeypatch.setattr(quarantine_module, "SYSTEM_QUARANTINE_DECISIONS_FILE", tmp_path / "decisions.json")

    manager = QuarantineManager()

    assert manager.quarantine_file(str(target), "test", 99) is None
    assert target.exists() is True

    metadata = manager.quarantine_file(str(target), "test", 99, allow_system_file=True)

    assert metadata is not None
    assert target.exists() is False
    assert metadata["sha256"] == calculate_file_sha256(quarantine_dir / f"{metadata['id']}.bin")


def test_system_quarantine_decision_is_remembered_until_hash_changes(monkeypatch, tmp_path):
    system_root = tmp_path / "Windows"
    system_root.mkdir()
    target = system_root / "driver-helper.exe"
    target.write_text("version-one", encoding="utf-8")
    monkeypatch.setenv("SystemRoot", str(system_root))
    monkeypatch.setattr(quarantine_module, "QUARANTINE_DIR", tmp_path / "quarantine")
    monkeypatch.setattr(quarantine_module, "SYSTEM_QUARANTINE_DECISIONS_FILE", tmp_path / "decisions.json")
    monkeypatch.setattr(engine_module, "save_json_list", lambda path, items: None)

    engine = _engine_without_services()
    engine.quarantine = QuarantineManager()
    decisions = [False, True]
    prompts: list[str] = []

    def decide(payload: dict) -> bool:
        prompts.append(payload["sha256"])
        return decisions.pop(0)

    engine.set_system_quarantine_decision_callback(decide)

    assert engine._quarantine_file(str(target), "manual_scan", 99) is None
    assert target.exists() is True
    assert len(prompts) == 1

    assert engine._quarantine_file(str(target), "manual_scan", 99) is None
    assert target.exists() is True
    assert len(prompts) == 1

    target.write_text("version-two", encoding="utf-8")
    metadata = engine._quarantine_file(str(target), "manual_scan", 99)

    assert metadata is not None
    assert target.exists() is False
    assert len(prompts) == 2
