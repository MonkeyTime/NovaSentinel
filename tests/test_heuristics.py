import threading
from pathlib import Path

import novaguard.core.heuristics as heuristics_module
import novaguard.core.scanner as scanner_module
from novaguard.core.engine import NovaSentinelEngine
from novaguard.core.heuristics import analyze_file, classify_severity, is_benign_python_artifact, is_runtime_state_candidate
from novaguard.core.scanner import (
    Scanner,
    is_excluded,
    is_runtime_state_path,
    iter_files,
    scan_file_resiliently,
    scan_worker_count,
)
from novaguard.models import ScanResult


def test_classify_severity_thresholds():
    assert classify_severity(90) == ("critical", True)
    assert classify_severity(75) == ("high", True)
    assert classify_severity(50) == ("medium", False)


def test_suspicious_script_is_scored(tmp_path: Path):
    sample = tmp_path / "dropper.ps1"
    sample.write_text(
        "powershell -enc ZQBjAGgAbwA=; vssadmin delete shadows; Invoke-Expression",
        encoding="utf-8",
    )
    result = analyze_file(sample, max_file_size_mb=2)
    assert result is not None
    assert result.score >= 70
    assert result.severity in {"high", "critical"}


def test_source_code_with_signature_strings_is_not_quarantined(tmp_path: Path):
    sample = tmp_path / "heuristics.py"
    sample.write_text(
        "from pathlib import Path\n"
        "SUSPICIOUS = {'powershell -enc': 24, 'vssadmin delete shadows': 28}\n"
        "def analyze():\n"
        "    return SUSPICIOUS\n",
        encoding="utf-8",
    )
    result = analyze_file(sample, max_file_size_mb=2)
    assert result is not None
    assert result.malicious is False
    assert result.score < 72


def test_pe_api_intent_families_are_explainable(tmp_path: Path, monkeypatch):
    sample = tmp_path / "loader.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 200_000)

    class FakeImport:
        def __init__(self, name: str):
            self.name = name.encode("utf-8")

    class FakeImportEntry:
        imports = [
            FakeImport("OpenProcess"),
            FakeImport("VirtualAllocEx"),
            FakeImport("WriteProcessMemory"),
            FakeImport("CreateRemoteThread"),
            FakeImport("URLDownloadToFileW"),
        ]

    class FakeSection:
        Name = b".text\x00\x00\x00"

        def get_entropy(self):
            return 5.2

    class FakeHeader:
        TimeDateStamp = 1_700_000_000

    class FakePE:
        sections = [FakeSection(), FakeSection(), FakeSection()]
        DIRECTORY_ENTRY_IMPORT = [FakeImportEntry()]
        FILE_HEADER = FakeHeader()

        def __init__(self, path, fast_load=True):
            pass

        def parse_data_directories(self):
            pass

        def get_overlay_data_start_offset(self):
            return None

        def close(self):
            pass

    monkeypatch.setattr(heuristics_module.pefile, "PE", FakePE)

    result = analyze_file(sample, max_file_size_mb=2)

    assert result is not None
    evidence = {hit.evidence for hit in result.hits}
    categories = {hit.category for hit in result.hits}
    assert "api-intent" in categories
    assert any("process-injection" in item for item in evidence)
    assert any("network-staging" in item for item in evidence)


def test_pe_structure_features_flag_packed_shape(tmp_path: Path, monkeypatch):
    sample = tmp_path / "packed.exe"
    sample.write_bytes(b"MZ" + b"\x90" * 300_000)

    class FakeSection:
        Name = b"UPX0\x00\x00\x00\x00"

        def get_entropy(self):
            return 7.8

    class FakeHeader:
        TimeDateStamp = 0

    class FakePE:
        sections = [FakeSection()]
        FILE_HEADER = FakeHeader()

        def __init__(self, path, fast_load=True):
            pass

        def parse_data_directories(self):
            pass

        def get_overlay_data_start_offset(self):
            return 180_000

        def close(self):
            pass

    monkeypatch.setattr(heuristics_module.pefile, "PE", FakePE)

    result = analyze_file(sample, max_file_size_mb=2)

    assert result is not None
    categories = {hit.category for hit in result.hits}
    assert "packed-section" in categories
    assert "packed-section-name" in categories
    assert "pe-overlay" in categories
    assert "pe-timestamp" in categories
    assert "sparse-imports" in categories


def test_python_bytecode_is_ignored(tmp_path: Path):
    cache_dir = tmp_path / "__pycache__"
    cache_dir.mkdir()
    sample = cache_dir / "engine.cpython-314.pyc"
    sample.write_bytes(b"\x00\x00\x00\x00compiled-bytecode")

    assert is_benign_python_artifact(sample) is True
    assert analyze_file(sample, max_file_size_mb=2) is None


def test_scanner_skips_python_cache_files(tmp_path: Path):
    cache_dir = tmp_path / "__pycache__"
    cache_dir.mkdir()
    (cache_dir / "engine.cpython-314.pyc").write_bytes(b"\x00\x00\x00\x00compiled-bytecode")
    healthy = tmp_path / "healthy.txt"
    healthy.write_text("hello", encoding="utf-8")

    paths = list(iter_files(tmp_path, exclusions=[], inclusions=[str(tmp_path)]))

    assert healthy in paths
    assert all(path.suffix.lower() != ".pyc" for path in paths)


def test_scanner_always_skips_runtime_state_files(tmp_path: Path, monkeypatch):
    state_dir = tmp_path / "NovaSentinel"
    state_dir.mkdir()
    history = state_dir / "history.json"
    history.write_text("[]", encoding="utf-8")
    event_tmp = state_dir / "events.json.tmp"
    event_tmp.write_text("[]", encoding="utf-8")
    log_dir = state_dir / "logs"
    log_dir.mkdir()
    app_log = log_dir / "novasentinel.log"
    app_log.write_text("locked", encoding="utf-8")
    legacy_dir = tmp_path / "novesentinel"
    legacy_dir.mkdir()
    legacy_history = legacy_dir / "history.json"
    legacy_history.write_text("[]", encoding="utf-8")
    normal = tmp_path / "normal.txt"
    normal.write_text("hello", encoding="utf-8")

    monkeypatch.setattr(scanner_module.config, "STATE_DIR", state_dir)
    monkeypatch.setattr(scanner_module.config, "QUARANTINE_DIR", state_dir / "quarantine")
    monkeypatch.setattr(scanner_module.config, "RECOVERY_DIR", state_dir / "recovery_vault")

    paths = list(iter_files(tmp_path, exclusions=[], inclusions=[str(tmp_path), str(state_dir)]))

    assert normal in paths
    assert history not in paths
    assert event_tmp not in paths
    assert app_log in paths
    assert legacy_history in paths
    assert list(iter_files(history, exclusions=[], inclusions=[str(history)])) == []
    assert list(iter_files(app_log, exclusions=[], inclusions=[str(app_log)])) == [app_log]


def test_scanner_does_not_skip_unowned_appdata_history_file(tmp_path: Path, monkeypatch):
    state_dir = tmp_path / "AppData" / "Roaming" / "novasentinel"
    state_dir.mkdir(parents=True)
    history = state_dir / "history.json"
    history.write_text("[]", encoding="utf-8")
    history_tmp = state_dir / "history.json.tmp"
    history_tmp.write_text("[]", encoding="utf-8")
    scanned: list[Path] = []

    monkeypatch.setattr(scanner_module.config, "STATE_DIR", tmp_path / "not-the-state-dir")
    monkeypatch.setattr(scanner_module.config, "QUARANTINE_DIR", tmp_path / "not-the-state-dir" / "quarantine")
    monkeypatch.setattr(scanner_module.config, "RECOVERY_DIR", tmp_path / "not-the-state-dir" / "recovery_vault")

    def fake_scan_file(path, max_file_size_mb):
        scanned.append(Path(path))
        return None, ""

    monkeypatch.setattr(scanner_module, "scan_file_resiliently", fake_scan_file)

    scanner = Scanner(settings=type("Settings", (), {"scan_exclusions": [], "scan_roots": [str(history_tmp)], "max_file_size_mb": 4})())
    assert scanner.scan_target(str(history_tmp)) == []
    assert scanner.scan_target(str(history)) == []
    assert list(iter_files(history, exclusions=[], inclusions=[str(history)])) == [history]
    assert list(iter_files(history_tmp, exclusions=[], inclusions=[str(history_tmp)])) == [history_tmp]
    result, error = scan_file_resiliently(history, max_file_size_mb=4)
    assert error == ""
    assert result is not None
    assert is_runtime_state_path(history_tmp) is False
    assert scanned == [history_tmp, history]


def test_appdata_runtime_state_files_are_blocked_before_disk_access(monkeypatch):
    state_dir = Path(r"C:\Users\admin\AppData\Roaming\NovaSentinel")
    monkeypatch.setattr(scanner_module.config, "STATE_DIR", state_dir)
    monkeypatch.setattr(heuristics_module.config, "STATE_DIR", state_dir)
    paths = [
        state_dir / "history.json",
        state_dir / "history.json.tmp",
        Path(r"c:/users/admin/appdata/roaming/novasentinel/history.json"),
        state_dir / "events.json.tmp",
    ]
    opened: list[Path] = []

    def fake_analyze(path, max_file_size_mb):
        opened.append(Path(path))
        return None, ""

    monkeypatch.setattr(scanner_module, "scan_file_resiliently", fake_analyze)

    for path in paths:
        assert is_runtime_state_path(path) is True
        assert is_runtime_state_candidate(path) is True
        assert analyze_file(path, max_file_size_mb=4) is None
        assert scan_file_resiliently(path, max_file_size_mb=4) == (None, "")
        assert list(iter_files(path, exclusions=[], inclusions=[str(path)])) == []

    scanner = Scanner(settings=type("Settings", (), {"scan_exclusions": [], "scan_roots": [str(paths[0])], "max_file_size_mb": 4})())
    assert scanner.scan_target(str(paths[0])) == []
    assert opened == []


def test_scanner_silently_skips_files_used_by_another_process(tmp_path: Path, monkeypatch):
    locked = tmp_path / "locked.db"
    locked.write_text("busy", encoding="utf-8")

    def fake_analyze(path, max_file_size_mb=64):
        raise OSError("[WinError 32] The process cannot access the file because it is being used by another process")

    monkeypatch.setattr("novaguard.core.scanner.analyze_file", fake_analyze)

    result, error = scan_file_resiliently(locked, max_file_size_mb=2)

    assert result is None
    assert error == ""


def test_scanner_continues_after_file_error(tmp_path: Path, monkeypatch):
    broken = tmp_path / "broken.ps1"
    broken.write_text("powershell -enc Zg==", encoding="utf-8")
    healthy = tmp_path / "healthy.txt"
    healthy.write_text("hello", encoding="utf-8")

    def fake_analyze(path, max_file_size_mb=64):
        if Path(path).name == "broken.ps1":
            raise OSError("access denied")
        return analyze_file(path, max_file_size_mb=max_file_size_mb)

    errors: list[tuple[str, str]] = []
    monkeypatch.setattr("novaguard.core.scanner.analyze_file", fake_analyze)

    scanner = Scanner(settings=type("Settings", (), {"scan_exclusions": [], "scan_roots": [str(tmp_path)], "max_file_size_mb": 4})())
    results = scanner.scan_target(str(tmp_path), error_callback=lambda path, err: errors.append((path, err)))

    assert len(errors) == 1
    assert any(Path(item[0]).name == "broken.ps1" for item in errors)
    assert any(Path(result.path).name == "healthy.txt" for result in results)


def test_scanner_uses_multiple_workers_for_multi_file_scan(tmp_path: Path, monkeypatch):
    for index in range(6):
        (tmp_path / f"sample-{index}.txt").write_text("hello", encoding="utf-8")

    lock = threading.Lock()
    started = 0
    worker_ids: set[int] = set()
    at_least_two_started = threading.Event()

    def fake_scan_file(path, max_file_size_mb):
        nonlocal started
        with lock:
            worker_ids.add(threading.get_ident())
            started += 1
            if started >= 2:
                at_least_two_started.set()
        at_least_two_started.wait(timeout=2)
        return None, ""

    monkeypatch.setattr(scanner_module, "scan_file_resiliently", fake_scan_file)

    scanner = Scanner(settings=type("Settings", (), {"scan_exclusions": [], "scan_roots": [str(tmp_path)], "max_file_size_mb": 4})())
    scanner.scan_target(str(tmp_path))

    assert scan_worker_count(6) >= 2
    assert len(worker_ids) >= 2


def test_scanner_starts_before_file_discovery_finishes(tmp_path: Path, monkeypatch):
    first = tmp_path / "first.txt"
    second = tmp_path / "second.txt"
    first.write_text("hello", encoding="utf-8")
    second.write_text("hello", encoding="utf-8")
    scan_started = threading.Event()
    discovery_resumed = threading.Event()

    def fake_iter_files(target, exclusions, inclusions=None):
        yield first
        assert scan_started.wait(timeout=2)
        discovery_resumed.set()
        yield second

    def fake_scan_file(path, max_file_size_mb):
        scan_started.set()
        return None, ""

    monkeypatch.setattr(scanner_module, "iter_files", fake_iter_files)
    monkeypatch.setattr(scanner_module, "scan_file_resiliently", fake_scan_file)

    scanner = Scanner(settings=type("Settings", (), {"scan_exclusions": [], "scan_roots": [str(tmp_path)], "max_file_size_mb": 4})())
    scanner.scan_target(str(tmp_path))

    assert discovery_resumed.is_set()


def test_scanner_reports_unknown_total_until_discovery_finishes(tmp_path: Path, monkeypatch):
    for index in range(40):
        (tmp_path / f"sample-{index}.txt").write_text("hello", encoding="utf-8")

    totals: list[int] = []

    def fake_scan_file(path, max_file_size_mb):
        return None, ""

    monkeypatch.setattr(scanner_module, "scan_file_resiliently", fake_scan_file)

    scanner = Scanner(settings=type("Settings", (), {"scan_exclusions": [], "scan_roots": [str(tmp_path)], "max_file_size_mb": 4})())
    scanner.scan_target(str(tmp_path), progress_callback=lambda path, index, total: totals.append(total))

    assert scanner_module.UNKNOWN_PROGRESS_TOTAL in totals
    assert totals[-1] == 40


def test_scanner_callbacks_stay_on_calling_thread(tmp_path: Path, monkeypatch):
    sample = tmp_path / "sample.txt"
    sample.write_text("hello", encoding="utf-8")
    caller_thread = threading.get_ident()
    callback_threads: list[int] = []

    def fake_scan_file(path, max_file_size_mb):
        return ScanResult(
            path=str(path),
            score=0,
            severity="info",
            malicious=False,
            engine="test",
            sha256="",
            file_size=5,
            scanned_at="now",
        ), ""

    monkeypatch.setattr(scanner_module, "scan_file_resiliently", fake_scan_file)

    scanner = Scanner(settings=type("Settings", (), {"scan_exclusions": [], "scan_roots": [str(tmp_path)], "max_file_size_mb": 4})())
    scanner.scan_target(
        str(tmp_path),
        progress_callback=lambda path, index, total: callback_threads.append(threading.get_ident()),
        result_callback=lambda result: callback_threads.append(threading.get_ident()),
    )

    assert callback_threads
    assert set(callback_threads) == {caller_thread}


def test_engine_resets_scan_state_after_failure(tmp_path: Path, monkeypatch):
    engine = NovaSentinelEngine()

    def fake_scan_target(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(engine.scanner, "scan_target", fake_scan_target)
    engine._run_scan("Full scan", [str(tmp_path)])

    snapshot = engine.get_snapshot()["state"]
    assert snapshot["scan_in_progress"] is False
    assert snapshot["scan_label"] == "Idle"
    assert "failed" in snapshot["last_scan_summary"].lower()


def test_temp_file_scan_retries_until_access_returns(tmp_path: Path, monkeypatch):
    sample = tmp_path / "recovering.tmp"
    sample.write_text("hello", encoding="utf-8")
    attempts = {"count": 0}

    def fake_analyze(path, max_file_size_mb=64):
        attempts["count"] += 1
        if attempts["count"] < 3:
            return None
        return analyze_file(path, max_file_size_mb=max_file_size_mb)

    monkeypatch.setattr("novaguard.core.scanner.analyze_file", fake_analyze)
    monkeypatch.setattr("novaguard.core.scanner.is_temp_path", lambda path: True)
    monkeypatch.setattr("novaguard.core.scanner.is_read_locked", lambda path: (True, "sharing violation"))
    monkeypatch.setattr("novaguard.core.scanner.time.sleep", lambda seconds: None)

    result, error = scan_file_resiliently(sample, max_file_size_mb=2)

    assert error == ""
    assert result is not None
    assert attempts["count"] == 3


def test_explicit_windows_temp_root_is_not_reexcluded():
    path = Path(r"C:\Windows\Temp\sample.tmp")
    assert is_excluded(path, [r"C:\Windows"], [r"C:\Windows\Temp"]) is False


def test_parent_scan_root_does_not_override_specific_exclusion():
    path = Path(r"C:\Users\admin\Documents\antivirus\build\sample.zip")
    assert is_excluded(path, [r"C:\Users\admin\Documents\antivirus"], [r"C:\Users\admin\Documents"]) is True


def test_runtime_state_excludes_state_files_not_whole_state_tree(tmp_path: Path, monkeypatch):
    state_dir = tmp_path / "NovaSentinel"
    monkeypatch.setattr(scanner_module.config, "STATE_DIR", state_dir)
    monkeypatch.setattr(heuristics_module.config, "STATE_DIR", state_dir)

    assert is_runtime_state_path(state_dir / "settings.json") is True
    assert is_runtime_state_candidate(state_dir / "settings.json") is True
    assert is_runtime_state_path(state_dir / "settings.json.bak") is True
    assert is_runtime_state_path(state_dir / "settings.json.123.456.tmp") is True
    assert is_runtime_state_path(state_dir / "settings.json.evil.exe") is False
    assert is_runtime_state_path(state_dir / "dropper.exe") is False
    assert is_runtime_state_candidate(state_dir / "dropper.exe") is False
    assert is_runtime_state_path(state_dir / "quarantine" / "payload.bin") is False
    assert is_runtime_state_path(state_dir / "canaries" / "canary.docx") is False


def test_engine_can_ignore_and_quarantine_current_scan_threat(tmp_path: Path):
    engine = NovaSentinelEngine()
    suspicious = tmp_path / "payload.ps1"
    suspicious.write_text("powershell -enc ZQBjAGgAbwA=", encoding="utf-8")
    result = analyze_file(suspicious, max_file_size_mb=2)

    assert result is not None

    engine._track_current_scan_threat(result)
    ignored_ok, _ = engine.ignore_current_threat(str(suspicious))
    assert ignored_ok is True
    assert engine._find_current_threat(str(suspicious))["action_taken"] == "ignored"

    engine._track_current_scan_threat(
        ScanResult(
            path=result.path,
            score=result.score,
            severity=result.severity,
            malicious=result.malicious,
            engine=result.engine,
            sha256=result.sha256,
            file_size=result.file_size,
            scanned_at=result.scanned_at,
            hits=result.hits,
            action_taken="none",
        )
    )
    quarantined_ok, _ = engine.quarantine_current_threat(str(suspicious))
    assert quarantined_ok is True
    assert suspicious.exists() is False
    assert engine._find_current_threat(str(suspicious))["action_taken"] == "quarantined"
