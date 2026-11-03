from pathlib import Path
from types import SimpleNamespace
import hashlib

import pytest
from watchdog.events import FileModifiedEvent, FileDeletedEvent, FileMovedEvent

import novaguard.core.heuristics as heuristics
import novaguard.core.process_guard as processes
import novaguard.core.realtime as realtime
from novaguard.core.engine import NovaSentinelEngine
from novaguard.models import AppSettings, DetectionHit, ScanResult


def result(path, score=46, malicious=False):
    return ScanResult(str(path), score, "low", malicious, "test", "", 1, "2026-11-03T12:00:00")


def protector():
    return realtime.RealtimeProtector(
        AppSettings(), lambda event: None, lambda item: None, lambda *args: None,
        SimpleNamespace(record_file_activity=lambda *args, **kwargs: None, record_canary_touch=lambda path: None),
    )


def test_unsigned_capability_heavy_binary_requires_review(tmp_path, monkeypatch):
    path = tmp_path / "utility.exe"
    path.write_bytes(b"MZ" + bytes(range(256)) * 100)
    def pe_hits(path, hits):
        for category in ["api-behavior", "api-intent", "pe-structure", "packed-section-name", "sparse-imports"]:
            hits.append(DetectionHit(category, 35, "capability", category))
    monkeypatch.setattr(heuristics, "analyze_pe", pe_hits)
    monkeypatch.setattr(heuristics, "trusted_publisher_subject", lambda path: "")
    item = heuristics.analyze_file(path)
    assert item.score == 71
    assert not item.malicious
    assert any(hit.category == "review-policy" for hit in item.hits)


@pytest.mark.parametrize("command", [
    'powershell.exe -File backup.ps1 -Encoding utf8',
    'vssadmin.exe list shadows',
    'certutil.exe -hashfile installer.exe SHA256',
    'python.exe C:\\tools\\powershell-encoding-helper.py',
])
def test_normal_admin_commands_are_not_execution_evidence(command):
    assert processes.command_line_signals(command) == (0, [])


def test_encoded_command_is_an_exact_option():
    risk, evidence = processes.command_line_signals('powershell.exe -EncodedCommand AAAA')
    assert risk == 26
    assert evidence == ["-encodedcommand"]


def test_process_command_line_does_not_quarantine_interpreter(tmp_path, monkeypatch):
    exe = tmp_path / "powershell.exe"
    exe.write_bytes(b"interpreter")
    scanned = []
    quarantined = []
    guard = processes.ProcessGuard(AppSettings(), lambda event: None, scanned.append,
                                   lambda *args: quarantined.append(args))
    process = SimpleNamespace(info={"pid": 42, "create_time": 1.0, "exe": str(exe), "name": exe.name,
                                   "cmdline": [str(exe), "-enc", "AAAA", "downloadstring", "invoke-expression"]})
    monkeypatch.setattr(processes, "analyze_file", lambda *args, **kwargs: result(exe, 71))
    guard._inspect_process(process)
    assert scanned[0].score == 71
    assert not scanned[0].malicious
    assert not quarantined
    # Same PID, different creation time must be inspected again.
    process.info["create_time"] = 2.0
    guard._inspect_process(process)
    assert len(scanned) == 2


def test_realtime_coalesces_duplicate_paths():
    guard = protector()
    for _ in range(100):
        guard._enqueue("same.exe")
    assert guard.queue.qsize() == 1


def test_realtime_rescans_changed_contents_without_time_window(tmp_path, monkeypatch):
    path = tmp_path / "sample.txt"
    path.write_bytes(b"before")
    guard = protector()
    calls = []
    def scan(target, **kwargs):
        calls.append(target.read_bytes())
        if len(calls) == 1:
            path.write_bytes(b"changed contents during scan")
        else:
            guard.stop_event.set()
        return result(target), ""
    monkeypatch.setattr(realtime, "scan_file_resiliently", scan)
    guard._enqueue(str(path))
    guard._worker_loop()
    assert calls == [b"before", b"changed contents during scan"]


def test_canary_metadata_events_do_not_trigger_containment(tmp_path):
    path = tmp_path / "test.canary"
    path.write_bytes(b"original")
    guard = protector()
    touches = []
    guard.ransomware_guard.record_canary_touch = touches.append
    guard.canary_hashes[str(path.resolve())] = hashlib.sha256(b"original").hexdigest()
    guard._register_sensitive_activity(str(path))
    assert touches == []
    path.write_bytes(b"tampered")
    guard._register_sensitive_activity(str(path))
    guard._register_sensitive_activity(str(path))
    assert touches == [str(path)]
    path.unlink()
    guard._register_sensitive_activity(str(path), "deleted")
    assert touches == [str(path), str(path)]


def test_deleted_and_renamed_canaries_reach_integrity_check(tmp_path):
    activity = []
    handler = realtime._RealtimeHandler(lambda path: None, lambda *args: activity.append(args), lambda path: True)
    handler.on_deleted(FileDeletedEvent(str(tmp_path / "a.canary")))
    handler.on_moved(FileMovedEvent(str(tmp_path / "b.canary"), str(tmp_path / "b.locked")))
    assert activity[0][1] == "deleted"
    assert activity[1] == (str(tmp_path / "b.canary"), "moved")


def test_changed_file_cannot_be_quarantined_using_old_hash(tmp_path):
    path = tmp_path / "changed.exe"
    path.write_bytes(b"new version")
    engine = NovaSentinelEngine.__new__(NovaSentinelEngine)
    events = []
    engine.record_event = events.append
    assert engine._quarantine_file(str(path), "manual_scan", 99, "outdated hash") is None
    assert path.exists()
    assert events[0].title == "File changed after scan"


def test_background_system_detection_does_not_open_a_dialog(tmp_path, monkeypatch):
    import novaguard.core.engine as engine_module
    path = tmp_path / "system.exe"
    path.write_bytes(b"content")
    engine = NovaSentinelEngine.__new__(NovaSentinelEngine)
    engine.record_event = lambda event: None
    engine.quarantine = SimpleNamespace(remembered_system_decision=lambda *args: None)
    monkeypatch.setattr(engine_module, "is_system_managed_path", lambda path: True)
    engine._request_system_quarantine_decision = lambda *args: pytest.fail("Unexpected modal")
    assert engine._quarantine_file(str(path), "realtime_protection", 99) is None


def test_eicar_documentation_is_not_a_test_signature():
    hits = []
    heuristics.analyze_text_signals(Path("guide.txt"), b"Documentation about EICAR-STANDARD-ANTIVIRUS-TEST-FILE", hits)
    assert not hits
    heuristics.analyze_text_signals(Path("test.txt"), heuristics.EICAR_TEST_SIGNATURE, hits)
    assert len(hits) == 1
    assert hits[0].score == 95


def test_suspicious_reputation_is_not_a_malicious_verdict(tmp_path, monkeypatch):
    path = tmp_path / "utility.exe"
    path.write_bytes(b"MZ ordinary utility")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    monkeypatch.setattr(heuristics, "_load_local_ioc_db", lambda: {
        digest: {"verdict": "suspicious", "score": 95},
    })
    item = heuristics.analyze_file(path, premium_features={"local_ioc_lookup"})
    assert item is not None
    assert not item.malicious
    assert item.score <= 71


def test_file_modified_during_analysis_has_no_stale_verdict(tmp_path, monkeypatch):
    path = tmp_path / "changing.txt"
    path.write_bytes(b"original")
    def mutate(target):
        target.write_bytes(b"different content after analysis")
        return hashlib.sha256(target.read_bytes()).hexdigest()
    monkeypatch.setattr(heuristics, "compute_sha256", mutate)
    assert heuristics.analyze_file(path) is None
