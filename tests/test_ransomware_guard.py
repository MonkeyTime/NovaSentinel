from __future__ import annotations

from pathlib import Path

import psutil

import novaguard.core.ransomware_guard as ransomware_guard_module
from novaguard.core.process_guard import ProcessGuard
from novaguard.core.ransomware_guard import RansomwareGuard
from novaguard.models import AppSettings, EventRecord


class FakeLockdownManager:
    def __init__(self) -> None:
        self.frozen_roots: list[str] = []
        self.released = False

    def freeze(self, roots: list[str], duration_seconds: int = 90) -> list[str]:
        self.frozen_roots = list(roots)
        return list(roots)

    def release(self) -> list[str]:
        self.released = True
        released = list(self.frozen_roots)
        self.frozen_roots = []
        return released


class FakeProcess:
    def __init__(self, pid: int, exe: str, open_paths: list[str]) -> None:
        self.info = {
            "pid": pid,
            "name": Path(exe).name,
            "exe": exe,
            "cmdline": [exe],
        }
        self._open_paths = open_paths
        self.suspended = False
        self.terminated = False

    def open_files(self):
        return [type("OpenFile", (), {"path": item})() for item in self._open_paths]

    def suspend(self):
        self.suspended = True

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=0):
        return None


def test_panic_mode_contains_multiple_related_processes(tmp_path: Path, monkeypatch):
    downloads = tmp_path / "Downloads"
    documents = tmp_path / "Documents"
    downloads.mkdir()
    documents.mkdir()
    bad_one = downloads / "bad-one.exe"
    bad_two = documents / "bad-two.exe"
    victim = documents / "client.docx"
    for path in [bad_one, bad_two, victim]:
        path.write_text("x", encoding="utf-8")

    events: list[EventRecord] = []
    quarantined: list[tuple[str, str, int]] = []
    lockdown = FakeLockdownManager()
    guard = ProcessGuard(
        settings=AppSettings(scan_roots=[str(downloads), str(documents)], scan_exclusions=[]),
        on_event=events.append,
        on_result=lambda result: None,
        quarantine_callback=lambda path, reason, score: quarantined.append((path, reason, score)) or {},
        lockdown_manager=lockdown,
    )
    guard._sensitive_roots = lambda: [str(downloads), str(documents)]  # type: ignore[method-assign]
    guard.suspicious_processes = {
        100: {"pid": 100, "exe": str(bad_one), "score": 88, "cmdline": str(bad_one), "evidence": ["powershell"]},
        101: {"pid": 101, "exe": str(bad_two), "score": 76, "cmdline": str(bad_two), "evidence": ["invoke-expression"]},
    }
    process_one = FakeProcess(100, str(bad_one), [str(victim)])
    process_two = FakeProcess(101, str(bad_two), [str(victim)])

    monkeypatch.setattr(psutil, "process_iter", lambda attrs=None: [process_one, process_two])

    guard.emergency_contain(str(victim), "ransomware_burst", [str(victim)])

    assert process_one.suspended is False
    assert process_two.suspended is False
    assert process_one.terminated is True
    assert process_two.terminated is True
    assert lockdown.frozen_roots == [str(downloads), str(documents)]
    assert len(quarantined) == 2
    assert any(event.title == "Panic mode activated" for event in events)


def test_manual_panic_does_not_stop_existing_processes(tmp_path: Path, monkeypatch):
    documents = tmp_path / "Documents"
    documents.mkdir()
    suspicious = documents / "helper.exe"
    suspicious.write_text("x", encoding="utf-8")

    events: list[EventRecord] = []
    lockdown = FakeLockdownManager()
    guard = ProcessGuard(
        settings=AppSettings(scan_roots=[str(documents)], scan_exclusions=[]),
        on_event=events.append,
        on_result=lambda result: None,
        quarantine_callback=lambda path, reason, score: {},
        lockdown_manager=lockdown,
    )
    guard._sensitive_roots = lambda: [str(documents)]  # type: ignore[method-assign]
    guard.suspicious_processes = {
        100: {"pid": 100, "exe": str(suspicious), "score": 99, "cmdline": str(suspicious), "evidence": ["powershell"]},
    }
    process = FakeProcess(100, str(suspicious), [str(documents / "client.docx")])

    monkeypatch.setattr(psutil, "process_iter", lambda attrs=None: [process])

    guard.emergency_contain("", "manual_panic", [])

    assert process.suspended is False
    assert process.terminated is False
    assert lockdown.frozen_roots == [str(documents)]
    assert any("Running apps were left alone" in event.description for event in events)


def test_should_block_risky_execution_in_panic():
    guard = ProcessGuard(
        settings=AppSettings(scan_roots=[], scan_exclusions=[]),
        on_event=lambda event: None,
        on_result=lambda result: None,
        quarantine_callback=lambda path, reason, score: {},
        lockdown_manager=FakeLockdownManager(),
    )

    assert guard._should_block_in_panic(r"C:\Users\admin\Downloads\dropper.exe", 50, 0) is True
    assert guard._should_block_in_panic(r"C:\Users\admin\AppData\Local\Temp\loader.exe", 24, 18) is True
    assert guard._should_block_in_panic(r"C:\Program Files\Vendor\app.exe", 50, 0) is False


def test_wsl_windows_mount_encryptor_command_scores_high_without_quarantining_system_binary():
    guard = ProcessGuard(
        settings=AppSettings(scan_roots=[], scan_exclusions=[]),
        on_event=lambda event: None,
        on_result=lambda result: None,
        quarantine_callback=lambda path, reason, score: {},
        lockdown_manager=FakeLockdownManager(),
    )

    command = (
        r'wsl.exe bash -lc "find /mnt/c/Users/admin/Documents -type f '
        r'-exec openssl enc -aes-256-cbc -in {} -out {}.locked \;"'
    )
    risk, evidence = guard._wsl_behavior_risk("wsl.exe", r"C:\Windows\System32\wsl.exe", command)

    assert risk >= 70
    assert any("wsl-windows-mount" in item for item in evidence)
    assert any("wsl-linux-encryptor" in item for item in evidence)
    assert guard._should_auto_quarantine_process(r"C:\Windows\System32\wsl.exe") is False
    assert guard._should_auto_quarantine_process(r"C:\Users\admin\Downloads\dropper.exe") is True


def test_ransomware_guard_persists_explainable_incident_and_recovery(tmp_path: Path, monkeypatch):
    incidents_path = tmp_path / "incidents.json"
    recovery_dir = tmp_path / "recovery_vault"
    monkeypatch.setattr(ransomware_guard_module, "INCIDENTS_FILE", incidents_path)
    monkeypatch.setattr(ransomware_guard_module, "RECOVERY_DIR", recovery_dir)

    events: list[EventRecord] = []
    emergency_calls: list[tuple[str, str, list[str] | None]] = []
    guard = RansomwareGuard(
        settings=AppSettings(ransomware_guard_enabled=True),
        on_event=events.append,
        emergency_callback=lambda path, reason, related_paths: emergency_calls.append((path, reason, related_paths)),
    )

    for index in range(ransomware_guard_module.BURST_THRESHOLD):
        document = tmp_path / f"client-{index}.docx"
        document.write_text(f"important content {index}", encoding="utf-8")
        guard.record_file_activity(str(document))

    incidents = guard.list_incidents()
    assert len(incidents) == 1
    incident = incidents[0]
    assert incident["reason"] == "ransomware_burst"
    assert incident["status"] == "contained"
    assert incident["actions"] == ["panic_mode_requested"]
    assert [step["step"] for step in incident["timeline"]] == ["signal", "recovery", "scoring", "containment"]
    assert incident["behavior_model"] == ransomware_guard_module.BEHAVIOR_MODEL_VERSION
    assert incident["behavior_score"] >= 80
    assert incident["confidence"] == "high"
    assert incident["signals"]["sensitive_file_count"] == ransomware_guard_module.BURST_THRESHOLD
    assert incident["signals"]["recovery_coverage_percent"] == 100
    assert "Modification burst" in incident["tags"]
    assert any("behavior score" in item for item in incident["evidence"])
    assert len(incident["related_paths"]) == ransomware_guard_module.BURST_THRESHOLD
    assert len(incident["recovery_files"]) == ransomware_guard_module.BURST_THRESHOLD
    assert recovery_dir.exists()
    assert any(event.title == "Ransomware-like modification burst" for event in events)
    assert len(emergency_calls) == 1
    assert emergency_calls[0][1] == "ransomware_burst"


def test_manual_panic_creates_incident(tmp_path: Path, monkeypatch):
    incidents_path = tmp_path / "incidents.json"
    monkeypatch.setattr(ransomware_guard_module, "INCIDENTS_FILE", incidents_path)
    monkeypatch.setattr(ransomware_guard_module, "RECOVERY_DIR", tmp_path / "recovery_vault")

    events: list[EventRecord] = []
    emergency_calls: list[tuple[str, str, list[str] | None]] = []
    guard = RansomwareGuard(
        settings=AppSettings(),
        on_event=events.append,
        emergency_callback=lambda path, reason, related_paths: emergency_calls.append((path, reason, related_paths)),
    )

    incident = guard.manual_panic()

    assert incident["reason"] == "manual_panic"
    assert incident["status"] == "contained"
    assert incident["behavior_score"] == 45
    assert incident["confidence"] == "operator"
    assert "Operator panic request" in incident["tags"]
    assert incidents_path.exists()
    assert any(event.title == "Manual panic mode" for event in events)
    assert emergency_calls == [("", "manual_panic", [])]


def test_manual_panic_records_recent_paths_without_targeting_them(tmp_path: Path, monkeypatch):
    incidents_path = tmp_path / "incidents.json"
    monkeypatch.setattr(ransomware_guard_module, "INCIDENTS_FILE", incidents_path)
    monkeypatch.setattr(ransomware_guard_module, "RECOVERY_DIR", tmp_path / "recovery_vault")

    emergency_calls: list[tuple[str, str, list[str] | None]] = []
    guard = RansomwareGuard(
        settings=AppSettings(),
        on_event=lambda event: None,
        emergency_callback=lambda path, reason, related_paths: emergency_calls.append((path, reason, related_paths)),
    )
    document = tmp_path / "client.docx"
    document.write_text("important", encoding="utf-8")
    guard.record_file_activity(str(document))

    incident = guard.manual_panic()

    assert str(document) in incident["related_paths"]
    assert emergency_calls[-1] == ("", "manual_panic", [])
