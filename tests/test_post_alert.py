from __future__ import annotations

from pathlib import Path

import psutil

from novaguard.core.post_alert import collect_post_alert_context


class FakeChild:
    pid = 222

    def name(self):
        return "child.exe"

    def exe(self):
        return r"C:\Users\admin\AppData\Local\Temp\child.exe"


class FakeProcess:
    def __init__(self, exe: str):
        self.pid = 111
        self.info = {
            "pid": 111,
            "name": Path(exe).name,
            "exe": exe,
            "cmdline": [exe, "--encrypt", r"C:\Users\admin\Documents"],
            "ppid": 42,
            "username": "admin",
            "create_time": 1_700_000_000,
            "status": "running",
        }

    def children(self, recursive=False):
        return [FakeChild()]

    def open_files(self):
        return [type("OpenFile", (), {"path": r"C:\Users\admin\Documents\client.docx"})()]

    def net_connections(self, kind="inet"):
        return [
            type(
                "Connection",
                (),
                {
                    "status": "ESTABLISHED",
                    "laddr": type("Addr", (), {"ip": "127.0.0.1", "port": 4444})(),
                    "raddr": type("Addr", (), {"ip": "10.0.0.5", "port": 443})(),
                },
            )()
        ]

    def memory_maps(self, grouped=False):
        return [
            type("Map", (), {"path": r"C:\Windows\System32\kernel32.dll", "rss": 4096, "private": 1024})(),
            type("Map", (), {"path": r"C:\Users\admin\AppData\Local\Temp\payload.dll", "rss": 8192, "private": 4096})(),
        ]


def test_collect_post_alert_context_captures_process_artifacts(monkeypatch):
    exe = r"C:\Users\admin\AppData\Local\Temp\dropper.exe"
    monkeypatch.setattr(psutil, "process_iter", lambda attrs=None: [FakeProcess(exe)])

    context = collect_post_alert_context(exe, 95, "unit-test")

    assert context["matched_process_count"] == 1
    process = context["matched_processes"][0]
    assert process["pid"] == 111
    assert process["children"][0]["pid"] == 222
    assert process["open_files"] == [r"C:\Users\admin\Documents\client.docx"]
    assert process["connections"][0]["remote"] == "10.0.0.5:443"
    assert any(item["path"].endswith("payload.dll") for item in process["memory_maps"])


def test_collect_post_alert_context_records_no_match(monkeypatch):
    monkeypatch.setattr(psutil, "process_iter", lambda attrs=None: [])

    context = collect_post_alert_context(r"C:\Temp\missing.exe", 90, "unit-test")

    assert context["matched_process_count"] == 0
    assert "No running process matched" in context["notes"][0]
