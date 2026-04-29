from novaguard.i18n import tr
from novaguard.ui.dashboard import NovaSentinelWindow


def _window_stub() -> NovaSentinelWindow:
    return NovaSentinelWindow.__new__(NovaSentinelWindow)


def test_forensic_detail_summarizes_post_alert_artifacts():
    window = _window_stub()
    item = {
        "path": r"C:\Temp\dropper.exe",
        "score": 95,
        "severity": "critical",
        "post_alert": {
            "collected_at": "2026-04-28T23:00:00",
            "trigger_reason": "result",
            "trigger_path": r"C:\Temp\dropper.exe",
            "matched_process_count": 1,
            "matched_processes": [
                {
                    "pid": 123,
                    "name": "dropper.exe",
                    "exe": r"C:\Temp\dropper.exe",
                    "cmdline": [r"C:\Temp\dropper.exe", "--stage"],
                    "ppid": 12,
                    "username": "admin",
                    "status": "running",
                    "create_time": "2026-04-28T22:59:00",
                    "children": [{"pid": 124, "name": "child.exe", "exe": r"C:\Temp\child.exe"}],
                    "open_files": [r"C:\Users\admin\Documents\client.docx"],
                    "connections": [{"local": "127.0.0.1:4444", "remote": "10.0.0.5:443", "status": "ESTABLISHED"}],
                    "memory_maps": [{"path": r"C:\Temp\payload.dll", "rss": 8192, "private": 4096}],
                }
            ],
        },
    }

    detail = window._forensic_detail(item)

    assert "dropper.exe [123]" in detail
    assert "Open files:" in detail
    assert "10.0.0.5:443" in detail
    assert "payload.dll" in detail


def test_forensic_counts_and_translations_exist():
    window = _window_stub()
    counts = window._forensic_counts(
        {
            "matched_process_count": 1,
            "matched_processes": [
                {
                    "memory_maps": [{}, {}],
                    "open_files": ["a"],
                    "connections": [{}, {}, {}],
                }
            ],
        }
    )

    assert counts == (1, 2, 1, 3)
    assert tr("fr", "nav.forensics") == "Forensic"
    assert tr("en", "forensics.title") == "Forensics"
    assert tr("fr", "heading.attack") == "ATT&CK"


def test_tree_tags_and_attack_summary_are_user_friendly():
    window = _window_stub()
    row = ("2026-04-29T12:00:00", "CRITICAL", 92, "T1486 Data Encrypted for Impact", "contained")
    tags = window._tree_tags_for_row(row, index=1)

    assert "row_odd" in tags
    assert "severity_critical" in tags
    assert "status_contained" in tags

    summary = window._attack_summary_for_incident(
        {
            "reason": "ransomware_burst",
            "signals": {"directory_count": 3},
            "actions": [],
            "evidence": [],
        }
    )
    assert "T1486" in summary
