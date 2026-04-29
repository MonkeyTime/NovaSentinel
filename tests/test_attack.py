from novaguard.attack import build_incident_graph, correlate_incident, correlate_scan_result, explain_incident, explain_scan_result
from novaguard.models import DetectionHit, ScanResult


def _scan_result() -> ScanResult:
    return ScanResult(
        path=r"C:\Temp\payload.ps1",
        score=96,
        severity="critical",
        malicious=True,
        engine="NovaSentinel-Heuristics",
        sha256="0" * 64,
        file_size=128,
        scanned_at="2026-04-29T12:00:00",
        hits=[
            DetectionHit("content", 24, "Encoded PowerShell command", "powershell -enc ZQBjAGgAbwA="),
            DetectionHit("content", 28, "Shadow copies deleted", "vssadmin delete shadows"),
            DetectionHit("api-intent", 20, "Remote process execution primitives", "process-injection: CreateRemoteThread"),
        ],
    )


def test_scan_result_maps_to_attack_and_xai():
    result = _scan_result()

    attack = correlate_scan_result(result)
    xai = explain_scan_result(result)
    technique_ids = {item["technique_id"] for item in attack["techniques"]}

    assert {"T1059.001", "T1490", "T1055", "T1027"}.issubset(technique_ids)
    assert "T1490" in attack["summary"]
    assert xai["final_score"] == 96
    assert xai["confidence"] == "high"
    assert xai["top_contributions"][0]["points"] == 28


def test_ransomware_incident_maps_to_attack_xai_and_graph():
    incident = {
        "id": "incident-1",
        "reason": "ransomware_burst",
        "behavior_model": "ransomware-behavior-score-v2",
        "behavior_score": 92,
        "confidence": "high",
        "severity": "critical",
        "status": "contained",
        "actions": ["recovery_evidence_preserved", "panic_mode_requested"],
        "signals": {
            "sensitive_file_count": 12,
            "directory_count": 3,
            "extension_count": 4,
            "burst_rate_per_second": 6.2,
            "recovery_coverage_percent": 83,
        },
        "related_paths": [r"C:\Users\admin\Documents\a.docx", r"C:\Users\admin\Pictures\b.jpg"],
        "evidence": ["vssadmin delete shadows"],
    }

    attack = correlate_incident(incident)
    incident["attack"] = attack
    xai = explain_incident(incident)
    graph = build_incident_graph(incident)
    technique_ids = {item["technique_id"] for item in attack["techniques"]}

    assert {"T1486", "T1083", "T1490"}.issubset(technique_ids)
    assert xai["final_score"] == 92
    assert any(node["type"] == "technique" for node in graph["nodes"])
    assert any(edge["relation"] == "maps_to" for edge in graph["edges"])
