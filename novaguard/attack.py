from __future__ import annotations

from pathlib import Path
from typing import Any


ATTACK_VERSION = "enterprise-attack-local-2026.04"

ATTACK_TECHNIQUES: dict[str, dict[str, Any]] = {
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactics": ["Defense Evasion"],
        "url": "https://attack.mitre.org/techniques/T1027/",
    },
    "T1055": {
        "name": "Process Injection",
        "tactics": ["Defense Evasion", "Privilege Escalation"],
        "url": "https://attack.mitre.org/techniques/T1055/",
    },
    "T1059.001": {
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactics": ["Execution"],
        "url": "https://attack.mitre.org/techniques/T1059/001/",
    },
    "T1083": {
        "name": "File and Directory Discovery",
        "tactics": ["Discovery"],
        "url": "https://attack.mitre.org/techniques/T1083/",
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactics": ["Command and Control"],
        "url": "https://attack.mitre.org/techniques/T1105/",
    },
    "T1112": {
        "name": "Modify Registry",
        "tactics": ["Defense Evasion"],
        "url": "https://attack.mitre.org/techniques/T1112/",
    },
    "T1204.002": {
        "name": "User Execution: Malicious File",
        "tactics": ["Execution"],
        "url": "https://attack.mitre.org/techniques/T1204/002/",
    },
    "T1490": {
        "name": "Inhibit System Recovery",
        "tactics": ["Impact"],
        "url": "https://attack.mitre.org/techniques/T1490/",
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactics": ["Impact"],
        "url": "https://attack.mitre.org/techniques/T1486/",
    },
    "T1547.001": {
        "name": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
        "tactics": ["Persistence", "Privilege Escalation"],
        "url": "https://attack.mitre.org/techniques/T1547/001/",
    },
    "T1562.001": {
        "name": "Impair Defenses: Disable or Modify Tools",
        "tactics": ["Defense Evasion"],
        "url": "https://attack.mitre.org/techniques/T1562/001/",
    },
}

API_INTENT_ATTACK_MAP = {
    "process-injection": [("T1055", 0.92, "API family shows remote memory modification or execution primitives.")],
    "ransomware-file-impact": [
        ("T1486", 0.78, "API family can enumerate and rewrite user files, matching ransomware impact preparation."),
        ("T1083", 0.64, "File enumeration APIs support local file discovery."),
    ],
    "crypto-impact": [("T1486", 0.58, "Cryptographic APIs are relevant to encryption-for-impact triage.")],
    "network-staging": [("T1105", 0.65, "Network/download APIs support payload staging or retrieval.")],
    "persistence-control": [
        ("T1547.001", 0.68, "Registry/service control APIs can support logon persistence."),
        ("T1112", 0.52, "Registry modification APIs can alter system or application configuration."),
    ],
}

TOKEN_ATTACK_MAP = {
    "powershell -enc": [("T1059.001", 0.92, "Encoded PowerShell is a common script execution and obfuscation pattern."), ("T1027", 0.68, "Encoded command content indicates obfuscation.")],
    "frombase64string": [("T1027", 0.72, "Base64 decoding is commonly used to hide payload content.")],
    "invoke-expression": [("T1059.001", 0.84, "Invoke-Expression executes dynamically constructed PowerShell.")],
    "downloadstring": [("T1105", 0.78, "DownloadString can retrieve remote payloads.")],
    "vssadmin delete shadows": [("T1490", 0.96, "Shadow copy deletion inhibits local recovery.")],
    "bcdedit /set": [("T1490", 0.74, "Boot configuration changes can impair recovery or safe boot options.")],
    "regsvr32": [("T1204.002", 0.55, "Regsvr32 often appears in scriptlet or file execution chains.")],
    "rundll32": [("T1204.002", 0.48, "Rundll32 can execute DLL payloads through a user-launched file chain.")],
    "wevtutil cl": [("T1562.001", 0.76, "Clearing event logs impairs defensive visibility.")],
    "schtasks /create": [("T1547.001", 0.62, "Scheduled or startup execution can establish persistence.")],
    "disableantispyware": [("T1562.001", 0.88, "Security tooling modification impairs defenses.")],
}

API_ATTACK_MAP = {
    "virtualalloc": [("T1055", 0.45, "Memory allocation can support injection or unpacking.")],
    "virtualallocex": [("T1055", 0.72, "Remote process memory allocation supports process injection.")],
    "writeprocessmemory": [("T1055", 0.86, "Writing into another process is a strong injection primitive.")],
    "createremotethread": [("T1055", 0.9, "Remote thread creation is a strong injection primitive.")],
    "urldownloadtofilew": [("T1105", 0.7, "Downloader API can transfer tools or payloads.")],
    "internetopena": [("T1105", 0.45, "WinINet usage can support payload staging.")],
    "internetreadfile": [("T1105", 0.48, "Network read API can support payload transfer.")],
    "cryptencrypt": [("T1486", 0.52, "Encryption API is relevant to ransomware triage when paired with file-impact signals.")],
    "findfirstfilew": [("T1083", 0.5, "File enumeration supports local discovery.")],
    "findnextfilew": [("T1083", 0.5, "File enumeration supports local discovery.")],
}


def technique_summary(technique_ids: list[str]) -> str:
    parts = []
    for technique_id in technique_ids:
        technique = ATTACK_TECHNIQUES.get(technique_id, {})
        name = technique.get("name", technique_id)
        parts.append(f"{technique_id} {name}")
    return "; ".join(parts)


def correlate_scan_result(result: Any) -> dict[str, Any]:
    payload = result.to_dict() if hasattr(result, "to_dict") else dict(result)
    hits = payload.get("hits", []) or []
    techniques: dict[str, dict[str, Any]] = {}
    for hit in hits:
        _apply_hit_mapping(techniques, hit)
    ordered = sorted(
        techniques.values(),
        key=lambda item: (-float(item["confidence"]), item["technique_id"]),
    )
    return {
        "version": ATTACK_VERSION,
        "techniques": ordered,
        "tactics": sorted({tactic for item in ordered for tactic in item.get("tactics", [])}),
        "summary": technique_summary([item["technique_id"] for item in ordered[:4]]),
    }


def explain_scan_result(result: Any) -> dict[str, Any]:
    payload = result.to_dict() if hasattr(result, "to_dict") else dict(result)
    hits = payload.get("hits", []) or []
    raw_total = sum(max(0, int(hit.get("score", 0))) for hit in hits)
    final_score = int(payload.get("score", 0) or 0)
    contributions = []
    for hit in sorted(hits, key=lambda item: int(item.get("score", 0)), reverse=True):
        score = max(0, int(hit.get("score", 0)))
        contributions.append(
            {
                "category": hit.get("category", ""),
                "source": hit.get("source", "heuristic"),
                "points": score,
                "weight_percent": round((score / raw_total) * 100, 1) if raw_total else 0.0,
                "evidence": hit.get("evidence", ""),
                "explanation": hit.get("explanation", ""),
            }
        )
    caps = [item for item in hits if item.get("category") == "trusted-publisher"]
    return {
        "model": "weighted-evidence-v1",
        "raw_score": min(raw_total, 100),
        "final_score": final_score,
        "score_delta": final_score - min(raw_total, 100),
        "confidence": _score_confidence(final_score, contributions),
        "top_contributions": contributions[:6],
        "counter_evidence": [
            {
                "category": item.get("category", ""),
                "evidence": item.get("evidence", ""),
                "explanation": item.get("explanation", ""),
            }
            for item in caps
        ],
    }


def correlate_incident(incident: dict[str, Any]) -> dict[str, Any]:
    techniques: dict[str, dict[str, Any]] = {}
    reason = str(incident.get("reason", ""))
    signals = incident.get("signals", {}) or {}
    actions = incident.get("actions", []) or []
    evidence = incident.get("evidence", []) or []
    if reason in {"ransomware_burst", "canary_touched"}:
        _add_technique(techniques, "T1486", 0.92, "Incident reflects encryption-for-impact telemetry: canary touch or rapid sensitive file burst.")
    if int(signals.get("directory_count", 0) or 0) >= 2:
        _add_technique(techniques, "T1083", 0.62, "Multiple folders touched imply file discovery or traversal.")
    if "panic_mode_requested" in actions:
        _add_technique(techniques, "T1490", 0.54, "Containment was requested because the behavior could impair recovery or availability.")
    for item in evidence:
        lowered = str(item).casefold()
        for token, mappings in TOKEN_ATTACK_MAP.items():
            if token in lowered:
                for technique_id, confidence, rationale in mappings:
                    _add_technique(techniques, technique_id, confidence, rationale)
    ordered = sorted(techniques.values(), key=lambda item: (-float(item["confidence"]), item["technique_id"]))
    return {
        "version": ATTACK_VERSION,
        "techniques": ordered,
        "tactics": sorted({tactic for item in ordered for tactic in item.get("tactics", [])}),
        "summary": technique_summary([item["technique_id"] for item in ordered[:4]]),
    }


def explain_incident(incident: dict[str, Any]) -> dict[str, Any]:
    signals = incident.get("signals", {}) or {}
    score = int(incident.get("behavior_score", 0) or 0)
    contributions = [
        ("sensitive_file_count", int(signals.get("sensitive_file_count", 0) or 0), "Sensitive files observed in the incident window."),
        ("directory_count", int(signals.get("directory_count", 0) or 0), "Distinct folders increase ransomware confidence."),
        ("extension_count", int(signals.get("extension_count", 0) or 0), "Multiple extension families reduce benign single-workflow likelihood."),
        ("burst_rate_per_second", float(signals.get("burst_rate_per_second", 0) or 0), "Higher file-change rate increases behavioral confidence."),
        ("recovery_coverage_percent", int(signals.get("recovery_coverage_percent", 0) or 0), "Recovery copies explain what data was preserved before containment."),
    ]
    return {
        "model": incident.get("behavior_model", "ransomware-behavior-score"),
        "final_score": score,
        "confidence": incident.get("confidence", _score_confidence(score, [])),
        "top_contributions": [
            {"signal": name, "value": value, "explanation": explanation}
            for name, value, explanation in contributions
        ],
        "counter_evidence": _incident_counter_evidence(incident),
    }


def build_incident_graph(incident: dict[str, Any]) -> dict[str, Any]:
    attack = incident.get("attack") or correlate_incident(incident)
    incident_id = str(incident.get("id", "incident"))
    nodes = [
        {"id": incident_id, "type": "incident", "label": incident.get("reason", "incident")},
    ]
    edges = []
    signals = incident.get("signals", {}) or {}
    for signal in ["sensitive_file_count", "directory_count", "extension_count", "burst_rate_per_second"]:
        if signal in signals:
            node_id = f"signal:{signal}"
            nodes.append({"id": node_id, "type": "signal", "label": f"{signal}={signals.get(signal)}"})
            edges.append({"source": node_id, "target": incident_id, "relation": "supports"})
    for technique in attack.get("techniques", [])[:6]:
        node_id = f"attack:{technique['technique_id']}"
        nodes.append({"id": node_id, "type": "technique", "label": f"{technique['technique_id']} {technique['name']}"})
        edges.append({"source": incident_id, "target": node_id, "relation": "maps_to"})
    for action in incident.get("actions", []) or []:
        node_id = f"action:{action}"
        nodes.append({"id": node_id, "type": "action", "label": action})
        edges.append({"source": incident_id, "target": node_id, "relation": "triggered"})
    for index, path in enumerate((incident.get("related_paths", []) or [])[:5], start=1):
        node_id = f"file:{index}"
        nodes.append({"id": node_id, "type": "file", "label": Path(path).name or path})
        edges.append({"source": incident_id, "target": node_id, "relation": "affected"})
    return {"nodes": nodes, "edges": edges}


def _apply_hit_mapping(techniques: dict[str, dict[str, Any]], hit: dict[str, Any]) -> None:
    category = str(hit.get("category", "")).casefold()
    evidence = str(hit.get("evidence", "")).casefold()
    if category == "api-intent":
        family = evidence.split(":", 1)[0].strip()
        for technique_id, confidence, rationale in API_INTENT_ATTACK_MAP.get(family, []):
            _add_technique(techniques, technique_id, confidence, rationale, evidence=hit.get("evidence", ""))
    if category == "api-behavior":
        api = evidence.strip().casefold()
        for technique_id, confidence, rationale in API_ATTACK_MAP.get(api, []):
            _add_technique(techniques, technique_id, confidence, rationale, evidence=hit.get("evidence", ""))
    if category in {"packed-section", "packed-section-name", "pe-overlay", "sparse-imports", "entropy"}:
        _add_technique(techniques, "T1027", 0.58, "Packing, overlay, sparse imports or high entropy can indicate obfuscation.", evidence=hit.get("evidence", ""))
    if category == "location" and "startup" in evidence:
        _add_technique(techniques, "T1547.001", 0.64, "Startup folder location indicates logon persistence potential.", evidence=hit.get("evidence", ""))
    if category == "location" and ("downloads" in evidence or "temp" in evidence):
        _add_technique(techniques, "T1204.002", 0.38, "User-writable download/temp location can participate in user execution chains.", evidence=hit.get("evidence", ""))
    if category == "extension" and evidence in {".exe", ".scr", ".msi", ".lnk"}:
        _add_technique(techniques, "T1204.002", 0.42, "Executable file type can be launched by the user or a parent process.", evidence=hit.get("evidence", ""))
    if category == "content":
        for token, mappings in TOKEN_ATTACK_MAP.items():
            if token in evidence:
                for technique_id, confidence, rationale in mappings:
                    _add_technique(techniques, technique_id, confidence, rationale, evidence=hit.get("evidence", ""))


def _add_technique(
    techniques: dict[str, dict[str, Any]],
    technique_id: str,
    confidence: float,
    rationale: str,
    evidence: str = "",
) -> None:
    meta = ATTACK_TECHNIQUES.get(technique_id, {"name": technique_id, "tactics": [], "url": ""})
    existing = techniques.get(technique_id)
    if existing:
        existing["confidence"] = round(max(float(existing["confidence"]), confidence), 2)
        if rationale not in existing["rationale"]:
            existing["rationale"].append(rationale)
        if evidence:
            existing["evidence"].append(evidence)
        return
    techniques[technique_id] = {
        "technique_id": technique_id,
        "name": meta["name"],
        "tactics": meta["tactics"],
        "url": meta["url"],
        "confidence": round(confidence, 2),
        "rationale": [rationale],
        "evidence": [evidence] if evidence else [],
    }


def _score_confidence(score: int, contributions: list[dict[str, Any]]) -> str:
    if score >= 88:
        return "high"
    if score >= 72:
        return "medium-high"
    if score >= 48:
        return "medium"
    if contributions:
        return "low"
    return "none"


def _incident_counter_evidence(incident: dict[str, Any]) -> list[dict[str, str]]:
    actions = incident.get("actions", []) or []
    signals = incident.get("signals", {}) or {}
    counter: list[dict[str, str]] = []
    if actions == ["recovery_evidence_preserved"]:
        counter.append({"signal": "no_containment", "explanation": "Observed-only incident: NovaSentinel preserved evidence without freezing folders or stopping apps."})
    event_kinds = signals.get("event_kinds", {}) or {}
    if event_kinds and not event_kinds.get("modified") and not event_kinds.get("moved"):
        counter.append({"signal": "create_only_burst", "explanation": "Create-only bursts are less consistent with active file encryption."})
    return counter
