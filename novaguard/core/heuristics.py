from __future__ import annotations

import hashlib
import math
import os
import subprocess
from datetime import datetime
from pathlib import Path
from time import time

import pefile

import novaguard.config as config
from novaguard.attack import correlate_scan_result, explain_scan_result
from novaguard.models import DetectionHit, ScanResult


HIGH_RISK_EXTENSIONS = {
    ".exe": 18,
    ".dll": 16,
    ".scr": 20,
    ".msi": 16,
    ".ps1": 24,
    ".bat": 22,
    ".cmd": 22,
    ".vbs": 24,
    ".js": 20,
    ".hta": 24,
    ".jar": 14,
    ".lnk": 14,
    ".py": 10,
    ".pyw": 10,
}

SUSPICIOUS_STRINGS = {
    "powershell -enc": 24,
    "frombase64string": 20,
    "invoke-expression": 18,
    "downloadstring": 18,
    "vssadmin delete shadows": 28,
    "bcdedit /set": 22,
    "regsvr32": 14,
    "rundll32": 12,
    "wevtutil cl": 18,
    "schtasks /create": 16,
    "disableantispyware": 20,
    "eicar-standard-antivirus-test-file": 95,
}

SUSPICIOUS_IMPORTS = {
    "VirtualAlloc": 10,
    "WriteProcessMemory": 14,
    "CreateRemoteThread": 16,
    "WinExec": 10,
    "ShellExecuteW": 8,
    "URLDownloadToFileW": 14,
    "InternetOpenA": 10,
    "InternetReadFile": 10,
    "SetWindowsHookExW": 12,
    "CryptEncrypt": 14,
    "FindFirstFileW": 8,
    "FindNextFileW": 8,
}

API_INTENT_FAMILIES = {
    "process-injection": {
        "imports": {
            "openprocess",
            "virtualalloc",
            "virtualallocex",
            "virtualprotect",
            "writeprocessmemory",
            "createremotethread",
            "queueuserapc",
            "ntwritevirtualmemory",
        },
        "score": 18,
        "minimum": 2,
        "explanation": "Imported APIs cluster around process memory modification or remote execution.",
    },
    "ransomware-file-impact": {
        "imports": {
            "createfilew",
            "writefile",
            "deletefilew",
            "movefileexw",
            "setfileattributesw",
            "findfirstfilew",
            "findnextfilew",
        },
        "score": 16,
        "minimum": 3,
        "explanation": "Imported APIs cluster around file enumeration, rewriting, deletion or attribute changes.",
    },
    "crypto-impact": {
        "imports": {
            "cryptacquirecontexta",
            "cryptacquirecontextw",
            "cryptencrypt",
            "cryptgenrandom",
            "bcryptencrypt",
            "bcryptgenrandom",
        },
        "score": 14,
        "minimum": 1,
        "explanation": "Imported APIs indicate cryptographic operations relevant to ransomware triage.",
    },
    "network-staging": {
        "imports": {
            "urldownloadtofilea",
            "urldownloadtofilew",
            "internetopena",
            "internetopenw",
            "internetreadfile",
            "winhttpopen",
            "winhttpsendrequest",
        },
        "score": 12,
        "minimum": 1,
        "explanation": "Imported APIs indicate downloader or network staging capability.",
    },
    "persistence-control": {
        "imports": {
            "regcreatekeyexa",
            "regcreatekeyexw",
            "regsetvalueexa",
            "regsetvalueexw",
            "createservicea",
            "createservicew",
            "startservicea",
            "startservicew",
        },
        "score": 12,
        "minimum": 1,
        "explanation": "Imported APIs align with persistence or service-control behavior.",
    },
}

LOCATION_RISK_MARKERS = {
    r"\appdata\local\temp": 12,
    r"\downloads": 8,
    r"\startup": 18,
    "\\public\\": 8,
}

SOURCE_OR_DOC_EXTENSIONS = {
    ".py",
    ".pyw",
    ".pyc",
    ".pyo",
    ".md",
    ".rst",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
}

PYTHON_EXECUTION_MARKERS = {
    b"subprocess.",
    b"os.system(",
    b"os.popen(",
    b"subprocess.run(",
    b"subprocess.popen(",
    b"base64.b64decode",
    b"eval(",
    b"exec(",
}

BENIGN_RUNTIME_SUFFIXES = {
    ".pyc",
    ".pyo",
}

RUNTIME_STATE_BASE_FILENAMES = {
    "settings.json",
    "history.json",
    "events.json",
    "incidents.json",
    "lockdown_state.json",
}
NO_WINDOW_FLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0)
TRUSTED_PUBLISHER_SUBJECTS = {
    "opera norway as",
    "microsoft corporation",
}
TRUSTED_PUBLISHER_SCORE_CAP = 46
HARD_MALICIOUS_CATEGORIES = {
    "content",
    "packed-section-name",
}
_SIGNATURE_CACHE: dict[tuple[str, int, int], str] = {}


def _is_same_or_child(path: Path, root: Path) -> bool:
    try:
        return path.resolve().is_relative_to(root.resolve())
    except (OSError, ValueError):
        return False


def _is_json_temp_name(name: str, base_name: str) -> bool:
    if name == f"{base_name}.tmp":
        return True
    if not name.startswith(f"{base_name}.") or not name.endswith(".tmp"):
        return False
    parts = name[len(base_name) + 1:-4].split(".")
    return bool(parts) and all(part.isdigit() for part in parts)


def is_runtime_state_candidate(path: Path) -> bool:
    name = path.name.casefold()
    is_state_file = any(
        name == base_name
        or name == f"{base_name}.bak"
        or _is_json_temp_name(name, base_name)
        for base_name in RUNTIME_STATE_BASE_FILENAMES
    )
    if is_state_file and _is_same_or_child(path, config.STATE_DIR):
        return True
    return False


def compute_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    entropy = 0.0
    length = len(data)
    for count in counts:
        if count:
            probability = count / length
            entropy -= probability * math.log2(probability)
    return entropy


def classify_severity(score: int) -> tuple[str, bool]:
    if score >= 88:
        return "critical", True
    if score >= 72:
        return "high", True
    if score >= 48:
        return "medium", False
    if score >= 24:
        return "low", False
    return "info", False


def read_sample(path: Path, size: int = 256 * 1024) -> bytes:
    try:
        with path.open("rb") as handle:
            return handle.read(size)
    except OSError:
        return b""


def add_hit(hits: list[DetectionHit], category: str, score: int, explanation: str, evidence: str, source: str = "heuristic") -> None:
    hits.append(
        DetectionHit(
            category=category,
            score=score,
            explanation=explanation,
            evidence=evidence,
            source=source,
        )
    )


def _powershell_signature_subject(path: Path) -> str:
    try:
        stat = path.stat()
    except OSError:
        return ""
    cache_key = (str(path).casefold(), int(stat.st_mtime), int(stat.st_size))
    if cache_key in _SIGNATURE_CACHE:
        return _SIGNATURE_CACHE[cache_key]
    env = dict(os.environ)
    env["NOVASENTINEL_SIGNATURE_PATH"] = str(path)
    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                (
                    "$sig = Get-AuthenticodeSignature -LiteralPath $env:NOVASENTINEL_SIGNATURE_PATH; "
                    "if ($sig.Status -eq 'Valid' -and $sig.SignerCertificate) { "
                    "$sig.SignerCertificate.Subject }"
                ),
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=4,
            env=env,
            creationflags=NO_WINDOW_FLAGS,
        )
    except (OSError, subprocess.TimeoutExpired):
        subject = ""
    else:
        subject = result.stdout.strip() if result.returncode == 0 else ""
    _SIGNATURE_CACHE[cache_key] = subject
    return subject


def trusted_publisher_subject(path: Path) -> str:
    if path.suffix.lower() not in {".exe", ".dll", ".scr", ".msi"}:
        return ""
    subject = _powershell_signature_subject(path)
    lowered = subject.casefold()
    if not subject:
        return ""
    if any(publisher in lowered for publisher in TRUSTED_PUBLISHER_SUBJECTS):
        return subject
    return ""


def apply_trusted_publisher_cap(path: Path, score: int, hits: list[DetectionHit]) -> int:
    if score < 72:
        return score
    if any(hit.category in HARD_MALICIOUS_CATEGORIES for hit in hits):
        return score
    subject = trusted_publisher_subject(path)
    if not subject:
        return score
    add_hit(
        hits,
        "trusted-publisher",
        0,
        "Valid Authenticode signature from a trusted desktop software publisher; capability-only PE signals were capped.",
        subject,
        source="trust-policy",
    )
    return min(score, TRUSTED_PUBLISHER_SCORE_CAP)


def _looks_like_benign_source_code(path: Path, lowered: bytes) -> bool:
    extension = path.suffix.lower()
    if extension not in SOURCE_OR_DOC_EXTENSIONS:
        return False
    if extension in BENIGN_RUNTIME_SUFFIXES:
        return True
    if extension in {".md", ".rst", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg"}:
        return True
    if extension in {".py", ".pyw"}:
        return any(token in lowered for token in [b"def ", b"class ", b"import ", b"from "])
    return False


def is_benign_python_artifact(path: Path) -> bool:
    extension = path.suffix.lower()
    if extension in BENIGN_RUNTIME_SUFFIXES:
        return True
    if "__pycache__" in {part.lower() for part in path.parts}:
        return True
    return ".cpython-" in path.name.lower()


def analyze_text_signals(path: Path, data: bytes, hits: list[DetectionHit]) -> None:
    lowered = data.lower()
    if _looks_like_benign_source_code(path, lowered):
        return
    for token, score in SUSPICIOUS_STRINGS.items():
        if token.encode("utf-8") in lowered:
            add_hit(
                hits,
                "content",
                score,
                "Embedded commands match common malicious or ransomware tradecraft.",
                token,
            )


def analyze_location(path: Path, hits: list[DetectionHit]) -> None:
    lowered = str(path).lower()
    for marker, score in LOCATION_RISK_MARKERS.items():
        if marker in lowered:
            add_hit(
                hits,
                "location",
                score,
                "File appeared in a user-writable location frequently abused by droppers and startup persistence.",
                marker,
            )


def analyze_extension(path: Path, hits: list[DetectionHit]) -> None:
    extension = path.suffix.lower()
    if extension in HIGH_RISK_EXTENSIONS:
        add_hit(
            hits,
            "extension",
            HIGH_RISK_EXTENSIONS[extension],
            "This executable or script type deserves elevated scrutiny.",
            extension,
        )


def analyze_entropy(path: Path, data: bytes, hits: list[DetectionHit]) -> None:
    extension = path.suffix.lower()
    if extension not in HIGH_RISK_EXTENSIONS and extension not in {".bin", ".dat"}:
        return
    entropy = shannon_entropy(data)
    if entropy >= 7.2:
        add_hit(hits, "entropy", 18, "High entropy can indicate packing, encryption, or obfuscation.", f"{entropy:.2f}")
    elif entropy >= 6.7:
        add_hit(hits, "entropy", 10, "Entropy is elevated compared with typical plain executables.", f"{entropy:.2f}")


def _normalized_import_name(name: str) -> str:
    return name.rsplit(".", 1)[0].casefold()


def _collect_imports(pe) -> list[str]:
    imports_seen: list[str] = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for item in entry.imports:
                if item.name:
                    imports_seen.append(item.name.decode("utf-8", errors="ignore"))
    return imports_seen


def analyze_api_intent_families(imports_seen: list[str], hits: list[DetectionHit]) -> None:
    normalized = {_normalized_import_name(name) for name in imports_seen}
    for family, profile in API_INTENT_FAMILIES.items():
        matched = sorted(normalized.intersection(profile["imports"]))
        if len(matched) < profile["minimum"]:
            continue
        add_hit(
            hits,
            "api-intent",
            int(profile["score"]),
            str(profile["explanation"]),
            f"{family}: {', '.join(matched[:8])}",
            source="api-intent-family",
        )


def _section_names(pe) -> list[str]:
    names: list[str] = []
    for section in getattr(pe, "sections", []):
        raw_name = getattr(section, "Name", b"")
        if isinstance(raw_name, bytes):
            names.append(raw_name.rstrip(b"\x00").decode("utf-8", errors="ignore").casefold())
        else:
            names.append(str(raw_name).casefold())
    return names


def analyze_pe_structure(path: Path, pe, imports_seen: list[str], hits: list[DetectionHit]) -> None:
    try:
        size = path.stat().st_size
    except OSError:
        size = 0
    section_count = len(getattr(pe, "sections", []))
    if section_count <= 2 and size > 120_000:
        add_hit(hits, "pe-structure", 8, "Large PE with very few sections can indicate packing or a loader stub.", f"{section_count} sections")
    elif section_count >= 10:
        add_hit(hits, "pe-structure", 8, "PE has an unusually high section count for a small desktop utility.", f"{section_count} sections")

    suspicious_section_names = {"upx", "upx0", "upx1", ".aspack", ".adata", ".packed", ".themida"}
    matched_names = sorted(set(_section_names(pe)).intersection(suspicious_section_names))
    if matched_names:
        add_hit(hits, "packed-section-name", 14, "Section names match common packer or obfuscator conventions.", ", ".join(matched_names))

    overlay_start = None
    try:
        overlay_start = pe.get_overlay_data_start_offset()
    except (AttributeError, OSError, ValueError):
        overlay_start = None
    if overlay_start and size > overlay_start:
        overlay_size = size - overlay_start
        if overlay_size > max(64_000, int(size * 0.25)):
            add_hit(hits, "pe-overlay", 10, "Large PE overlay can hide appended payloads or encrypted data.", str(overlay_size))

    timestamp = getattr(getattr(pe, "FILE_HEADER", None), "TimeDateStamp", None)
    if timestamp == 0:
        add_hit(hits, "pe-timestamp", 6, "PE timestamp is zeroed, which is common in packed or synthetic samples.", "0")
    elif isinstance(timestamp, int) and timestamp > int(time()) + 86_400:
        add_hit(hits, "pe-timestamp", 8, "PE timestamp is in the future, which can indicate tampering or synthetic build metadata.", str(timestamp))

    if not imports_seen and size > 80_000:
        add_hit(hits, "sparse-imports", 14, "Large executable with no visible imports can indicate packing or delayed API resolution.", "0")
    elif len(imports_seen) <= 6 and size > 180_000:
        add_hit(hits, "sparse-imports", 10, "Large executable with very sparse imports can indicate packing or delayed resolution.", str(len(imports_seen)))


def analyze_pe(path: Path, hits: list[DetectionHit]) -> None:
    if path.suffix.lower() not in {".exe", ".dll", ".scr"}:
        return
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories()
    except (pefile.PEFormatError, OSError):
        return
    try:
        entropies = [section.get_entropy() for section in pe.sections]
        if entropies and max(entropies) >= 7.4:
            add_hit(hits, "packed-section", 16, "One or more PE sections look heavily packed or encrypted.", f"max entropy {max(entropies):.2f}")
        imports_seen = _collect_imports(pe)
        for api_name, score in SUSPICIOUS_IMPORTS.items():
            if _normalized_import_name(api_name) in {_normalized_import_name(name) for name in imports_seen}:
                add_hit(
                    hits,
                    "api-behavior",
                    score,
                    "The binary imports APIs aligned with process injection, staging, crypto or persistence behavior.",
                    api_name,
                    source="api-semantics",
                )
        analyze_api_intent_families(imports_seen, hits)
        analyze_pe_structure(path, pe, imports_seen, hits)
    finally:
        pe.close()


def analyze_file(path: str | Path, max_file_size_mb: int = 64) -> ScanResult | None:
    target = Path(path)
    if is_runtime_state_candidate(target):
        return None
    if not target.exists() or target.is_dir():
        return None
    if is_benign_python_artifact(target):
        return None
    try:
        size = target.stat().st_size
    except OSError:
        return None
    if size > max_file_size_mb * 1024 * 1024:
        return None

    hits: list[DetectionHit] = []
    sample = read_sample(target)
    analyze_extension(target, hits)
    analyze_location(target, hits)
    analyze_entropy(target, sample, hits)
    analyze_text_signals(target, sample, hits)
    analyze_pe(target, hits)

    if size < 12_000 and target.suffix.lower() in {".exe", ".dll", ".scr"}:
        add_hit(hits, "size", 10, "Very small executable stubs are often used by downloaders or loaders.", str(size))

    score = min(sum(hit.score for hit in hits), 100)
    score = apply_trusted_publisher_cap(target, score, hits)
    severity, malicious = classify_severity(score)

    try:
        sha256 = compute_sha256(target)
    except OSError:
        sha256 = ""

    result = ScanResult(
        path=str(target),
        score=score,
        severity=severity,
        malicious=malicious,
        engine="NovaSentinel Hybrid Heuristics",
        sha256=sha256,
        file_size=size,
        scanned_at=datetime.now().isoformat(timespec="seconds"),
        hits=hits,
    )
    result.attack = correlate_scan_result(result)
    result.xai = explain_scan_result(result)
    return result
