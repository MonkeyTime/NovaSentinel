from __future__ import annotations


RESEARCH_NOTES = [
    {
        "title": "DawnGNN: Documentation augmented windows malware detection using graph neural network",
        "date": "2024-02-29",
        "source": "Computers & Security",
        "url": "https://doi.org/10.1016/j.cose.2024.103788",
        "theme": "API semantics and graph-style malware reasoning",
        "idea": "Use API semantics and relationships instead of only file signatures.",
        "implemented": "PE import scoring, suspicious API semantics, and readable evidence attached to scan hits.",
        "status": "integrated",
    },
    {
        "title": "Large Language Models for Cyber Security: A Systematic Literature Review",
        "date": "2024-05-08",
        "source": "arXiv / TOSEM accepted",
        "url": "https://doi.org/10.48550/arXiv.2405.04760",
        "theme": "Explainable analyst support",
        "idea": "Autonomous multi-step security workflows and explainable analyst support are rising trends.",
        "implemented": "Trust Center, incident timeline, evidence rows, and current-scan threat explanations.",
        "status": "integrated",
    },
    {
        "title": "Evaluation and Detection of Adversarial Attacks for ML-based NIDS",
        "date": "2024-01-01",
        "source": "PhD thesis, Newcastle University",
        "url": "http://hdl.handle.net/10443/6504",
        "theme": "Adversarial resilience",
        "idea": "Modern AI detectors need adversarial resilience and threat-model thinking, not only accuracy.",
        "implemented": "Layered scoring keeps static signals, behavior signals, and user-space containment separate.",
        "status": "integrated",
    },
    {
        "title": "XAPID: An Explainable AI Framework for Behavior-based Malware Detection via Windows API Calls",
        "date": "2025-01-01",
        "source": "Thesis, University of Nevada Reno",
        "url": "https://scholarwolf.unr.edu/entities/thesis/7fbb5918-b895-4c77-8532-cae2333e06f9",
        "theme": "Explainable Windows API behavior",
        "idea": "Windows API behavior plus human-readable explanation is useful for desktop malware triage.",
        "implemented": "API import evidence is grouped into intent families such as injection, file impact, crypto, staging and persistence.",
        "status": "integrated",
    },
    {
        "title": "Ransomware Detection Using Windows API Calls and Machine Learning",
        "date": "2023-04-24",
        "source": "Thesis, Virginia Tech",
        "url": "https://vtechworks.lib.vt.edu/items/0cf2c98c-183c-4fce-a116-8f01ba3c5cd7",
        "theme": "Windows API call ransomware profiles",
        "idea": "Ransomware can be characterized by API presence/frequency patterns even before heavy dynamic analysis.",
        "implemented": "NovaSentinel maps PE imports into risk-aware API intent families for user-space triage.",
        "status": "integrated",
    },
    {
        "title": "Machine Learning-Based Ransomware Detection Through Static Analysis of PE File Features",
        "date": "2025-01-01",
        "source": "Thesis, Theseus",
        "url": "https://urn.fi/URN:NBN:fi:amk-2025080623818",
        "theme": "Static PE ransomware signals",
        "idea": "PE entropy, imports and structural features can provide low-false-positive ransomware signals.",
        "implemented": "PE entropy, section count, sparse imports, overlay size, suspicious section names, timestamps and extension scoring.",
        "status": "integrated",
    },
    {
        "title": "Generating Adversarial Malware Examples Using Particle Swarm Optimization",
        "date": "2023-12-01",
        "source": "Thesis, Rochester Institute of Technology",
        "url": "https://repository.rit.edu/theses/11515/",
        "theme": "API substitution and adversarial evasion",
        "idea": "Attackers can replace exact API calls with semantically equivalent alternatives to evade brittle detectors.",
        "implemented": "NovaSentinel scores API intent families rather than relying only on one exact import name.",
        "status": "integrated",
    },
    {
        "title": "Enhancing Ransomware Threat Detection: Risk-Aware Classification via Windows API Call Analysis and Hybrid ML/DL Models",
        "date": "2025-11-05",
        "source": "Journal of Cybersecurity and Privacy",
        "url": "https://doi.org/10.3390/jcp5040096",
        "theme": "Risk-aware ransomware behavior",
        "idea": "Ransomware behavior should be scored with threat severity, API patterns and cross-source generalization in mind.",
        "implemented": "Ransomware incidents now record behavior score, confidence, tags, timeline and affected files.",
        "status": "integrated",
    },
    {
        "title": "Machine Learning-Based Static Ransomware Detection Using PE Header Features and SHAP Interpretation",
        "date": "2026-04-01",
        "source": "Journal of Cybersecurity and Privacy",
        "url": "https://www.mdpi.com/2624-800X/6/2/58",
        "theme": "Interpretable PE header features",
        "idea": "Static PE header features remain useful when the detector exposes interpretable feature importance.",
        "implemented": "NovaSentinel surfaces each scoring reason as evidence instead of a black-box score only.",
        "status": "integrated",
    },
    {
        "title": "XAI-Driven Malware Detection from Memory Artifacts: An Alert-Driven AI Framework with TabNet and Ensemble Classification",
        "date": "2026-02-10",
        "source": "MDPI AI",
        "url": "https://doi.org/10.3390/ai7020066",
        "theme": "Post-alert forensic depth",
        "idea": "Post-alert forensic depth can be layered after a fast detector instead of running all heavy checks inline.",
        "implemented": "Post-alert enrichment captures matching process context, open files, connections and mapped modules without slowing first-pass scanning.",
        "status": "integrated",
    },
    {
        "title": "An Explainable Memory Forensics Approach for Malware Analysis",
        "date": "2026-02-23",
        "source": "arXiv",
        "url": "https://doi.org/10.48550/arXiv.2602.19831",
        "theme": "Explainable memory forensics",
        "idea": "Memory analysis can recover volatile artifacts and should remain understandable to analysts.",
        "implemented": "Alert records can now include bounded process and memory-map evidence for analyst review.",
        "status": "integrated",
    },
    {
        "title": "Using Memory Forensics to Analyze Programming Language Runtimes",
        "date": "2022-01-01",
        "source": "Doctoral dissertation, Louisiana State University",
        "url": "https://repository.lsu.edu/gradschool_dissertations/5737/",
        "theme": "Runtime and memory artifacts",
        "idea": "Language runtime artifacts can provide useful malware context after an alert.",
        "implemented": "NovaSentinel collects child processes and mapped modules after high-risk alerts while staying user-space.",
        "status": "integrated",
    },
]


def research_summary(language: str | None = None) -> str:
    french = language == "fr"
    lines = _intro_lines(french)
    lines.append("")
    for note in RESEARCH_NOTES:
        status = _status_label(note["status"], french)
        lines.append(f"- {note['date']} | {status} | {note['title']} ({note['source']})")
        lines.append(f"  {_label('Theme', french)}: {note['theme']}")
        lines.append(f"  {_label('Research takeaway', french)}: {note['idea']}")
        lines.append(f"  {_label('NovaSentinel integration', french)}: {note['implemented']}")
        lines.append(f"  {note['url']}")
    lines.append("")
    lines.extend(_closing_lines(french))
    return "\n".join(lines)


def _intro_lines(french: bool) -> list[str]:
    if french:
        return [
            "NovaSentinel n'est pas presente comme un antivirus a signatures classique.",
            "Cette page relie chaque fonction importante a une piste de recherche recente : familles d'intention API, signaux PE, comportement ransomware, canaris, telemetrie et analyse post-alerte.",
        ]
    return [
        "NovaSentinel is designed around recent detection themes rather than a legacy signature-only model.",
        "This page maps the research lineage to concrete product decisions: API intent families, PE signals, ransomware behavior, canaries, telemetry and post-alert analysis.",
    ]


def _closing_lines(french: bool) -> list[str]:
    if french:
        return [
            "Position actuelle:",
            "- Integre: familles d'intention API, heuristiques statiques, signaux PE enrichis, scoring comportemental, canaris, rafales ransomware, preuves lisibles et Trust Center.",
            "- Roadmap: correlation plus profonde avec MITRE ATT&CK, graphe d'incident et explications XAI plus detaillees.",
        ]
    return [
        "Current position:",
        "- Integrated: API intent families, static heuristics, enriched PE signals, behavior scoring, canaries, ransomware bursts, readable evidence and Trust Center.",
        "- Roadmap: deeper MITRE ATT&CK correlation, incident graphing, and richer XAI explanations.",
    ]


def _label(text: str, french: bool) -> str:
    if not french:
        return text
    labels = {
        "Theme": "Theme",
        "Research takeaway": "Apport recherche",
        "NovaSentinel integration": "Integration NovaSentinel",
    }
    return labels[text]


def _status_label(status: str, french: bool) -> str:
    if status == "integrated":
        return "integre" if french else "integrated"
    if status == "roadmap":
        return "piste suivante" if french else "roadmap"
    return status
