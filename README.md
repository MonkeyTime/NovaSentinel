# NovaSentinel

NovaSentinel is an original Windows 11 antivirus built as a modern, explainable desktop defender rather than a legacy signature-only scanner. It runs in the background, exposes a tray icon, keeps an interactive desktop console, monitors risky user-writeable locations in real time, quarantines high-confidence threats, and includes a lightweight anti-ransomware layer based on canary files and burst detection.

## What it includes

- Background Windows app launched with `pythonw` through [`launch_novaguard.pyw`](C:\Users\admin\Documents\antivirus\launch_novaguard.pyw)
- Tray icon with open, quick-scan, protection toggle, and exit actions
- Windows 11-style desktop interface built with `customtkinter`
- Hybrid file scoring:
  - static PE structure signals
  - suspicious command and content pattern detection
  - API intent families inspired by Windows API malware and adversarial-evasion research
  - entropy-based packed binary detection
  - enriched PE features: section count, suspicious section names, overlay size, timestamp anomalies and sparse imports
  - risky location awareness for startup, temp, and user-writeable folders
- Background process launch scoring via `psutil`
- Real-time monitoring via `watchdog`
- Automatic quarantine with restore/delete actions
- Ransomware safeguards:
  - canary files
  - rapid document-modification burst detection
  - emergency containment hook
- Post-alert enrichment for high-risk detections:
  - matching process snapshot
  - child process list
  - open files and network connections when visible to user-space
  - mapped memory modules and suspicious user-writable DLL mappings
- Dedicated Forensics panel for reviewing enriched post-alert evidence
- Research panel inside the UI with the design lineage

## Research basis

The architecture was intentionally aligned with current research directions that stayed relevant through 2024-2026:

- `2024-02-29` [DawnGNN](https://doi.org/10.1016/j.cose.2024.103788): Windows malware detection can benefit from API semantics and graph-style reasoning, not just raw signatures.
- `2024-05-08` [Large Language Models for Cyber Security: A Systematic Literature Review](https://doi.org/10.48550/arXiv.2405.04760): autonomous multi-step security workflows and explainable analyst support are increasingly important.
- `2024` [Evaluation and Detection of Adversarial Attacks for ML-based NIDS](http://hdl.handle.net/10443/6504): resilience against evasion and adversarial thinking matters alongside raw detector accuracy.
- `2025` [XAPID: An Explainable AI Framework for Behavior-based Malware Detection via Windows API Calls](https://scholarwolf.unr.edu/entities/thesis/7fbb5918-b895-4c77-8532-cae2333e06f9): behavior-based Windows API reasoning should stay explainable for human triage.
- `2023` [Ransomware Detection Using Windows API Calls and Machine Learning](https://vtechworks.lib.vt.edu/items/0cf2c98c-183c-4fce-a116-8f01ba3c5cd7): API call presence/frequency can form practical ransomware behavior profiles.
- `2025` [Machine Learning-Based Ransomware Detection Through Static Analysis of PE File Features](https://urn.fi/URN:NBN:fi:amk-2025080623818): entropy, imports and structural PE features remain practical low-false-positive signals for ransomware-oriented screening.
- `2023` [Generating Adversarial Malware Examples Using Particle Swarm Optimization](https://repository.rit.edu/theses/11515/): exact API-name detectors are brittle, so NovaSentinel groups semantically similar APIs into intent families.
- `2025-11-05` [Enhancing Ransomware Threat Detection](https://doi.org/10.3390/jcp5040096): ransomware detection benefits from risk-aware behavior scoring, API patterns, and cross-source validation.
- `2026` [Machine Learning-Based Static Ransomware Detection Using PE Header Features and SHAP Interpretation](https://www.mdpi.com/2624-800X/6/2/58): static PE features are more useful when the detector exposes interpretable evidence.
- `2026-02-10` [XAI-Driven Malware Detection from Memory Artifacts](https://www.mdpi.com/2673-2688/7/2/66): deep forensic steps are often best used as a second stage after a fast initial alert; NovaSentinel now performs bounded post-alert process/memory enrichment.
- `2026-02-23` [An Explainable Memory Forensics Approach for Malware Analysis](https://doi.org/10.48550/arXiv.2602.19831): memory/process artifacts can be attached to alerts in a readable way.
- `2022` [Using Memory Forensics to Analyze Programming Language Runtimes](https://repository.lsu.edu/gradschool_dissertations/5737/): runtime and memory artifacts are useful post-alert context for suspicious processes.

The in-app Research panel maps each source to what is already integrated and what remains roadmap work.

## Install

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\install_windows.ps1 -RunNow
```

## Run manually

```powershell
.venv\Scripts\pythonw.exe .\launch_novaguard.pyw
```

## Build an executable

```powershell
.\scripts\build_windows.ps1 -Clean
```

The executable output is placed in `dist\NovaSentinel\NovaSentinel.exe`.

## Build a Windows installer

```powershell
.\scripts\build_installer.ps1
```

The installer output is placed in the `release\` folder with a timestamped filename.

## Limits

NovaSentinel is a serious host-based protection project, but it is still a user-space antivirus, not a signed kernel EDR product. It does not yet ship a kernel mini-filter, an AMSI provider, ETW consumers, or a cloud reputation backend.
