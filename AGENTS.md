# AGENTS.md — AI Agent Operating Instructions

> **Repository:** `android-enterprise-security-lab`
> **Scope:** AI Dev Agents, Automated Reviewers, and Coding Assistants
> **Governance:** Non-destructive Security Research, Diagnostic Tooling, and Static/Dynamic Analysis Frameworks

---

## 1. Executive Directive & Mission Scope

This repository provides an open-source, non-destructive diagnostic framework and educational environment for analyzing **Android Mobile Device Management (MDM)**, **DevicePolicyManager (DPM) APIs**, and **Hardware-Backed Root of Trust architectures**.

### Permitted Agent Tasks
- Developing read-only diagnostic utilities (Python, Bash, Kotlin/Android).
- Writing and refining static analysis, policy inspection, and telemetry auditing tools.
- Generating i18n translation assets and modern frontend landing pages.
- Maintaining documentation (`README.md`, `Architecture.md`, `CONTRIBUTING.md`).
- Formatting, refactoring, and optimizing codebase structure and automated tests.

### Forbidden Agent Actions
- **No Weaponization:** Do NOT generate fully automated exploit payloads, zero-day lock bypasses, or offensive malware targeting commercial MDM software (e.g., Knox Guard, PayJoy, or carrier locks).
- **No Credential Harvesting:** Do NOT write features designed to bypass user consent or exfiltrate private personal data from target devices.
- **No Destruction:** Do NOT write scripts that corrupt device storage partitions (`/dev/block/*`), brick bootloaders, or bypass hardware eFuses.

---

## 2. Environment & Repository Architecture

Agents operating within this workspace must strictly follow the repository layout:

```text
android-enterprise-security-lab/
├── .github/
│   └── workflows/          # CI/CD and deployment workflows
├── website/                # Web landing page (Tailwind CSS, i18n index.html)
├── core/                   # Core Python inspection modules & analysis tools
├── scripts/                # Shell scripts for rapid Linux/macOS ADB diagnostics
├── docs/                   # Security architecture specifications
├── output/                 # Local directory for generated JSON audit reports (git-ignored)
├── AGENTS.md               # AI Agent operating directives (This file)
├── README.md               # Main project README
└── LICENSE                 # Apache License 2.0

```

---

## 3. Code Style & Technical Standards

### A. Python Standards (`core/`)

* **Version:** Python 3.9+ compatible.
* **Type Hints:** Mandatory type annotations on all function signatures (`typing.Dict`, `typing.List`, `typing.Optional`, etc.).
* **Error Handling:** Graceful subprocess execution handling (`subprocess.CalledProcessError`, `FileNotFoundError`). Never allow raw tracebacks when handling standard ADB disconnections.
* **Output Standard:** Tools must output structured, formatted JSON when exporting audit reports.

### B. Shell Scripting (`scripts/`)

* **Interpreter:** `#!/usr/bin/env bash` with strict error handling flags (`set -euo pipefail`).
* **Compatibility:** Portable across Linux and macOS environments.
* **UI Output:** Use standard ANSI color variables (`RED`, `GREEN`, `YELLOW`, `BLUE`, `NC`) for terminal formatting.

### C. Web Frontend (`website/`)

* **Structure:** Single-file HTML design (`index.html`) using CDN-loaded Tailwind CSS.
* **Localization:** Pure vanilla JavaScript i18n dictionary objects supporting `English`, `Bengali (বাংলা)`, and `Spanish (Español)`.
* **Accessibility & UX:** Fully responsive dark-mode UI with clean glassmorphic components.

---

## 4. Execution & Testing Protocol

Before submitting a Pull Request (PR) or committing changes, AI Agents must run local validation steps:

```bash
# 1. Validate Python Syntax and Typing
python3 -m py_compile core/mdm_inspector.py

# 2. Check Shell Script Syntax
bash -n scripts/adb_check.sh

# 3. Dry-Run Inspection Utility (Requires ADB or mock connection)
python3 core/mdm_inspector.py --help

```

---

## 5. Security & Ethical Boundaries

AI Agents must enforce the following ethical principles:

1. **Safety First:** Maintain the Apache 2.0 open-source licensing compliance and preserve all legal disclaimers.
2. **Defensive Focus:** Frame all outputs, code comments, and documentation toward **security research, system administration, and diagnostic auditing**.
3. **Target Sanitization:** Replace explicit PII, hardware MAC addresses, or real customer device identifiers with standard safe placeholders (e.g., `192.168.1.1`, `00:11:22:33:44:55`, `com.example.mdm`).

---

## 6. Self-Correction & Verification Checklist

When generating or modifying code in this project, verify:

* [ ] Is all code non-destructive and safe for research environments?
* [ ] Does the code run without throwing unhandled exceptions when no device is connected?
* [ ] Is documentation up to date with new flags or modules introduced?
* [ ] Are type hints and error handlers properly implemented?
