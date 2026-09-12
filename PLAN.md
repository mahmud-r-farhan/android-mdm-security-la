
# PLAN.md — Project Roadmap & Development Plan

> **Repository:** `android-enterprise-security-lab`
> **Status:** Active Security Research & Diagnostic Tooling
> **Target Audience:** Security Researchers, Developers, System Administrators, and Educational Users

---

## 1. Vision & Core Objectives

The goal of **`android-enterprise-security-lab`** is to provide an open-source, non-destructive diagnostic suite and security research environment for analyzing Android Mobile Device Management (MDM), Device Policy Manager (DPM) APIs, and hardware-backed enforcement mechanisms (e.g., Samsung Knox Guard, PayJoy, and carrier locks).

### Primary Pillars
1. **Auditing & Inspection:** Non-destructive tools to detect Device Owner / Profile Owner privileges, DPM policy flags, and active MDM packages.
2. **End-User Accessibility:** Zero-friction automated setup wrappers (Windows / Linux / macOS) for non-technical users to inspect device state without manual command-line configuration.
3. **Security Research & Education:** Comprehensive technical documentation covering Android enterprise architectures, hardware root of trust, and attestation flows.

---

## 2. Multi-Phase Roadmap

### Phase 1: Foundational Inspection & Core Tooling (Current Status)
- [x] Initial repository architecture and LICENSE (Apache 2.0).
- [x] Core Python inspection engine (`core/mdm_inspector.py`) targeting ADB and DPM API responses.
- [x] Lightweight Bash diagnostic script (`scripts/adb_check.sh`) for rapid scanning on Linux/macOS.
- [x] Architectural documentation (`docs/Architecture.md`) detailing Device Policy Manager privileges and Knox Guard mechanisms.
- [x] Internationalized web landing page (`website/index.html`) with multi-language UI support (EN, BN, ES).
- [x] GitHub Actions automated deployment workflow (`.github/workflows/deploy.yml`) for GitHub Pages.
- [x] AI Agent operating guidelines (`AGENTS.md`).

---

### Phase 2: One-Click End-User Installer & Environment Automation ✅
- [x] **Windows Automated Setup Suite (`setup.ps1` / `setup.bat`):**
  - Automated detection, download, and extraction of Google's official `platform-tools`.
  - Automatic user `PATH` environment variable registration (no administrator rights required).
  - One-click launch wrapper (`setup.bat`) that runs setup and offers to launch the inspector.
- [x] **Cross-Platform Installer Script (`setup.sh`):**
  - Automated dependency setup for Debian/Ubuntu (apt), Arch (pacman), Fedora (dnf) and macOS (Homebrew), with a no-root local `tools/platform-tools` download fallback.
- [x] **OEM Driver Helper:**
  - `scripts/oem_driver_check.ps1` — Device Manager scan identifying Samsung, Google, MediaTek, Xiaomi and other OEM devices by vendor ID, flagging missing/faulty ADB drivers.

---

### Phase 3: Desktop GUI Application (Electron / Desktop Wrapper) ✅
- [x] **Lightweight GUI Wrapper (`gui/`):**
  - Electron desktop app with `contextIsolation` enabled and a minimal IPC bridge.
  - Reuses the Python inspection engine (`mdm_inspector --json`) as its analysis backend.
  - Visual dashboard displaying:
    - Connected device information (Brand, Model, Android Version, SDK level).
    - Device Owner (DO) / Profile Owner (PO) status indicator (Visual badge: Safe vs. Managed).
    - List of detected MDM/EMI packages.
    - One-click "Export Audit Report (JSON)" button with native save dialog.

---

### Phase 4: Advanced Static Analysis & Dynamic Monitoring ✅
- [x] **APK Manifest & Permission Analyzer (`core/apk_analyzer.py`):**
  - Pure-Python binary AXML decoder (`core/axml_parser.py`) — no external tooling required.
  - Flags `BIND_DEVICE_ADMIN`, `MANAGE_DEVICE_POLICY_*`, `SYSTEM_ALERT_WINDOW`, DeviceAdmin receivers, boot-persistence receivers and accessibility services.
- [x] **Live Telemetry & Logcat Monitor (`core/logcat_monitor.py`):**
  - Real-time, read-only monitor highlighting DevicePolicyManager / MDM traffic from `adb logcat`, with optional tee-to-file.
- [x] **Framework Emulation & Testbed:**
  - `scripts/create_testbed_avd.sh` + `docs/Testbed.md` — disposable emulator-only managed-enterprise AVD with optional Google TestDPC Device Owner provisioning.

---

### Quality Assurance ✅
- [x] Unit test-suite (`tests/`) with mocked ADB and byte-accurate synthetic AXML fixtures.
- [x] GitHub Actions CI (`.github/workflows/ci.yml`): syntax, CLI smoke checks and pytest on Python 3.9/3.11/3.12.
- [x] GitHub Pages deployment workflow (`.github/workflows/deploy.yml`).

---

## 3. Repository Structure Target

```text
android-enterprise-security-lab/
├── .github/
│   └── workflows/          # CI validation + GitHub Pages deployment
├── core/                   # Python inspection modules & analysis tools
│   ├── mdm_inspector.py    # Primary CLI inspection utility
│   ├── apk_analyzer.py     # APK manifest & permission analyzer
│   ├── axml_parser.py      # Pure-Python binary manifest decoder
│   └── logcat_monitor.py   # Live DPM/MDM telemetry monitor
├── gui/                    # Electron desktop dashboard (Phase 3)
├── scripts/                # Setup, diagnostics & testbed automation
├── docs/                   # Security architecture specifications & testbed guide
├── tests/                  # pytest unit tests
├── website/                # Web landing page (Tailwind CSS, i18n index.html)
├── output/                 # Generated diagnostic reports (git-ignored)
├── tools/                  # Local platform-tools fallback install (git-ignored)
├── AGENTS.md               # Directives for AI coding assistants
├── PLAN.md                 # Project roadmap & milestone tracking
├── README.md               # Main project README
└── LICENSE                 # Apache License 2.0

```

---

## 4. Safety & Ethical Guidelines

* **Educational & Defensive Scope:** All code developed under this plan must prioritize non-destructive auditing, system administration, and security research.
* **No Exploits:** Automated weaponized unlock payloads or zero-day bypass mechanisms targeting commercial vendors will not be accepted or merged into this codebase.
* **Consent & Ownership:** Diagnostics should only be performed on hardware owned by the researcher or used with explicit consent.
