
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

### Phase 2: One-Click End-User Installer & Environment Automation
- [ ] **Windows Automated Setup Suite (`setup.ps1` / `setup.bat`):**
  - Automated detection, download, and extraction of Google's official `platform-tools`.
  - Automatic user `PATH` environment variable registration.
  - One-click launch wrapper that opens the terminal or diagnostic GUI automatically.
- [ ] **Cross-Platform Installer Script (`setup.sh`):**
  - Automated dependency setup for Debian/Ubuntu, Arch Linux, and macOS (Homebrew integration).
- [ ] **OEM Driver Helper:**
  - Automated diagnostic module verifying whether Samsung, Google, or MediaTek ADB drivers are missing on Windows.

---

### Phase 3: Desktop GUI Application (Electron / Desktop Wrapper)
- [ ] **Lightweight GUI Wrapper:**
  - Build a clean desktop interface using Electron or Tauri for non-technical users.
  - Bundled internal relative execution of `platform-tools/adb` (no manual PATH setup needed).
  - Visual dashboard displaying:
    - Connected device information (Brand, Model, Android Version, SDK level).
    - Device Owner (DO) / Profile Owner (PO) status indicator (Visual badge: Safe vs. Managed).
    - List of detected MDM/EMI packages.
    - One-click "Export Audit Report (JSON/PDF)" button.

---

### Phase 4: Advanced Static Analysis & Dynamic Monitoring
- [ ] **APK Manifest & Permission Analyzer:**
  - Python static analysis module parsing target MDM APKs for `BIND_DEVICE_ADMIN`, `MANAGE_DEVICE_POLICY_*`, and System Overlay permissions.
- [ ] **Live Telemetry & Logcat Monitor:**
  - Real-time logging agent capturing DevicePolicyManager IPC broadcasts and cloud attestation ping requests via `adb logcat`.
- [ ] **Framework Emulation & Testbed:**
  - Documentation and scripts for building local Android Virtual Devices (AVD) running managed enterprise profiles for testing.

---

## 3. Repository Structure Target

```text
android-enterprise-security-lab/
├── .github/
│   └── workflows/          # GitHub Actions deployment pipelines
├── website/                # Web landing page (Tailwind CSS, i18n index.html)
├── core/                   # Python inspection modules & analysis tools
│   ├── __init__.py
│   └── mdm_inspector.py    # Primary CLI inspection utility
├── scripts/                # Setup & diagnostic scripts
│   ├── adb_check.sh        # Bash quick scan
│   ├── setup.ps1           # Automated Windows installer & PATH setup
│   └── setup.sh            # Linux/macOS automated environment setup
├── docs/                   # Educational & architectural documentation
│   └── Architecture.md     # Technical reference on Android DPM & Knox Guard
├── output/                 # Generated diagnostic reports (git-ignored)
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
