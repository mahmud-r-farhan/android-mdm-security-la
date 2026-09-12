# Android Enterprise Security Lab

> **Disclaimer & Notice of Educational Intent**
> This repository is strictly created for **educational, security research, and analytical purposes**. The code, methodologies, and technical documentation herein aim to assist mobile security researchers, forensic analysts, system administrators, and Android developers in understanding Android Device Admin APIs, Mobile Device Management (MDM) architecture, and OEM-level security frameworks (e.g., Samsung Knox, PayJoy, OEM Config).
>
> Unauthorized bypass or alteration of device management controls on financed or third-party devices may violate terms of service or regional telecommunication laws. The maintainers do not endorse, encourage, or support illegal activities or commercial bypass services.

---

## 📌 Project Overview

**Android Enterprise Security Lab** is an open-source framework and knowledge base dedicated to analyzing how commercial financing locking applications and enterprise MDM solutions operate on the Android OS level.

Modern financing platforms enforce remote locking using Android's deep system privileges (`DeviceOwner`, `DeviceAdmin`, or custom OEM extensions). This project explores:
1. Identifying MDM agents and associated package signatures.
2. Understanding the privilege escalation and persistence mechanisms of lock apps.
3. Auditing privilege states via ADB debug interfaces in a **non-destructive, read-only** manner.
4. Documenting countermeasures and security mitigations for Android security developers.

---

## 🏗 System Architecture & Mechanics

MDM locking software relies on layered security controls within the Android OS:

```
+-------------------------------------------------------------+
|                     User Interface Layer                    |
|             (System Overlay / Lock Screen Window)           |
+-------------------------------------------------------------+
|                   Application Layer (MDM Agent)             |
|   - Keeps persistent foreground service                     |
|   - Prevents uninstallation via DeviceAdmin Receiver        |
+-------------------------------------------------------------+
|                 Android Framework & Policy                  |
|   - DevicePolicyManager (DPM)                               |
|   - OEM Knox / Custom Enterprise APIs                       |
+-------------------------------------------------------------+
|                Hardware Root of Trust / eFuse               |
|   - Knox Guard / Telecommunication IMEI Verification        |
+-------------------------------------------------------------+
```

### Key Mechanisms Analyzed
* **DevicePolicyManager (DPM):** Grants elevated capabilities, including disabling USB Debugging, disabling factory reset options, and overriding system status bars.
* **System Overlay (`TYPE_APPLICATION_OVERLAY`):** Renders non-dismissible UI screens that intercept touch events and block access to System Settings.
* **Persistence via Receiver Signals:** Auto-restarts services on `BOOT_COMPLETED`, network change, or screen-on events.

---

## 🧰 Tool Suite

| Tool | Phase | Purpose |
|------|-------|---------|
| `core/mdm_inspector.py` | 1 | Device Owner / Profile Owner audit, known-MDM signature scan, JSON reports |
| `core/apk_analyzer.py` | 4 | Static APK manifest analysis (pure-Python AXML decoder; flags DeviceAdmin, overlay & policy permissions) |
| `core/logcat_monitor.py` | 4 | Live, read-only telemetry of DPM/MDM activity from `adb logcat` |
| `scripts/adb_check.sh` | 1 | Rapid bash diagnostic (Linux/macOS) |
| `scripts/setup.sh` / `setup.ps1` / `setup.bat` | 2 | One-click environment automation incl. platform-tools auto-install & PATH registration |
| `scripts/oem_driver_check.ps1` | 2 | Windows OEM ADB driver diagnostics (Samsung / Google / MediaTek / Xiaomi VIDs) |
| `scripts/create_testbed_avd.sh` | 4 | Disposable managed-enterprise emulator testbed (see [docs/Testbed.md](docs/Testbed.md)) |
| `gui/` | 3 | Electron desktop dashboard (device info, DO/PO badges, package list, one-click JSON export) |

---

## 📂 Repository Structure

```
android-enterprise-security-lab/
├── .github/
│   └── workflows/
│       ├── ci.yml              # Python/Bash validation + unit tests
│       └── deploy.yml          # GitHub Pages deployment for website/
├── core/                       # Python inspection & analysis modules
│   ├── mdm_inspector.py        # Primary CLI inspection utility
│   ├── apk_analyzer.py         # APK manifest & permission analyzer
│   ├── axml_parser.py          # Pure-Python binary AndroidManifest decoder
│   └── logcat_monitor.py       # Live DPM/MDM telemetry monitor
├── gui/                        # Electron desktop dashboard (Phase 3)
├── scripts/                    # Setup, diagnostics & testbed automation
│   ├── adb_check.sh
│   ├── setup.sh / setup.ps1 / setup.bat
│   ├── oem_driver_check.ps1
│   └── create_testbed_avd.sh
├── docs/                       # Educational & architectural documentation
│   ├── Architecture.md
│   └── Testbed.md
├── tests/                      # pytest unit tests (mocked ADB + AXML fixtures)
├── website/                    # Web landing page (Tailwind CSS, i18n)
├── output/                     # Generated diagnostic reports (git-ignored)
├── AGENTS.md                   # Directives for AI coding assistants
├── PLAN.md                     # Project roadmap & milestone tracking
└── LICENSE                     # Apache License 2.0
```

---

## 🚀 Getting Started

### Prerequisites
* **Android SDK Platform-Tools** (`adb`, `fastboot`)
* **Python 3.9+**
* An Android test device/emulator running **Android 10 (API Level 29) or higher** with Developer Options enabled.

### Environment Setup

Execute the appropriate setup utility for your OS:

* **Linux / macOS:**
  ```bash
  chmod +x scripts/setup.sh
  ./scripts/setup.sh            # add --auto for unattended mode
  ```

* **Windows (double-click or PowerShell):**
  ```
  scripts\setup.bat             # one-click launcher
  ```
  ```powershell
  .\scripts\setup.ps1           # or directly from PowerShell
  ```

The setup utilities verify Python, install `adb` when missing (package manager
or a local no-root download), and on Windows register platform-tools on the
user PATH automatically.

---

## 🧪 Research & Analysis Methodology

### Phase 1: Package & Policy Identification
Run the Python MDM Inspector to audit registered `DeviceOwner` policies and installed MDM signatures:
```bash
python3 core/mdm_inspector.py                 # human-readable + JSON export
python3 core/mdm_inspector.py --json          # machine-readable stdout
python3 core/mdm_inspector.py --device <SERIAL> --output reports/audit.json
```

Alternatively, run the rapid Bash diagnostic script:
```bash
chmod +x scripts/adb_check.sh
./scripts/adb_check.sh
```

### Phase 2: Evaluating Privilege States
Determining whether the targeted app operates as a standard `DeviceAdmin` or a deeper `DeviceOwner`:
```bash
adb shell dpm list-owners
```

### Phase 3: Static APK Analysis
Inspect any APK for device-management capabilities (never executes the APK):
```bash
python3 core/apk_analyzer.py path/to/suspect.apk
python3 core/apk_analyzer.py path/to/suspect.apk --json --output output/apk_report.json
```

### Phase 4: Live Telemetry
Watch DevicePolicyManager / MDM activity in real time:
```bash
python3 core/logcat_monitor.py                 # all traffic, flagged lines highlighted
python3 core/logcat_monitor.py --keywords-only --log output/telemetry.log
```

### Phase 5: Desktop Dashboard (non-technical users)
```bash
cd gui && npm install && npm start
```

### Reproducing a managed environment safely
Build a disposable Device-Owner emulator testbed (emulator-only, never
physical hardware) — see [docs/Testbed.md](docs/Testbed.md):
```bash
./scripts/create_testbed_avd.sh
```

---

## ✅ Running the Tests

```bash
python -m pip install pytest
python -m pytest tests/ -v
```

The suite covers the DPM output parser, risk classification, the binary AXML
decoder (UTF-8 and UTF-16 string pools) and the end-to-end APK analyzer,
using mocked ADB and byte-accurate synthetic manifests.

---

## 🛡 Recommended Defenses & Countermeasures

For enterprise developers and financial application architects, the following mechanisms prevent unauthorized bypassing:

1. **Knox Guard / Hardware-backed Attestation:** Bind device compliance checks to hardware trust anchors (e.g., Knox eFuse, Keymaster/KeyMint attestation).
2. **Prevent Debugging Modes:** Disable `DISALLOW_DEBUGGING_FEATURES` via `DevicePolicyManager` to lock down ADB interfaces.
3. **Out-of-Band Integrity Check:** Regularly verify device compliance against a remote cloud service using SafetyNet / Play Integrity API.

---

## 🤝 Contributing

Contributions for research documentation, new MDM signature identification, and educational analysis are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

---

## 📜 License

This project is licensed under the [Apache License 2.0](LICENSE) - feel free to use it for research and educational purposes.
