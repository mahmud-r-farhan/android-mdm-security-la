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
3. Analyzing potential bypass vectors via ADB debug interfaces, package management manipulation, and system privileges in a non-destructive manner.
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
|   - Knox Guard / Telecommunication IMEI Verification         |
+-------------------------------------------------------------+
```

### Key Mechanisms Analyzed
* **DevicePolicyManager (DPM):** Grants elevated capabilities, including disabling USB Debugging, disabling factory reset options, and overriding system status bars.
* **System Overlay (`TYPE_APPLICATION_OVERLAY`):** Renders non-dismissible UI screens that intercept touch events and block access to System Settings.
* **Persistence via Receiver Signals:** Auto-restarts services on `BOOT_COMPLETED`, network change, or screen-on events.

---

## 📂 Repository Structure

```
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
  ./scripts/setup.sh
  ```

* **Windows (PowerShell):**
  ```powershell
  .\scripts\setup.ps1
  ```

---

## 🧪 Research & Analysis Methodology

### Phase 1: Package & Policy Identification
Run the Python MDM Inspector to audit registered `DeviceOwner` policies and installed MDM signatures:
```bash
python3 core/mdm_inspector.py
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
