# MDM-Unlocker-PoC: Educational MDM & Knox Security Research

> **Disclaimer & Notice of Educational Intent**
> This repository is strictly created for **educational, security research, and analytical purposes**. The code, methodologies, and technical documentation herein aim to assist mobile security researchers, forensic analysts, and Android developers in understanding Android Device Admin APIs, Mobile Device Management (MDM) architecture, and OEM-level security frameworks (e.g., Samsung Knox, PayJoy, OEM Config). 
> 
> Unauthorized bypass or alteration of device management controls on financed or third-party devices may violate terms of service or regional telecommunication laws. The maintainers do not endorse, encourage, or support illegal activities or commercial bypass services.

---

## 📌 Project Overview

**MDM-Unlocker-PoC** is an open-source framework and knowledge base dedicated to analyzing how commercial financing locking applications and enterprise MDM solutions operate on the Android OS level.

Modern financing platforms enforce remote locking using Android's deep system privileges (`DeviceOwner`, `DeviceAdmin`, or custom OEM extensions). This project explores:
1. Identifying MDM agents and associated package signatures.
2. Understanding the privilege escalation and persistence mechanisms of lock apps.
3. Analyzing potential bypass vectors via ADB debug interfaces, package management manipulation, and system privileges.
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
├── docs/
│   ├── mdm-architecture.md         # Detailed breakdown of Android DPM APIs
│   ├── knox-guard-analysis.md       # Hardware vs Software MDM binding
│   └── threat-model.md             # Security threat modeling of persistence
├── scripts/
│   ├── package_detector.sh         # Bash script to scan for active MDM/Admin packages via ADB
│   ├── test_payload.py             # Python utility demonstrating package state inspection
│   └── adb_privilege_checker.py    # Checks active Device Owner status on connected device
├── README.md
└── LICENSE
```

---

## 🚀 Getting Started

### Prerequisites
* **Android SDK Platform-Tools** (`adb`, `fastboot`)
* **Python 3.8+**
* An Android test device/emulator running **Android 10 (API Level 29) or higher** with Developer Options enabled.

### Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/MDM-Unlocker-PoC.git
   cd MDM-Unlocker-PoC
   ```

2. **Connect your test device via USB:**
   Ensure USB Debugging is authorized on your target test environment.
   ```bash
   adb devices
   ```

3. **Run the MDM Package Detector:**
   The detection script scans active system packages against known enterprise and financing MDM signatures (e.g., PayJoy, Knox Guard, OEM Config).
   ```bash
   chmod +x scripts/package_detector.sh
   ./scripts/package_detector.sh
   ```

---

## 🧪 Research & Analysis Methodology

### Phase 1: Package Identification
Detecting active admin apps on the device using Android shell utilities:
```bash
adb shell pm list packages -e | grep -i "admin\|lock\|pay\|mdm"
adb shell dumpsys device_policy
```

### Phase 2: Evaluating Privilege States
Determining whether the targeted app operates as a standard `DeviceAdmin` or a deeper `DeviceOwner`:
```bash
adb shell dpm status
```

### Phase 3: Mitigation & Disabling Vectors (PoC)
Testing package state modification for standard (non-Knox) MDM profiles:
```bash
# Hiding user-level package state
adb shell pm hide <package_name>

# Disabling user zero installation state
adb shell pm uninstall -k --user 0 <package_name>
```
*Note: Hardware-backed solutions (like Knox Guard) will detect state tampering upon internet reconnection via cloud verification.*

---

## 🛡 Recommended Defenses & Countermeasures

For enterprise developers and financial application architects, the following mechanisms prevent unauthorized bypassing:

1. **Knox Guard / Hardware-backed Attestation:** Bind device compliance checks to hardware trust anchors (e.g., Knox eFuse, Keymaster/KeyMint attestation).
2. **Prevent Debugging Modes:** Disable `DISALLOW_DEBUGGING_FEATURES` via `DevicePolicyManager` to lock down ADB interfaces.
3. **Out-of-Band Integrity Check:** Regularly verify device compliance against a remote cloud service using SafetyNet / Play Integrity API.

---

## 🤝 Contributing

Contributions for research documentation, new MDM signature identification, and educational analysis are welcome! Please follow these guidelines:
1. Ensure all submissions focus on security research and mitigation strategies.
2. Do not include commercial bypass tools, proprietary hardware dumps, or illegal keygens.
3. Open an Issue first to discuss proposed updates.

---

## 📜 License

This project is licensed under the [MIT License](LICENSE) - feel free to use it for research and educational purposes.
