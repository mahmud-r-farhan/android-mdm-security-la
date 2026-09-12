# Technical Architecture & Android MDM Internals

## 1. Overview & Android Security Framework

This document outlines the security architecture of Android Mobile Device Management (MDM), Device Administrator APIs, and hardware-backed enforcement mechanisms used in enterprise management and installment-based device financing.

Modern Android devices enforce access controls through multi-layered security boundaries:

1. **Linux Kernel & SELinux:** Enforces Mandatory Access Control (MAC) policies and isolates process memory.
2. **Android Framework & Application Sandbox:** Enforces permission checks (`dpm`, `pm`, system permissions).
3. **Hardware Root of Trust:** Secure enclaves (ARM TrustZone, Samsung Knox eFuse, Google Titan M) enforcing cryptographic boot integrity and remote attestation.


```

+-------------------------------------------------------------------+
|               Third-Party / Financing Control App                 |
+-------------------------------------------------------------------+
|
[ Interacts via DevicePolicyManager API ]
v
+-------------------------------------------------------------------+
|                 Android System Server (System UI)                 |
|  - System-level Lock Overlays   - Factory Reset Prevention (FRP)  |
+-------------------------------------------------------------------+
|
[ Enforces Policy & Cryptographic Verification ]
v
+-------------------------------------------------------------------+
|                  Hardware Root of Trust / TrustZone               |
|  - eFuse Status   - Knox Guard / Keymaster   - Hardware Re-attest |
+-------------------------------------------------------------------+

```

---

## 2. Device Management Privilege Hierarchy

Android categorizes administrative control into specific privilege tiers:

### A. Device Administrator (Legacy)
Introduced in Android 2.2, this mode grants standard administrative rights (e.g., password policies, remote wipe). 
* **Limitations:** Users can navigate to `Settings -> Security -> Device Admin Apps` and manually revoke privileges unless blocked by secondary system overlays.

### B. Profile Owner (Work Profile)
Introduced in Android 5.0, Profile Owner isolates personal data from corporate data by creating a managed user profile container (`UserHandle`).
* **Scope:** Administrative control is strictly limited to the enterprise container and cannot restrict personal apps or wipe global system partitions.

### C. Device Owner (DO) / Android Enterprise
Grants full, unrevokable administrative control across the entire device operating system.
* **Privileges:**
  * Disables Factory Reset Protection (FRP) and Settings UI options.
  * Blocks Developer Options, USB Debugging, and ADB connectivity.
  * Enforces persistent system overlays that restrict touch inputs during lock states.
  * Prohibits uninstallation or force-stopping of the managed controller app.

---

## 3. Remote Locking Mechanics & System Overlays

When a financing server issues a lock command to a device, the client application executes the following framework flow:

1. **Push Notification / Polling:** The app receives a trigger signal from the cloud backend via FCM (Firebase Cloud Messaging) or persistent socket connections.
2. **System Overlay Injection:** The app requests system window drawing rights via `TYPE_APPLICATION_OVERLAY` or native system-level flags:
   ```java
   WindowManager.LayoutParams params = new WindowManager.LayoutParams(
       WindowManager.LayoutParams.MATCH_PARENT,
       WindowManager.LayoutParams.MATCH_PARENT,
       WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
       WindowManager.LayoutParams.FLAG_FULLSCREEN | 
       WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL,
       PixelFormat.TRANSLUCENT
   );


3. **Keyguard Hijack:** The application intercepts back navigation, home gestures, and hardware key callbacks to restrict system access to emergency calls or payment gateways.

---

## 4. Hardware-Backed Enforcement & Attestation (e.g., Samsung Knox)

To prevent users from removing MDM controls through recovery wipes or firmware re-flashing, modern hardware utilizes hardware cryptographic binding.

### Samsung Knox Guard Architecture

* **Hardware eFuse & TrustZone:** During device provisioning, the IMEI and serial number are linked with vendor attestation servers.
* **Persistent Attestation:** Upon system boot or factory reset, the bootloader verifies OS signatures against the Hardware Root of Trust.
* **Cloud Re-binding:** Once the device connects to Wi-Fi or cellular networks, the TrustZone component contacts Knox Attestation servers. If an unpaid balance or active policy lock is flagged in the vendor registry, the Knox agent automatically reinstalls the lock payload in the system partition.

---

## 5. Research & Audit Methodology

Within this lab environment, analysis of MDM policies is conducted using non-destructive, read-only diagnostic tools:

1. **Policy Enumeration:** Reading registered package managers and active DPM state via `adb shell dpm list-owners`.
2. **Package Profiling:** Inspecting manifest permissions (`android.permission.BIND_DEVICE_ADMIN`, `MANAGE_DEVICE_POLICY_*`).
3. **Network Telemetry:** Auditing outgoing REST API endpoints to determine remote attestation frequencies and payload configurations.
