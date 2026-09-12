# Enterprise Testbed: Studying Device Owners Safely

This guide explains how to build a **disposable, emulator-only** lab
environment for observing Android Device Owner / Profile Owner behavior —
the same privilege tier used by commercial MDM suites and device-financing
lock applications.

> **Safety contract.** The testbed runs exclusively on the Android Emulator.
> It never targets physical devices, never flashes partitions, and every
> provisioning step is reversible by deleting the AVD.

---

## 1. Why a dedicated testbed?

Real-world MDM agents only expose their full behavior (lock overlays,
policy enforcement, persistence) when they hold genuine administrative
privileges. To study these mechanisms **defensively** we need an
environment where:

| Requirement | How the testbed satisfies it |
|---|---|
| Full `DevicePolicyManager` privileges | `dpm set-device-owner` on an account-free emulator |
| Reproducibility | AVD snapshot / recreate via `create_testbed_avd.sh` |
| Isolation from personal data | Emulator only; disposable at any time |
| Observability | `adb logcat` telemetry via `core/logcat_monitor.py` |

---

## 2. Prerequisites

1. **Android SDK command-line tools** with `sdkmanager`, `avdmanager`,
   `emulator`, and `platform-tools` on `PATH` (or `ANDROID_HOME` set).
2. **KVM** (Linux) or **HAXM/Hyper-V** (Windows) acceleration for usable
   emulator performance.
3. Optional: a locally built copy of Google's
   [TestDPC sample](https://github.com/googlesamples/android-testdpc)
   (`TestDPC.apk`). TestDPC is Google's official reference Device/Profile
   Owner used by the Android team itself for testing enterprise APIs.

---

## 3. One-command setup

```bash
chmod +x scripts/create_testbed_avd.sh
./scripts/create_testbed_avd.sh                 # API 33, name mdm-lab-testbed
./scripts/create_testbed_avd.sh --api 34 --name lab34
```

The script will:

1. Install the `google_apis` x86_64 system image for the requested API.
2. Create a fresh `pixel_5`-profile AVD (replacing any previous testbed).
3. Boot the emulator headless (`-no-window`) and wait for full boot.
4. If `TEST_DPC_APK` points to a valid APK, install it and register it as
   **Device Owner** with:

   ```bash
   adb shell dpm set-device-owner com.afwsamples.testdpc/.DeviceAdminReceiver
   ```

   > `set-device-owner` refuses to run if user accounts exist on the
   > device — that is a platform safety property worth knowing about.

---

## 4. Lab exercises

With the testbed running:

```bash
# A. Inspect privilege state from the host
python3 core/mdm_inspector.py

# B. Watch DPM IPC traffic live while toggling policies inside TestDPC
python3 core/logcat_monitor.py --keywords-only

# C. Compare the DPM restriction flags TestDPC sets
adb shell dumpsys device_policy | less
```

Suggested observations:

* Enable *"Disallow factory reset"* in TestDPC and confirm the Settings
  option disappears — this is the same DPM flag commercial lock apps use.
* Trigger a lock via TestDPC's device-owner lock API and observe which
  window type the lock UI uses (`adb shell dumpsys window windows`).
* Watch `logcat_monitor.py` output while TestDPC checks policy: note the
  `DevicePolicyManager` IPC entries and their timing.

---

## 5. Teardown

```bash
adb emu kill                     # stop the emulator
avdmanager delete avd -n mdm-lab-testbed   # remove all traces
```

Because the entire state lives inside the AVD directory, teardown is
complete and immediate — a property that physical-device experiments can
never guarantee.
