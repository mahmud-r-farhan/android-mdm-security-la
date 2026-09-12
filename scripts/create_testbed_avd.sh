#!/usr/bin/env bash
# ==============================================================================
# Android Enterprise Security Lab - Managed-Profile Testbed Builder
# File: scripts/create_testbed_avd.sh
# Description: Automates creation of a disposable Android Virtual Device (AVD)
#              for safely studying Device Owner / Profile Owner behavior in a
#              managed-enterprise configuration. Emulator-only: NEVER targets
#              physical hardware and performs no destructive operations.
#
# Prerequisites (Android SDK cmdline-tools):
#   sdkmanager, avdmanager, emulator on PATH (or set ANDROID_HOME).
#
# Optional: set TEST_DPC_APK to a locally built TestDPC APK
#           (https://github.com/googlesamples/android-testdpc) to provision a
#           Device Owner automatically.
#
# Usage:
#   ./scripts/create_testbed_avd.sh [--api 33] [--name mdm-lab-testbed]
# License: Apache License 2.0
# ==============================================================================

set -euo pipefail

# ANSI Color Codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

API_LEVEL="33"
AVD_NAME="mdm-lab-testbed"
SYSTEM_IMAGE="system-images;android-33;google_apis;x86_64"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --api)   API_LEVEL="$2"; SYSTEM_IMAGE="system-images;android-${API_LEVEL};google_apis;x86_64"; shift 2 ;;
        --name)  AVD_NAME="$2"; shift 2 ;;
        -h|--help)
            grep '^# ' "$0" | sed 's/^# //'
            exit 0
            ;;
        *) echo -e "${RED}[X] Unknown argument: $1${NC}"; exit 2 ;;
    esac
done

require_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}[X] Required tool '$1' not found on PATH.${NC}"
        echo -e "    Install Android SDK cmdline-tools, then run:"
        echo -e "      sdkmanager --install \"cmdline-tools;latest\""
        exit 1
    fi
}

echo -e "${BLUE}====================================================================${NC}"
echo -e "${BLUE}   Managed-Enterprise AVD Testbed Builder (emulator-only)           ${NC}"
echo -e "${BLUE}====================================================================${NC}"

require_tool sdkmanager
require_tool avdmanager
require_tool emulator

# ----------------------------------------------------------------------------
# 1. Install the system image (idempotent)
# ----------------------------------------------------------------------------
echo -e "${BLUE}[*] Ensuring system image: ${SYSTEM_IMAGE}${NC}"
yes | sdkmanager --install "$SYSTEM_IMAGE" > /dev/null 2>&1 || \
    sdkmanager --install "$SYSTEM_IMAGE"

# ----------------------------------------------------------------------------
# 2. Create the AVD (non-interactive, overwriting any previous testbed)
# ----------------------------------------------------------------------------
echo -e "${BLUE}[*] Creating AVD '${AVD_NAME}' (API ${API_LEVEL})...${NC}"
if avdmanager list avd | grep -q "Name: ${AVD_NAME}"; then
    echo -e "${YELLOW}[=] AVD '${AVD_NAME}' already exists; re-creating for a clean state.${NC}"
    echo "no" | avdmanager delete avd -n "$AVD_NAME" > /dev/null 2>&1 || true
fi
echo "no" | avdmanager create avd \
    --name "$AVD_NAME" \
    --package "$SYSTEM_IMAGE" \
    --device "pixel_5" \
    --force > /dev/null

echo -e "${GREEN}[✓] AVD created.${NC}"

# ----------------------------------------------------------------------------
# 3. Boot the emulator headless and wait for readiness
# ----------------------------------------------------------------------------
echo -e "${BLUE}[*] Booting emulator (headless)...${NC}"
nohup emulator -avd "$AVD_NAME" -no-window -no-audio -no-boot-anim > /tmp/emulator-testbed.log 2>&1 &
EMULATOR_PID=$!
echo -e "${GREEN}[+] Emulator process started (pid ${EMULATOR_PID}); logs: /tmp/emulator-testbed.log${NC}"

echo -e "${BLUE}[*] Waiting for device...${NC}"
adb wait-for-device
BOOTED=0
for _ in $(seq 1 60); do
    BOOT_STATE="$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r' || true)"
    if [[ "$BOOT_STATE" == "1" ]]; then
        BOOTED=1
        break
    fi
    sleep 2
done

if [[ "$BOOTED" != "1" ]]; then
    echo -e "${RED}[X] Emulator did not finish booting within 120s. Check /tmp/emulator-testbed.log${NC}"
    exit 1
fi
echo -e "${GREEN}[✓] Emulator booted.${NC}"

# ----------------------------------------------------------------------------
# 4. Optional Device Owner provisioning with Google's TestDPC sample
# ----------------------------------------------------------------------------
if [[ -n "${TEST_DPC_APK:-}" && -f "${TEST_DPC_APK:-}" ]]; then
    echo -e "${BLUE}[*] Installing TestDPC from ${TEST_DPC_APK} ...${NC}"
    adb install "$TEST_DPC_APK"
    echo -e "${BLUE}[*] Setting Device Owner (emulator must have NO accounts)...${NC}"
    adb shell pm clear com.google.android.gms > /dev/null 2>&1 || true
    if adb shell dpm set-device-owner com.afwsamples.testdpc/.DeviceAdminReceiver; then
        echo -e "${GREEN}[✓] TestDPC is now the Device Owner. Verify with:${NC}"
        echo -e "      adb shell dpm list-owners"
        echo -e "      python3 core/mdm_inspector.py"
    else
        echo -e "${YELLOW}[!] set-device-owner failed. Remove all accounts from the AVD and retry:${NC}"
        echo -e "      adb shell dpm set-device-owner com.afwsamples.testdpc/.DeviceAdminReceiver"
    fi
else
    echo -e "${YELLOW}[i] TEST_DPC_APK not set; skipping Device Owner provisioning.${NC}"
    echo -e "    To provision: build https://github.com/googlesamples/android-testdpc then:"
    echo -e "      TEST_DPC_APK=/path/to/TestDPC.apk $0"
fi

echo ""
echo -e "${GREEN}[+] Testbed ready. Suggested lab workflow:${NC}"
echo -e "      python3 core/mdm_inspector.py            # audit DPM state"
echo -e "      python3 core/logcat_monitor.py           # live policy telemetry"
echo -e "      adb emu kill                             # destroy session"
echo -e "${BLUE}====================================================================${NC}"
