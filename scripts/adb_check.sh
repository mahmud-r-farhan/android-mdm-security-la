#!/usr/bin/env bash
# ==============================================================================
# Android Enterprise Security Lab - Quick ADB Diagnostic Script
# File: scripts/adb_check.sh
# Description: Rapid bash script to query DPM policies, Knox flags, and MDM state.
# License: Apache License 2.0
# ==============================================================================

set -euo pipefail

# ANSI Color Codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}====================================================================${NC}"
echo -e "${BLUE}      Android Enterprise Security Lab - ADB Quick Diagnostic        ${NC}"
echo -e "${BLUE}====================================================================${NC}"

# 1. Check if ADB is installed
if ! command -v adb &> /dev/null; then
    echo -e "${RED}[X] Error: 'adb' command not found. Please install Android Platform Tools.${NC}"
    exit 1
fi

# 2. Check connected devices
DEVICES=$(adb devices | grep -v "List of devices" | grep "device$" || true)

if [ -z "$DEVICES" ]; then
    echo -e "${RED}[!] No ADB device connected or authorized.${NC}"
    echo -e "${YELLOW}-> Make sure USB Debugging is enabled in Developer Options.${NC}"
    exit 1
fi

DEVICE_ID=$(echo "$DEVICES" | head -n1 | awk '{print $1}')
echo -e "${GREEN}[+] Target Device Connected: ${DEVICE_ID}${NC}\n"

# 3. Retrieve basic hardware and OS information
echo -e "${BLUE}[*] Gathering System Build Properties...${NC}"
MODEL=$(adb -s "$DEVICE_ID" shell getprop ro.product.model)
BRAND=$(adb -s "$DEVICE_ID" shell getprop ro.product.brand)
SDK=$(adb -s "$DEVICE_ID" shell getprop ro.build.version.sdk)
ANDROID_VER=$(adb -s "$DEVICE_ID" shell getprop ro.build.version.release)
KNOX_VER=$(adb -s "$DEVICE_ID" shell getprop ro.config.knox.version 2>/dev/null || echo "Not Supported")

echo -e "  - Manufacturer/Model : ${BRAND} ${MODEL}"
echo -e "  - Android Version    : ${ANDROID_VER} (API Level ${SDK})"
echo -e "  - Knox Version       : ${KNOX_VER}"
echo ""

# 4. Check Device Policy Manager (DPM) Active Owners
echo -e "${BLUE}[*] Auditing Device Policy Manager (DPM)...${NC}"
DPM_OUTPUT=$(adb -s "$DEVICE_ID" shell dpm list-owners 2>/dev/null || true)

if echo "$DPM_OUTPUT" | grep -q "Device Owner:"; then
    echo -e "  ${RED}[!] CRITICAL: Device Owner (DO) privilege IS ACTIVE on this phone.${NC}"
    echo -e "  ${YELLOW}${DPM_OUTPUT}${NC}"
elif echo "$DPM_OUTPUT" | grep -q "Profile Owner:"; then
    echo -e "  ${YELLOW}[!] WARNING: Profile Owner (PO) work profile detected.${NC}"
    echo -e "  ${YELLOW}${DPM_OUTPUT}${NC}"
else
    echo -e "  ${GREEN}[✓] No Device Owner or Profile Owner policies registered.${NC}"
fi
echo ""

# 5. Scan for common EMI/MDM package signatures
echo -e "${BLUE}[*] Scanning Installed Packages for Known MDM Signatures...${NC}"
PACKAGES=$(adb -s "$DEVICE_ID" shell pm list packages)

TARGET_PACKAGES=(
    "com.payjoy.vanilla:PayJoy"
    "com.shoppay.finance:ShopUp/PayWell"
    "com.sec.knox.guard:Samsung Knox Guard"
    "com.google.android.apps.work.clouddpc:Android Device Policy"
    "com.airwatch.androidagent:VMware Workspace ONE"
    "com.microsoft.windowsintune.companyportal:Microsoft Intune"
)

FOUND_MDM=0
for ENTRY in "${TARGET_PACKAGES[@]}"; do
    PKG="${ENTRY%%:*}"
    NAME="${ENTRY#*:}"
    if echo "$PACKAGES" | grep -q "package:${PKG}"; then
        echo -e "  ${RED}[!] DETECTED: ${NAME} (${PKG})${NC}"
        FOUND_MDM=$((FOUND_MDM + 1))
    fi
done

if [ "$FOUND_MDM" -eq 0 ]; then
    echo -e "  ${GREEN}[✓] No known commercial or enterprise MDM packages identified.${NC}"
fi

echo ""
echo -e "${BLUE}====================================================================${NC}"
echo -e "${GREEN}[+] Diagnostic Scan Complete.${NC}"
echo -e "${BLUE}====================================================================${NC}"
