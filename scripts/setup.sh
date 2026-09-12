#!/usr/bin/env bash
# ==============================================================================
# Android Enterprise Security Lab - Cross-Platform Environment Setup Script
# File: scripts/setup.sh
# Description: Automated dependency check and ADB platform-tools installer for Linux/macOS.
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
echo -e "${BLUE}   Android Enterprise Security Lab - Environment Setup Utility      ${NC}"
echo -e "${BLUE}====================================================================${NC}"

OS_TYPE="$(uname -s)"
echo -e "${BLUE}[*] Operating System Detected: ${OS_TYPE}${NC}"

# Check Python 3 installation
if command -v python3 &> /dev/null; then
    PY_VER=$(python3 --version)
    echo -e "${GREEN}[✓] Python 3 detected: ${PY_VER}${NC}"
else
    echo -e "${RED}[X] Python 3 is not installed. Please install Python 3.9+ to run lab scripts.${NC}"
fi

# Check ADB platform-tools installation
if command -v adb &> /dev/null; then
    ADB_VER=$(adb version | head -n1)
    echo -e "${GREEN}[✓] Android ADB detected: ${ADB_VER}${NC}"
else
    echo -e "${YELLOW}[!] 'adb' executable not found in PATH.${NC}"
    echo -e "${BLUE}[*] Attempting automated platform-tools installation instructions...${NC}"

    case "$OS_TYPE" in
        Linux*)
            if command -v apt-get &> /dev/null; then
                echo -e "    Run: ${YELLOW}sudo apt-get update && sudo apt-get install -y android-sdk-platform-tools${NC}"
            elif command -v pacman &> /dev/null; then
                echo -e "    Run: ${YELLOW}sudo pacman -S android-tools${NC}"
            else
                echo -e "    Please download Android Platform Tools from: https://developer.android.com/tools/releases/platform-tools"
            fi
            ;;
        Darwin*)
            if command -v brew &> /dev/null; then
                echo -e "    Run: ${YELLOW}brew install --cask android-platform-tools${NC}"
            else
                echo -e "    Please install Homebrew or download Platform Tools from Google Developer portal."
            fi
            ;;
        *)
            echo -e "    Please download Android Platform Tools manually."
            ;;
    esac
fi

echo ""
echo -e "${GREEN}[+] Setup check complete. You can now run 'python3 core/mdm_inspector.py'${NC}"
echo -e "${BLUE}====================================================================${NC}"
