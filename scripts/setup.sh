#!/usr/bin/env bash
# ==============================================================================
# Android Enterprise Security Lab - Cross-Platform Environment Setup Script
# File: scripts/setup.sh
# Description: Automated dependency check and ADB platform-tools installer
#              for Linux and macOS. Installs via the native package manager
#              when permitted, otherwise falls back to a local, repo-contained
#              platform-tools download (tools/platform-tools) - no root needed.
# Usage:
#   ./scripts/setup.sh              # interactive (asks before sudo installs)
#   ./scripts/setup.sh --auto       # non-interactive; never prompts for sudo,
#                                   # falls back to local download directly
# License: Apache License 2.0
# ==============================================================================

set -euo pipefail

# ANSI Color Codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

AUTO_MODE=0
if [[ "${1:-}" == "--auto" ]]; then
    AUTO_MODE=1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCAL_TOOLS_DIR="${REPO_ROOT}/tools"
PLATFORM_TOOLS_DIR="${LOCAL_TOOLS_DIR}/platform-tools"

echo -e "${BLUE}====================================================================${NC}"
echo -e "${BLUE}   Android Enterprise Security Lab - Environment Setup Utility      ${NC}"
echo -e "${BLUE}====================================================================${NC}"

OS_TYPE="$(uname -s)"
echo -e "${BLUE}[*] Operating System Detected: ${OS_TYPE}${NC}"

# ----------------------------------------------------------------------------
# 1. Python 3.9+ check
# ----------------------------------------------------------------------------
if command -v python3 &> /dev/null; then
    PY_VER="$(python3 -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])')"
    PY_OK="$(python3 -c 'import sys; print(1 if sys.version_info >= (3, 9) else 0)')"
    if [[ "$PY_OK" == "1" ]]; then
        echo -e "${GREEN}[✓] Python 3 detected: ${PY_VER}${NC}"
    else
        echo -e "${YELLOW}[!] Python ${PY_VER} is older than the required 3.9.${NC}"
    fi
else
    echo -e "${RED}[X] Python 3 is not installed. Please install Python 3.9+ to run lab scripts.${NC}"
fi

# ----------------------------------------------------------------------------
# 2. Local platform-tools fallback downloader (works everywhere, no sudo)
# ----------------------------------------------------------------------------
install_platform_tools_local() {
    echo -e "${BLUE}[*] Downloading official Google platform-tools to ${PLATFORM_TOOLS_DIR} ...${NC}"
    mkdir -p "$LOCAL_TOOLS_DIR"

    local zip_path="${LOCAL_TOOLS_DIR}/platform-tools.zip"
    local url
    case "$OS_TYPE" in
        Darwin*) url="https://dl.google.com/android/repository/platform-tools-latest-darwin.zip" ;;
        *)       url="https://dl.google.com/android/repository/platform-tools-latest-linux.zip" ;;
    esac

    if command -v curl &> /dev/null; then
        curl -fL --progress-bar -o "$zip_path" "$url"
    elif command -v wget &> /dev/null; then
        wget -O "$zip_path" "$url"
    else
        echo -e "${RED}[X] Neither curl nor wget found; cannot download platform-tools.${NC}"
        return 1
    fi

    if command -v unzip &> /dev/null; then
        unzip -q -o "$zip_path" -d "$LOCAL_TOOLS_DIR"
    else
        echo -e "${RED}[X] 'unzip' is not installed; cannot extract platform-tools.${NC}"
        return 1
    fi
    rm -f "$zip_path"

    echo -e "${GREEN}[✓] platform-tools installed locally at ${PLATFORM_TOOLS_DIR}${NC}"
    echo -e "${YELLOW}    Add it to your PATH for this session:${NC}"
    echo -e "      export PATH=\"${PLATFORM_TOOLS_DIR}:\$PATH\""
    echo -e "${YELLOW}    and permanently (bash):${NC}"
    echo -e "      echo 'export PATH=\"${PLATFORM_TOOLS_DIR}:\$PATH\"' >> ~/.bashrc"
    export PATH="${PLATFORM_TOOLS_DIR}:${PATH}"
}

# ----------------------------------------------------------------------------
# 3. ADB check / installation
# ----------------------------------------------------------------------------
adb_available() {
    command -v adb &> /dev/null || [[ -x "${PLATFORM_TOOLS_DIR}/adb" ]]
}

confirm() {
    local prompt="$1"
    if [[ "$AUTO_MODE" == "1" ]]; then
        return 1
    fi
    read -r -p "$(echo -e "${YELLOW}${prompt} [y/N]:${NC} ")" answer
    [[ "$answer" =~ ^[Yy]$ ]]
}

if command -v adb &> /dev/null; then
    ADB_VER="$(adb version | head -n1)"
    echo -e "${GREEN}[✓] Android ADB detected: ${ADB_VER}${NC}"
else
    echo -e "${YELLOW}[!] 'adb' executable not found in PATH.${NC}"
    echo -e "${BLUE}[*] Attempting automated installation...${NC}"

    INSTALLED=0
    case "$OS_TYPE" in
        Linux*)
            if command -v apt-get &> /dev/null; then
                if confirm "Install 'adb' via apt (requires sudo)?"; then
                    sudo apt-get update -y && sudo apt-get install -y adb && INSTALLED=1
                fi
            elif command -v pacman &> /dev/null; then
                if confirm "Install 'android-tools' via pacman (requires sudo)?"; then
                    sudo pacman -S --noconfirm android-tools && INSTALLED=1
                fi
            elif command -v dnf &> /dev/null; then
                if confirm "Install 'android-tools' via dnf (requires sudo)?"; then
                    sudo dnf install -y android-tools && INSTALLED=1
                fi
            fi
            ;;
        Darwin*)
            if command -v brew &> /dev/null; then
                if confirm "Install 'android-platform-tools' via Homebrew?"; then
                    brew install --cask android-platform-tools && INSTALLED=1
                fi
            else
                echo -e "${YELLOW}    Homebrew not found; skipping package-manager install.${NC}"
            fi
            ;;
    esac

    if [[ "$INSTALLED" != "1" ]]; then
        echo -e "${BLUE}[*] Falling back to local (no-root) platform-tools download.${NC}"
        install_platform_tools_local
    fi
fi

# Re-check after install attempts
if adb_available; then
    if ! command -v adb &> /dev/null && [[ -x "${PLATFORM_TOOLS_DIR}/adb" ]]; then
        export PATH="${PLATFORM_TOOLS_DIR}:${PATH}"
    fi
    echo -e "${GREEN}[✓] ADB ready: $(adb version | head -n1)${NC}"
else
    echo -e "${RED}[X] ADB could not be installed automatically.${NC}"
    echo -e "    Manual download: https://developer.android.com/tools/releases/platform-tools"
fi

echo ""
echo -e "${GREEN}[+] Setup complete. Next steps:${NC}"
echo -e "    1. Enable ${YELLOW}USB Debugging${NC} on your Android device (Developer Options)."
echo -e "    2. Connect the device and accept the RSA fingerprint prompt."
echo -e "    3. Run the inspector:  ${BLUE}python3 core/mdm_inspector.py${NC}"
echo -e "       or the quick scan:  ${BLUE}bash scripts/adb_check.sh${NC}"
echo -e "${BLUE}====================================================================${NC}"
