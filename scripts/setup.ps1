<#
.SYNOPSIS
    Android Enterprise Security Lab - Automated Windows Setup Script
.DESCRIPTION
    Checks Python 3 and Android Platform Tools (ADB) availability on Windows.
    When ADB is missing it downloads Google's official platform-tools,
    extracts them to %LOCALAPPDATA%\Android\platform-tools, and registers the
    directory on the *user* PATH (no administrator rights required).
.PARAMETER SkipDownload
    Only check the environment; do not download platform-tools.
.NOTES
    File: scripts/setup.ps1
    License: Apache License 2.0
#>

[CmdletBinding()]
param(
    [switch]$SkipDownload
)

$ErrorActionPreference = "Stop"

Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host "   Android Enterprise Security Lab - Windows Environment Setup      " -ForegroundColor Cyan
Write-Host "====================================================================" -ForegroundColor Cyan

# Modern TLS required for dl.google.com on older PowerShell runtimes.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ---------------------------------------------------------------------------
# 1. Check Python 3
# ---------------------------------------------------------------------------
function Find-Python {
    foreach ($candidate in @("python", "python3", "py")) {
        try {
            $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
            if ($cmd) { return $candidate }
        } catch { <# ignore #> }
    }
    return $null
}

$pythonCmd = Find-Python
if ($pythonCmd) {
    $pyVersion = & $pythonCmd --version 2>&1
    Write-Host "[+] Python detected: $pyVersion" -ForegroundColor Green
} else {
    Write-Host "[!] Python 3 not detected in PATH." -ForegroundColor Yellow
    Write-Host "    Install Python 3.9+ from https://python.org (enable 'Add to PATH')." -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# 2. Check / install ADB platform-tools
# ---------------------------------------------------------------------------
$installPath = Join-Path $env:LOCALAPPDATA "Android\platform-tools"
$downloadUrl = "https://dl.google.com/android/repository/platform-tools-latest-windows.zip"

function Test-Adb {
    if (Get-Command adb -ErrorAction SilentlyContinue) { return $true }
    if (Test-Path (Join-Path $installPath "adb.exe")) { return $true }
    return $false
}

function Add-ToUserPath([string]$dir) {
    $current = [Environment]::GetEnvironmentVariable("Path", "User")
    if (-not $current) { $current = "" }
    $entries = $current -split ";" | Where-Object { $_ -ne "" }
    if ($entries -contains $dir) {
        Write-Host "[=] '$dir' is already on the user PATH." -ForegroundColor Cyan
        return
    }
    [Environment]::SetEnvironmentVariable("Path", ($current.TrimEnd(";") + ";" + $dir), "User")
    Write-Host "[+] Registered '$dir' on the user PATH." -ForegroundColor Green
    Write-Host "[!] Open a NEW terminal for the PATH change to take effect." -ForegroundColor Yellow
}

if (Test-Adb) {
    $adbExe = if (Get-Command adb -ErrorAction SilentlyContinue) { "adb" } else { Join-Path $installPath "adb.exe" }
    $adbVersion = & $adbExe version 2>&1 | Select-Object -First 1
    Write-Host "[+] Android ADB detected: $adbVersion" -ForegroundColor Green
    if (-not (Get-Command adb -ErrorAction SilentlyContinue)) {
        Add-ToUserPath $installPath
    }
} elseif ($SkipDownload) {
    Write-Host "[!] ADB missing and -SkipDownload specified; nothing installed." -ForegroundColor Yellow
} else {
    Write-Host "[!] ADB executable not found in PATH." -ForegroundColor Yellow
    Write-Host "[*] Downloading official Google Platform Tools for Windows..." -ForegroundColor Cyan

    $zipPath = Join-Path $env:TEMP "platform-tools-latest-windows.zip"
    try {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -UseBasicParsing
        Write-Host "[+] Downloaded platform-tools to $zipPath" -ForegroundColor Green

        if (Test-Path $installPath) {
            Remove-Item -Recurse -Force $installPath
        }
        $parent = Split-Path $installPath -Parent
        if (-not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }

        Expand-Archive -Path $zipPath -DestinationPath $parent -Force
        Write-Host "[+] Extracted Android Platform-Tools to $installPath" -ForegroundColor Green
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue

        Add-ToUserPath $installPath
    } catch {
        Write-Host "[X] Failed to auto-download platform-tools: $_" -ForegroundColor Red
        Write-Host "[*] Manual download: https://developer.android.com/tools/releases/platform-tools" -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# 3. Optional OEM driver diagnostics (Windows-only extra)
# ---------------------------------------------------------------------------
$driverScript = Join-Path $PSScriptRoot "oem_driver_check.ps1"
if (Test-Path $driverScript) {
    Write-Host ""
    Write-Host "[*] Running OEM ADB driver diagnostics..." -ForegroundColor Cyan
    & $driverScript
}

Write-Host ""
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host "[+] Setup check complete." -ForegroundColor Green
Write-Host "    Next: enable USB Debugging, connect the device, then run" -ForegroundColor Cyan
Write-Host "        python core/mdm_inspector.py" -ForegroundColor White
Write-Host "    (open a new terminal first if PATH was just updated)" -ForegroundColor DarkGray
Write-Host "====================================================================" -ForegroundColor Cyan
