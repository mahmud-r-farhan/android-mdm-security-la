<#
.SYNOPSIS
    Android Enterprise Security Lab - Automated Windows Setup Script
.DESCRIPTION
    Checks Python 3 and Android Platform Tools (ADB) availability on Windows,
    providing automated setup instructions or downloading platform-tools if needed.
.NOTES
    File: scripts/setup.ps1
    License: Apache License 2.0
#>

$ErrorActionPreference = "Stop"

Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host "   Android Enterprise Security Lab - Windows Environment Setup      " -ForegroundColor Cyan
Write-Host "====================================================================" -ForegroundColor Cyan

# 1. Check Python 3
try {
    $pyVersion = python --version 2>&1
    Write-Host "[+] Python detected: $pyVersion" -ForegroundColor Green
} catch {
    Write-Host "[!] Python 3 not detected in PATH. Please install Python 3.9+ from https://python.org" -ForegroundColor Yellow
}

# 2. Check ADB
if (Get-Command adb -ErrorAction SilentlyContinue) {
    $adbVersion = adb version | Select-Object -First 1
    Write-Host "[+] Android ADB detected: $adbVersion" -ForegroundColor Green
} else {
    Write-Host "[!] ADB executable not found in PATH." -ForegroundColor Yellow
    Write-Host "[*] Downloading official Google Platform Tools for Windows..." -ForegroundColor Cyan

    $zipPath = "$env:TEMP\platform-tools-latest-windows.zip"
    $extractPath = "$env:USERPROFILE\platform-tools"
    $downloadUrl = "https://dl.google.com/android/repository/platform-tools-latest-windows.zip"

    try {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath
        Write-Host "[+] Downloaded platform-tools zip to $zipPath" -ForegroundColor Green

        if (Test-Path $extractPath) {
            Remove-Item -Recurse -Force $extractPath
        }

        Expand-Archive -Path $zipPath -DestinationPath $env:USERPROFILE -Force
        Write-Host "[+] Extracted Android Platform-Tools to $extractPath" -ForegroundColor Green
        Write-Host "[*] Add '$extractPath\platform-tools' to your User Environment PATH to enable 'adb' globally." -ForegroundColor Yellow
    } catch {
        Write-Host "[X] Failed to auto-download platform-tools: $_" -ForegroundColor Red
        Write-Host "[*] Please manually download from: https://developer.android.com/tools/releases/platform-tools" -ForegroundColor Yellow
    }
}

Write-Host "`n====================================================================" -ForegroundColor Cyan
Write-Host "[+] Setup check complete. Run 'python core/mdm_inspector.py' to launch inspector." -ForegroundColor Green
Write-Host "====================================================================" -ForegroundColor Cyan
