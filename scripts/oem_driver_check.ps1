<#
.SYNOPSIS
    Android Enterprise Security Lab - OEM ADB Driver Diagnostic Helper
.DESCRIPTION
    Non-destructive Windows diagnostic that inspects Device Manager (PnP
    devices) for connected Android devices, verifies whether a working ADB
    interface driver is present, and identifies common OEM vendor IDs
    (Samsung, Google, MediaTek, Xiaomi, OnePlus, Huawei) so the correct
    driver package can be installed when devices show up as unknown/error.
.NOTES
    File: scripts/oem_driver_check.ps1
    License: Apache License 2.0
#>

$ErrorActionPreference = "Continue"

Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host "        OEM ADB Driver Diagnostic (read-only device scan)           " -ForegroundColor Cyan
Write-Host "====================================================================" -ForegroundColor Cyan

# Known Android USB vendor IDs (hex) -> OEM name
$VendorIds = @{
    "04E8" = "Samsung"
    "18D1" = "Google / Nexus / Pixel"
    "0E8D" = "MediaTek (reference design)"
    "2717" = "Xiaomi"
    "12D1" = "Huawei / Honor"
    "2A70" = "OnePlus"
    "0BB4" = "HTC"
    "0FCE" = "Sony"
    "22D9" = "OPPO"
    "2B70" = "Vivo / FunTouch"
    "1949" = "Amazon (Fire)"
    "1004" = "LG"
    "0489" = "Foxconn (various OEM)"
    "2A45" = "Meizu"
    "2B4C" = "Realme"
}

$androidKeywords = @(
    "android", "adb", "mtp", "samsung", "pixel", "galaxy",
    "knox", "mediatek", "xiaomi", "oneplus", "huawei", "oppo", "vivo"
)

function Get-PnpDevicesSafe {
    try {
        return @(Get-PnpDevice -PresentOnly -ErrorAction Stop)
    } catch {
        Write-Host "[!] Get-PnpDevice unavailable; falling back to CIM." -ForegroundColor Yellow
        try {
            return @(Get-CimInstance Win32_PnPEntity -ErrorAction Stop |
                Where-Object { $_.Status -ne $null })
        } catch {
            Write-Host "[X] Unable to enumerate devices: $_" -ForegroundColor Red
            return @()
        }
    }
}

$devices = Get-PnpDevicesSafe
if ($devices.Count -eq 0) {
    Write-Host "[X] No PnP devices could be enumerated." -ForegroundColor Red
    exit 1
}

$androidDevices = @()
foreach ($device in $devices) {
    $name = $device.FriendlyName
    $instance = $device.InstanceId
    if (-not $name -or -not $instance) { continue }

    $lowerName = $name.ToLower()
    $lowerInstance = $instance.ToLower()

    $keywordHit = $false
    foreach ($keyword in $androidKeywords) {
        if ($lowerName.Contains($keyword) -or $lowerInstance.Contains($keyword)) {
            $keywordHit = $true
            break
        }
    }
    $vidHit = $false
    foreach ($vid in $VendorIds.Keys) {
        if ($lowerInstance.Contains("vid_$($vid.ToLower())")) { $vidHit = $true; break }
    }

    if ($keywordHit -or $vidHit) {
        $androidDevices += $device
    }
}

if ($androidDevices.Count -eq 0) {
    Write-Host "[=] No Android device currently visible in Device Manager." -ForegroundColor Yellow
    Write-Host "    Connect a device over USB (unlock screen, allow file transfer) and re-run." -ForegroundColor DarkGray
    exit 0
}

Write-Host "[+] Found $($androidDevices.Count) Android-related device entry/entries:`n" -ForegroundColor Green

$problemFound = $false
foreach ($device in $androidDevices) {
    $name = $device.FriendlyName
    $instance = $device.InstanceId
    $status = $device.Status
    $vendor = "Unknown OEM"

    foreach ($vid in $VendorIds.Keys) {
        if ($instance -match "VID_$vid") { $vendor = $VendorIds[$vid]; break }
    }

    $icon = if ($status -eq "OK") { "[OK] " } else { "[!!] " }
    $color = if ($status -eq "OK") { "Green" } else { "Red" }
    Write-Host ("  {0}{1}" -f $icon, $name) -ForegroundColor $color
    Write-Host ("        Vendor : {0}" -f $vendor)
    Write-Host ("        Status : {0}" -f $status)
    Write-Host ("        ID     : {0}" -f $instance)

    if ($status -ne "OK") {
        $problemFound = $true
    }

    if ($name -match "ADB Interface|Android Composite ADB|Android ADB") {
        Write-Host "        -> ADB interface driver is present." -ForegroundColor DarkGreen
    }
    Write-Host ""
}

if ($problemFound) {
    Write-Host "[!] One or more devices are in an error state (missing/faulty driver)." -ForegroundColor Yellow
    Write-Host "    Recommended driver packages:" -ForegroundColor Yellow
    Write-Host "      - Samsung      : Samsung USB Drivers  https://developer.samsung.com/android-usb-driver"
    Write-Host "      - Google/Pixel : Google USB Driver (Android Studio SDK Manager)"
    Write-Host "      - Others       : OEM support page, or universal ADB driver (e.g. ClockworkMod)"
    Write-Host "    After installing, unplug/replug the device and re-run this diagnostic."
} else {
    Write-Host "[+] All detected Android devices report healthy driver status." -ForegroundColor Green
}

Write-Host "====================================================================" -ForegroundColor Cyan
