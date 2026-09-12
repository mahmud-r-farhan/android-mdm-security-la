#!/usr/bin/env python3
"""
Android Enterprise Security Lab - MDM & Privilege Inspector
-----------------------------------------------------------
Module: core/mdm_inspector.py
Description: Automated assessment tool to identify Mobile Device Management (MDM) 
             packages, Device Owner / Profile Owner policies, and active security 
             frameworks via Android Debug Bridge (ADB).

License: Apache License 2.0
Project: https://github.com/your-username/android-enterprise-security-lab
"""

import subprocess
import json
import sys
import os
import re
from typing import Dict, List, Any, Optional

# List of known MDM and device lock package identifiers for lab auditing
KNOWN_MDM_PACKAGES = {
    # Commercial & EMI Lock Providers
    "com.payjoy.vanilla": "PayJoy Device Lock",
    "com.shoppay.finance": "ShopUp / PayWell Lock",
    "com.singer.emilock": "Singer EMI Control",
    "com.walton.mdm": "Walton Enterprise Manager",
    "com.samsung.klms": "Samsung Knox License Management",
    "com.samsung.android.knox.attestation": "Samsung Knox Attestation Agent",
    "com.sec.knox.guard": "Samsung Knox Guard System",
    
    # Enterprise MDM Solutions
    "com.google.android.apps.work.clouddpc": "Android Device Policy (Google)",
    "com.airwatch.androidagent": "VMware Workspace ONE / AirWatch",
    "com.microsoft.windowsintune.companyportal": "Microsoft Intune Company Portal",
    "com.mobileiron": "Ivanti / MobileIron",
    "com.meraki.sm": "Cisco Meraki System Manager",
    "com.soti.mobicontrol.androidwork": "SOTI MobiControl"
}

class MDMInspector:
    def __init__(self, device_id: Optional[str] = None):
        """Initialize the inspector with an optional target ADB device ID."""
        self.device_id = device_id
        self.adb_base = ["adb"] if not device_id else ["adb", "-s", device_id]
        self._verify_adb_installation()

    def _verify_adb_installation(self) -> None:
        """Check if ADB executable is available in PATH."""
        try:
            subprocess.run(["adb", "version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        except (FileNotFoundError, subprocess.CalledProcessError):
            print("[X] Error: 'adb' executable not found in PATH. Please install Android Platform Tools.")
            sys.exit(1)

    def run_adb_cmd(self, args: List[str]) -> str:
        """Execute an ADB shell command and return output string."""
        cmd = self.adb_base + args
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            return f"Error: {e.stderr.strip()}"

    def check_device_connection(self) -> bool:
        """Verify that a target device is connected via ADB."""
        output = self.run_adb_cmd(["devices"])
        lines = [line for line in output.split("\n")[1:] if line.strip()]
        if not lines:
            print("[!] No ADB devices attached. Please enable USB Debugging and connect your target phone.")
            return False
        print(f"[+] Active ADB Device Detected: {lines[0].split()[0]}")
        return True

    def get_device_info(self) -> Dict[str, str]:
        """Fetch general OS and system model information."""
        return {
            "model": self.run_adb_cmd(["shell", "getprop", "ro.product.model"]),
            "manufacturer": self.run_adb_cmd(["shell", "getprop", "ro.product.manufacturer"]),
            "android_version": self.run_adb_cmd(["shell", "getprop", "ro.build.version.release"]),
            "sdk_level": self.run_adb_cmd(["shell", "getprop", "ro.build.version.sdk"]),
            "knox_version": self.run_adb_cmd(["shell", "getprop", "ro.config.knox.version"])
        }

    def inspect_device_owners(self) -> Dict[str, Any]:
        """Query DevicePolicyManager service for registered Device Owner or Profile Owner."""
        output = self.run_adb_cmd(["shell", "dpm", "list-owners"])
        is_device_owner = "Device Owner:" in output
        is_profile_owner = "Profile Owner:" in output
        
        owners = []
        if is_device_owner or is_profile_owner:
            for line in output.split("\n"):
                if "admin=" in line:
                    match = re.search(r'admin= ComponentInfo\{([^/]+)', line)
                    if match:
                        owners.append(match.group(1))

        return {
            "has_device_owner": is_device_owner,
            "has_profile_owner": is_profile_owner,
            "active_admin_packages": owners,
            "raw_dpm_output": output
        }

    def scan_mdm_packages(self) -> List[Dict[str, str]]:
        """Scan installed application packages against known MDM indicators."""
        installed = self.run_adb_cmd(["shell", "pm", "list", "packages"])
        detected = []

        for pkg_id, label in KNOWN_MDM_PACKAGES.items():
            if f"package:{pkg_id}" in installed:
                detected.append({
                    "package_name": pkg_id,
                    "description": label
                })

        return detected

    def generate_audit_report((self) -> Dict[str, Any]:
        """Run complete inspection and compile results into a structured dictionary."""
        if not self.check_device_connection():
            return {"error": "Device connection failed"}

        print("[*] Gathering system specifications...")
        device_info = self.get_device_info()

        print("[*] Auditing DevicePolicyManager (DPM) privileges...")
        dpm_info = self.inspect_device_owners()

        print("[*] Scanning installed system/third-party MDM packages...")
        mdm_packages = self.scan_mdm_packages()

        report = {
            "device_info": device_info,
            "device_policy_management": dpm_info,
            "detected_mdm_packages": mdm_packages,
            "risk_assessment": "HIGH" if (dpm_info["has_device_owner"] or mdm_packages) else "LOW"
        }

        return report

def main():
    print("=" * 65)
    print("      ANDROID ENTERPRISE SECURITY LAB - MDM INSPECTOR UTILITY      ")
    print("=" * 65)

    inspector = MDMInspector()
    report = inspector.generate_audit_report()

    if "error" in report:
        sys.exit(1)

    print("\n" + "=" * 30 + " AUDIT REPORT " + "=" * 30)
    print(json.dumps(report, indent=4))
    print("=" * 74)

    # Export report to JSON file for laboratory tracking
    os.makedirs("output", exist_ok=True)
    report_file = "output/mdm_audit_report.json"
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)
    print(f"\n[+] Audit report saved successfully to '{report_file}'")

if __name__ == "__main__":
    main()
