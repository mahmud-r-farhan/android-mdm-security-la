#!/usr/bin/env python3
"""
Android Enterprise Security Lab - MDM & Privilege Inspector
-----------------------------------------------------------
Module: core/mdm_inspector.py
Description: Automated, NON-DESTRUCTIVE assessment tool to identify Mobile
             Device Management (MDM) packages, Device Owner / Profile Owner
             policies, and active security frameworks via Android Debug
             Bridge (ADB). All operations are strictly read-only.

License: Apache License 2.0
Project: https://github.com/mahmud-r-farhan/android-mdm-security-la
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

TOOL_NAME = "Android Enterprise Security Lab - MDM Inspector"
TOOL_VERSION = "2.0.0"

# Default location for exported audit reports (repository-local, git-ignored)
DEFAULT_OUTPUT_DIR = "output"
DEFAULT_REPORT_NAME = "mdm_audit_report.json"

# ---------------------------------------------------------------------------
# Known MDM / device-financing lock package identifiers for lab auditing.
# Keys are package names, values are human-readable descriptions.
# ---------------------------------------------------------------------------
KNOWN_MDM_PACKAGES: Dict[str, str] = {
    # --- Commercial device-financing / EMI lock providers -----------------
    "com.payjoy.vanilla": "PayJoy Device Lock",
    "com.payjoy.agent": "PayJoy Lock Agent",
    "com.payjoy.lock": "PayJoy Lock",
    "com.shoppay.finance": "ShopUp / PayWell Lock",
    "com.singer.emilock": "Singer EMI Control",
    "com.walton.mdm": "Walton Enterprise Manager",
    "com.helloshopy.applock": "HelloShopy Financing Lock",
    "com.credpay.lock": "CredPay Financing Lock",
    "com.tappay.lock": "TapPay Device Lock",
    # --- Samsung Knox stack ------------------------------------------------
    "com.samsung.klmsagent": "Samsung KLM License Agent",
    "com.samsung.android.knox.attestation": "Samsung Knox Attestation Agent",
    "com.samsung.android.kgclient": "Samsung Knox Guard Client",
    "com.sec.knox.guard": "Samsung Knox Guard System",
    "com.sec.enterprise.knox.attestation": "Samsung Knox Enterprise Attestation",
    # --- Google / Android Enterprise ----------------------------------------
    # NOTE: com.google.android.gms is deliberately NOT listed — it exists on
    # virtually every device and would produce false positives; the actual
    # Google DPC app is com.google.android.apps.work.clouddpc below.
    "com.google.android.apps.work.clouddpc": "Android Device Policy (Google)",
    # --- Enterprise MDM / EMM suites ----------------------------------------
    "com.airwatch.androidagent": "VMware Workspace ONE / AirWatch",
    "com.microsoft.windowsintune.companyportal": "Microsoft Intune Company Portal",
    "com.mobileiron": "Ivanti / MobileIron",
    "com.meraki.sm": "Cisco Meraki Systems Manager",
    "com.soti.mobicontrol.androidwork": "SOTI MobiControl",
    "com.soti.mobicontrol.aosp": "SOTI MobiControl (AOSP)",
    "com.zimbra.mobilesync": "Zimbra Mobile Sync (MDM profile)",
    "com.manageengine.mdm.agent": "ManageEngine Mobile Device Manager",
    "com.hexnode.mdmagent": "HexNode MDM Agent",
    "com.ninjaone.mdm": "NinjaOne MDM Agent",
    "com.samsung.android.da.daagent": "Samsung Dual Agent (Knox container)",
}

# Permissions that indicate device-management capabilities when present on
# an installed app (used for heuristic enrichment of the report).
MANAGEMENT_INDICATOR_PERMISSIONS: List[str] = [
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
]


# In machine-readable (--json) mode, progress lines are redirected to stderr
# so stdout remains a pure JSON stream suitable for piping to jq etc.
_PROGRESS_STREAM = sys.stdout


def _progress(message: str) -> None:
    print(message, file=_PROGRESS_STREAM, flush=True)


class InspectorError(RuntimeError):
    """Base class for inspector-specific failures."""


class ADBNotFoundError(InspectorError):
    """Raised when the adb executable is not available on PATH."""


class DeviceConnectionError(InspectorError):
    """Raised when no authorized ADB device is attached."""


class MDMInspector:
    """Read-only diagnostic engine for Android device-management state."""

    def __init__(self, device_id: Optional[str] = None, timeout: int = 30):
        """Initialize the inspector with an optional target ADB device ID.

        Args:
            device_id: ADB serial of the target device (``adb -s <serial>``).
                When omitted and multiple devices are attached the user must
                pass ``--device`` explicitly.
            timeout: Per-command ADB timeout in seconds.
        """
        self.device_id = device_id
        self.timeout = timeout
        self.adb_base: List[str] = ["adb"] if not device_id else ["adb", "-s", device_id]
        self._verify_adb_installation()

    # ------------------------------------------------------------------
    # Low-level helpers
    # ------------------------------------------------------------------
    def _verify_adb_installation(self) -> None:
        """Check that the adb executable is available in PATH."""
        try:
            subprocess.run(
                ["adb", "version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
                timeout=self.timeout,
            )
        except FileNotFoundError as exc:
            raise ADBNotFoundError(
                "'adb' executable not found in PATH. Install Android Platform Tools "
                "(run scripts/setup.sh or scripts/setup.ps1) and try again."
            ) from exc
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            raise ADBNotFoundError(f"'adb' executable failed to run: {exc}") from exc

    def run_adb_cmd(self, args: List[str]) -> str:
        """Execute an ADB command and return its stdout as a string.

        Never raises on non-zero exit codes; returns a prefixed error string
        so report generation can continue for partially reachable devices.
        """
        cmd = self.adb_base + args
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.timeout,
            )
            if result.returncode != 0:
                stderr = (result.stderr or "").strip()
                return f"Error: {stderr or 'command failed'}"
            return (result.stdout or "").strip()
        except subprocess.TimeoutExpired:
            return "Error: command timed out"
        except (subprocess.SubprocessError, OSError) as exc:
            return f"Error: {exc}"

    # ------------------------------------------------------------------
    # Inspection steps (all strictly read-only)
    # ------------------------------------------------------------------
    def check_device_connection(self) -> bool:
        """Verify that a target device is connected and authorized via ADB."""
        output = self.run_adb_cmd(["devices"])
        lines = [
            line.strip()
            for line in output.split("\n")[1:]
            if line.strip() and not line.startswith("*")
        ]
        # Only consider devices in a usable state ("device"); flag the rest.
        usable = [line for line in lines if line.split()[-1] == "device"]

        if not lines:
            _progress("[!] No ADB devices attached. Enable USB Debugging and connect the target phone.")
            return False

        if not usable:
            _progress("[!] Device(s) attached but not authorized/unauthorized states detected:")
            for line in lines:
                _progress(f"    {line}")
            _progress("    Accept the USB-debugging RSA prompt on the device, then retry.")
            return False

        if self.device_id is None and len(usable) > 1:
            _progress("[!] Multiple devices attached; pass --device <serial> to pick one:")
            for line in usable:
                _progress(f"    {line.split()[0]}")
            return False

        serial = usable[0].split()[0]
        _progress(f"[+] Active ADB Device Detected: {serial}")
        return True

    def get_device_info(self) -> Dict[str, str]:
        """Fetch general OS and system model information."""
        return {
            "model": self.run_adb_cmd(["shell", "getprop", "ro.product.model"]),
            "manufacturer": self.run_adb_cmd(["shell", "getprop", "ro.product.manufacturer"]),
            "brand": self.run_adb_cmd(["shell", "getprop", "ro.product.brand"]),
            "android_version": self.run_adb_cmd(["shell", "getprop", "ro.build.version.release"]),
            "sdk_level": self.run_adb_cmd(["shell", "getprop", "ro.build.version.sdk"]),
            "security_patch": self.run_adb_cmd(["shell", "getprop", "ro.build.version.security_patch"]),
            "knox_version": self.run_adb_cmd(["shell", "getprop", "ro.config.knox.version"]),
        }

    @staticmethod
    def parse_dpm_output(output: str) -> Dict[str, Any]:
        """Parse ``dpm list-owners`` text into a structured dictionary.

        Exposed as a static method so it can be unit-tested without a device.
        """
        is_device_owner = "Device Owner:" in output
        is_profile_owner = "Profile Owner:" in output

        owners: List[str] = []
        for line in output.split("\n"):
            if "admin=" not in line:
                continue
            # Format: admin= ComponentInfo{com.example.mdm/com.example.mdm.AdminReceiver}
            match = re.search(r"admin=\s*ComponentInfo\{([^/}]+)", line)
            if match and match.group(1) not in owners:
                owners.append(match.group(1))

        return {
            "has_device_owner": is_device_owner,
            "has_profile_owner": is_profile_owner,
            "active_admin_packages": owners,
            "raw_dpm_output": output,
        }

    def inspect_device_owners(self) -> Dict[str, Any]:
        """Query DevicePolicyManager for registered Device/Profile Owners."""
        output = self.run_adb_cmd(["shell", "dpm", "list-owners"])
        if output.startswith("Error:"):
            return {
                "has_device_owner": False,
                "has_profile_owner": False,
                "active_admin_packages": [],
                "raw_dpm_output": output,
            }
        return self.parse_dpm_output(output)

    def scan_mdm_packages(self) -> List[Dict[str, str]]:
        """Scan installed application packages against known MDM indicators."""
        installed = self.run_adb_cmd(["shell", "pm", "list", "packages"])
        if installed.startswith("Error:"):
            return []

        detected: List[Dict[str, str]] = []
        for pkg_id, label in KNOWN_MDM_PACKAGES.items():
            if f"package:{pkg_id}" in installed:
                detected.append({"package_name": pkg_id, "description": label})
        return detected

    @staticmethod
    def assess_risk(dpm_info: Dict[str, Any], mdm_packages: List[Dict[str, str]]) -> Dict[str, Any]:
        """Derive a transparent, explainable risk classification."""
        findings: List[str] = []
        if dpm_info.get("has_device_owner"):
            findings.append("Active Device Owner policy (full-device management).")
        if dpm_info.get("has_profile_owner"):
            findings.append("Active Profile Owner (managed work profile).")
        if mdm_packages:
            findings.append(
                f"{len(mdm_packages)} known MDM/financing-lock package signature(s) installed."
            )

        if dpm_info.get("has_device_owner"):
            level = "HIGH"
        elif mdm_packages or dpm_info.get("has_profile_owner"):
            level = "MEDIUM"
        else:
            level = "LOW"

        return {"level": level, "findings": findings}

    def generate_audit_report(self) -> Dict[str, Any]:
        """Run the complete inspection and compile a structured report dict."""
        if not self.check_device_connection():
            raise DeviceConnectionError("Device connection failed")

        _progress("[*] Gathering system specifications...")
        device_info = self.get_device_info()

        _progress("[*] Auditing DevicePolicyManager (DPM) privileges...")
        dpm_info = self.inspect_device_owners()

        _progress("[*] Scanning installed packages for known MDM signatures...")
        mdm_packages = self.scan_mdm_packages()

        risk = self.assess_risk(dpm_info, mdm_packages)

        return {
            "tool": TOOL_NAME,
            "tool_version": TOOL_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "device_info": device_info,
            "device_policy_management": dpm_info,
            "detected_mdm_packages": mdm_packages,
            "risk_assessment": risk,
            "read_only_audit": True,
        }


def build_arg_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="mdm_inspector",
        description=(
            "Non-destructive MDM / Device-Policy audit utility. Inspects Device "
            "Owner and Profile Owner state, known MDM package signatures, and "
            "device metadata over ADB. Read-only: performs no state changes."
        ),
        epilog="Example: python3 core/mdm_inspector.py --json --output output/report.json",
    )
    parser.add_argument(
        "--device", "-s",
        metavar="SERIAL",
        help="ADB device serial to target (required when multiple devices are attached).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the full audit report as JSON on stdout (machine-readable mode).",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="PATH",
        help="Write the JSON report to PATH in addition to (or instead of) stdout.",
    )
    parser.add_argument(
        "--no-export",
        action="store_true",
        help="Do not write the default output/mdm_audit_report.json file.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {TOOL_VERSION}",
    )
    return parser


def export_report(report: Dict[str, Any], path: str) -> None:
    """Write the audit report to disk as pretty-printed JSON."""
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=4, ensure_ascii=False)
        handle.write("\n")


def main(argv: Optional[List[str]] = None) -> int:
    global _PROGRESS_STREAM
    args = build_arg_parser().parse_args(argv)

    # In machine-readable mode keep stderr for diagnostics, stdout pure JSON.
    if args.json:
        _PROGRESS_STREAM = sys.stderr
    else:
        print("=" * 65)
        print(f"      {TOOL_NAME.upper()}      ")
        print("=" * 65)

    try:
        inspector = MDMInspector(device_id=args.device)
        report = inspector.generate_audit_report()
    except ADBNotFoundError as exc:
        print(f"[X] Error: {exc}", file=sys.stderr)
        return 2
    except DeviceConnectionError as exc:
        print(f"[X] Error: {exc}", file=sys.stderr)
        return 1
    except InspectorError as exc:
        print(f"[X] Unexpected inspector failure: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report, indent=4, ensure_ascii=False))
    else:
        print("\n" + "=" * 30 + " AUDIT REPORT " + "=" * 30)
        print(json.dumps(report, indent=4, ensure_ascii=False))
        print("=" * 74)

    if args.output:
        export_report(report, args.output)
        _progress(f"[+] Audit report saved to '{args.output}'")
    elif not args.no_export:
        default_path = os.path.join(DEFAULT_OUTPUT_DIR, DEFAULT_REPORT_NAME)
        export_report(report, default_path)
        _progress(f"[+] Audit report saved successfully to '{default_path}'")

    return 0


if __name__ == "__main__":
    sys.exit(main())
