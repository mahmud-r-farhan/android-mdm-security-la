#!/usr/bin/env python3
"""
Android Enterprise Security Lab - APK Manifest & Permission Analyzer
--------------------------------------------------------------------
Module: core/apk_analyzer.py
Description: NON-DESTRUCTIVE static analysis of Android APK files. Decodes
             the compiled ``AndroidManifest.xml`` (pure-Python AXML parser,
             no external tooling required) and flags device-management,
             overlay, and persistence capabilities such as:

               * ``android.permission.BIND_DEVICE_ADMIN``
               * ``MANAGE_DEVICE_POLICY_*`` permission families
               * ``SYSTEM_ALERT_WINDOW`` / ``INTERNAL_SYSTEM_WINDOW``
                 (lock-screen overlay capability)
               * ``DeviceAdminReceiver`` component declarations
               * Boot-completion receivers and accessibility services

             The tool never executes the APK and never modifies it.

License: Apache License 2.0
"""

import argparse
import json
import os
import sys
import zipfile
from typing import Any, Dict, List, Optional

try:  # Package-relative import (python -m core.apk_analyzer)
    from core.axml_parser import AXMLFormatError, AXMLNode, parse_axml
except ImportError:  # Direct script execution (python core/apk_analyzer.py)
    from axml_parser import AXMLFormatError, AXMLNode, parse_axml

TOOL_NAME = "Android Enterprise Security Lab - APK Manifest Analyzer"
TOOL_VERSION = "1.0.0"

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# Permissions that grant device-management, overlay, or persistence powers.
# Maps permission -> (severity, rationale).
MANAGEMENT_PERMISSIONS: Dict[str, Dict[str, str]] = {
    "android.permission.BIND_DEVICE_ADMIN": {
        "severity": "HIGH",
        "rationale": "Allows the app to act as / bind a Device Administrator.",
    },
    "android.permission.SYSTEM_ALERT_WINDOW": {
        "severity": "HIGH",
        "rationale": "Draws over other apps; used for non-dismissible lock overlays.",
    },
    "android.permission.INTERNAL_SYSTEM_WINDOW": {
        "severity": "HIGH",
        "rationale": "System-grade window creation (signature permission).",
    },
    "android.permission.RECEIVE_BOOT_COMPLETED": {
        "severity": "MEDIUM",
        "rationale": "Auto-starts components at boot (persistence mechanism).",
    },
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": {
        "severity": "MEDIUM",
        "rationale": "Exempts the app from Doze; keeps agents always alive.",
    },
    "android.permission.FOREGROUND_SERVICE": {
        "severity": "LOW",
        "rationale": "Runs persistent foreground services.",
    },
    "android.permission.QUERY_ALL_PACKAGES": {
        "severity": "MEDIUM",
        "rationale": "Full inventory of installed applications.",
    },
    "android.permission.WRITE_SECURE_SETTINGS": {
        "severity": "HIGH",
        "rationale": "Can toggle secure system settings (signature permission).",
    },
    "android.permission.MANAGE_USERS": {
        "severity": "MEDIUM",
        "rationale": "Controls user/profile creation (enterprise feature).",
    },
    "android.permission.READ_PHONE_STATE": {
        "severity": "LOW",
        "rationale": "Reads telephony identity (IMEI etc.) often used by lock agents.",
    },
    "android.permission.BIND_ACCESSIBILITY_SERVICE": {
        "severity": "HIGH",
        "rationale": "Accessibility-service binding; powerful input interception.",
    },
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": {
        "severity": "MEDIUM",
        "rationale": "Reads all notifications (2FA interception surface).",
    },
    "android.permission.REQUEST_INSTALL_PACKAGES": {
        "severity": "MEDIUM",
        "rationale": "Silently installs additional payloads.",
    },
    "android.permission.PACKAGE_USAGE_STATS": {
        "severity": "MEDIUM",
        "rationale": "Usage statistics access (app activity monitoring).",
    },
}

# Prefix-matched permission families (all MANAGE_DEVICE_POLICY_* variants).
MANAGEMENT_PERMISSION_PREFIXES: List[str] = ["android.permission.MANAGE_DEVICE_POLICY_"]

DEVICE_ADMIN_META_DATA = "android.app.device_admin"
ACCESSIBILITY_META_DATA = "android.accessibilityservice"


class APKAnalysisError(RuntimeError):
    """Raised when an APK cannot be statically analyzed."""


def _attr(node: AXMLNode, name: str) -> Optional[Any]:
    """Read an android-namespaced attribute, falling back to plain name."""
    namespaced = f"{{{ANDROID_NS}}}{name}"
    if namespaced in node.attributes:
        return node.attributes[namespaced]
    return node.attributes.get(name)


def _classify_permission(permission: str) -> Optional[Dict[str, str]]:
    """Return severity/rationale for a permission, if it is management-related."""
    if permission in MANAGEMENT_PERMISSIONS:
        return MANAGEMENT_PERMISSIONS[permission]
    for prefix in MANAGEMENT_PERMISSION_PREFIXES:
        if permission.startswith(prefix):
            return {
                "severity": "HIGH",
                "rationale": "DevicePolicyManager control capability "
                "(Android Enterprise device-management API surface).",
            }
    return None


def _readable(value: Any) -> Any:
    """Render resource-reference integers (e.g. versionName="@string/x")."""
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return value
    if isinstance(value, int) and value > 0x01000000:
        return f"@0x{value:08x}"
    return value


def analyze_manifest_bytes(manifest: bytes) -> Dict[str, Any]:
    """Analyze raw compiled AndroidManifest.xml bytes.

    Args:
        manifest: Binary contents of ``AndroidManifest.xml``.

    Returns:
        Structured analysis dictionary.
    """
    root = parse_axml(manifest)
    if root.tag != "manifest":
        raise APKAnalysisError(
            f"Unexpected manifest root element <{root.tag}> (expected <manifest>)"
        )

    package_name = root.attributes.get("package") or "<unknown>"
    version_name = root.attributes.get("versionName")
    version_code = root.attributes.get("versionCode")

    permissions: List[str] = []
    for node in root.find_all("uses-permission"):
        name = _attr(node, "name")
        if isinstance(name, str) and name:
            permissions.append(name)

    uses_sdk = root.find("uses-sdk")
    min_sdk = _attr(uses_sdk, "minSdkVersion") if uses_sdk is not None else None
    target_sdk = _attr(uses_sdk, "targetSdkVersion") if uses_sdk is not None else None

    app_node = root.find("application")
    app_label = _attr(app_node, "label") if app_node is not None else None

    # --- capability flagging ----------------------------------------------
    flagged_permissions: List[Dict[str, str]] = []
    for permission in permissions:
        classification = _classify_permission(permission)
        if classification:
            flagged_permissions.append(
                {"permission": permission, **classification}
            )

    components = analyze_components(root)

    indicators: List[str] = []
    if any(item["permission"] == "android.permission.BIND_DEVICE_ADMIN"
           for item in flagged_permissions) or components["device_admin_receivers"]:
        indicators.append("Device Administrator capability (DPM agent).")
    if any(item["permission"] == "android.permission.SYSTEM_ALERT_WINDOW"
           for item in flagged_permissions):
        indicators.append("System overlay capability (potential lock screen).")
    if components["boot_receivers"]:
        indicators.append("Boot-time persistence (BOOT_COMPLETED receivers).")
    if components["accessibility_services"]:
        indicators.append("Accessibility service (input interception surface).")
    if any(p.startswith("android.permission.MANAGE_DEVICE_POLICY_") for p in permissions):
        indicators.append("Android Enterprise MANAGE_DEVICE_POLICY_* controls.")

    severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
    if indicators:
        max_severity = max(
            (severity_rank[item["severity"]] for item in flagged_permissions),
            default=2,
        )
        overall = {1: "LOW", 2: "MEDIUM", 3: "HIGH"}[max_severity]
    else:
        overall = "NONE"

    return {
        "package_name": package_name,
        "version_name": _readable(version_name),
        "version_code": version_code,
        "min_sdk_version": min_sdk,
        "target_sdk_version": target_sdk,
        "application_label": _readable(app_label),
        "declared_permissions_count": len(permissions),
        "declared_permissions": permissions,
        "management_related_permissions": flagged_permissions,
        "components": components,
        "management_indicators": indicators,
        "management_capability_level": overall,
    }


def analyze_components(root: AXMLNode) -> Dict[str, List[Dict[str, Any]]]:
    """Extract device-management-relevant components from the manifest tree."""
    device_admin_receivers: List[Dict[str, Any]] = []
    boot_receivers: List[Dict[str, Any]] = []
    accessibility_services: List[Dict[str, Any]] = []
    overlay_activities: List[Dict[str, Any]] = []

    for receiver in root.find_all("receiver"):
        name = _attr(receiver, "name") or "<unnamed>"
        permission = _attr(receiver, "permission") or ""
        intents = [
            _attr(action, "name")
            for action in receiver.find_all("action")
            if _attr(action, "name")
        ]
        meta_names = [
            _attr(meta, "name") for meta in receiver.find_all("meta-data")
        ]

        entry = {"component": name, "permission": permission, "intent_filters": intents}

        if permission == "android.permission.BIND_DEVICE_ADMIN" or \
                DEVICE_ADMIN_META_DATA in meta_names:
            device_admin_receivers.append(entry)
        if "android.intent.action.BOOT_COMPLETED" in intents:
            boot_receivers.append(entry)

    for service in root.find_all("service"):
        name = _attr(service, "name") or "<unnamed>"
        permission = _attr(service, "permission") or ""
        meta_names = [_attr(meta, "name") for meta in service.find_all("meta-data")]
        if permission == "android.permission.BIND_ACCESSIBILITY_SERVICE" or \
                ACCESSIBILITY_META_DATA in meta_names:
            accessibility_services.append(
                {"component": name, "permission": permission}
            )

    for activity in root.find_all("activity"):
        name = _attr(activity, "name") or "<unnamed>"
        exclude_from_recents = _attr(activity, "excludeFromRecents")
        task_affinity = _attr(activity, "taskAffinity")
        if exclude_from_recents is True or task_affinity == "":
            overlay_activities.append(
                {
                    "component": name,
                    "exclude_from_recents": exclude_from_recents,
                    "task_affinity": task_affinity,
                }
            )

    return {
        "device_admin_receivers": device_admin_receivers,
        "boot_receivers": boot_receivers,
        "accessibility_services": accessibility_services,
        "stealth_or_overlay_activities": overlay_activities,
    }


def analyze_apk(apk_path: str) -> Dict[str, Any]:
    """Analyze an APK file and return the structured report.

    Args:
        apk_path: Filesystem path to the APK archive.

    Raises:
        APKAnalysisError: On unreadable/invalid archives or manifests.
    """
    if not os.path.isfile(apk_path):
        raise APKAnalysisError(f"APK not found: {apk_path}")

    try:
        with zipfile.ZipFile(apk_path, "r") as archive:
            if "AndroidManifest.xml" not in archive.namelist():
                raise APKAnalysisError(
                    "Archive does not contain AndroidManifest.xml (not a valid APK?)"
                )
            manifest_bytes = archive.read("AndroidManifest.xml")
    except zipfile.BadZipFile as exc:
        raise APKAnalysisError(f"File is not a valid APK/ZIP archive: {exc}") from exc
    except OSError as exc:
        raise APKAnalysisError(f"Cannot read APK file: {exc}") from exc

    # Sanity check: compiled manifests start with RES_XML_TYPE (0x0003).
    if len(manifest_bytes) < 4 or manifest_bytes[0:2] != b"\x03\x00":
        raise APKAnalysisError(
            "AndroidManifest.xml appears to be plain text; this tool analyzes "
            "compiled binary manifests from real APK builds."
        )

    try:
        report = analyze_manifest_bytes(manifest_bytes)
    except AXMLFormatError as exc:
        raise APKAnalysisError(f"Failed to parse binary manifest: {exc}") from exc

    report["apk_path"] = os.path.abspath(apk_path)
    report["apk_size_bytes"] = os.path.getsize(apk_path)
    return report


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apk_analyzer",
        description=(
            "Static, read-only analysis of APK manifests for device-management "
            "(MDM / DeviceAdmin / overlay) capabilities. No code is executed."
        ),
        epilog="Example: python3 core/apk_analyzer.py sample.apk --json",
    )
    parser.add_argument("apk", metavar="APK", help="Path to the APK file to analyze.")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the full analysis as JSON on stdout.",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="PATH",
        help="Write the JSON analysis to PATH.",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {TOOL_VERSION}"
    )
    return parser


def print_human_report(report: Dict[str, Any]) -> None:
    """Render a readable console summary of an analysis report."""
    print("=" * 65)
    print(f"      {TOOL_NAME.upper()}      ")
    print("=" * 65)
    print(f"  APK             : {report.get('apk_path')}")
    print(f"  Package         : {report['package_name']}")
    if report.get("version_name") or report.get("version_code"):
        print(f"  Version         : {report.get('version_name')} "
              f"(code {report.get('version_code')})")
    print(f"  SDK             : min={report.get('min_sdk_version')} "
          f"target={report.get('target_sdk_version')}")
    print(f"  Permissions     : {report['declared_permissions_count']} declared")
    print()

    print("[*] Management-related permissions:")
    if report["management_related_permissions"]:
        for item in report["management_related_permissions"]:
            print(f"    [{item['severity']:6s}] {item['permission']}")
            print(f"             {item['rationale']}")
    else:
        print("    (none detected)")

    print()
    print("[*] Device-management components:")
    comps = report["components"]
    for label, key in (
        ("DeviceAdmin receivers", "device_admin_receivers"),
        ("Boot receivers", "boot_receivers"),
        ("Accessibility services", "accessibility_services"),
        ("Stealth/overlay activities", "stealth_or_overlay_activities"),
    ):
        entries = comps[key]
        if entries:
            for entry in entries:
                print(f"    {label}: {entry.get('component')}")
        else:
            print(f"    {label}: none")

    print()
    print("[*] Management indicators:")
    if report["management_indicators"]:
        for indicator in report["management_indicators"]:
            print(f"    - {indicator}")
    else:
        print("    - No MDM-style management capabilities detected.")
    print()
    print(f"[=] Management capability level: {report['management_capability_level']}")
    print("=" * 65)


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)

    try:
        report = analyze_apk(args.apk)
    except APKAnalysisError as exc:
        print(f"[X] Error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report, indent=4, ensure_ascii=False))
    else:
        print_human_report(report)

    if args.output:
        directory = os.path.dirname(args.output)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=4, ensure_ascii=False)
            handle.write("\n")
        print(f"[+] Analysis saved to '{args.output}'")

    return 0


if __name__ == "__main__":
    sys.exit(main())
