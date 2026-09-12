"""Tests for core/mdm_inspector.py with mocked ADB subprocess calls."""

from unittest import mock

import pytest
import mdm_inspector
from mdm_inspector import (
    ADBNotFoundError,
    MDMInspector,
    build_arg_parser,
)


class FakeCompleted:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def fake_run_factory(pm_list="", dpm_output="(empty)"):
    """Build a subprocess.run replacement answering common ADB queries."""

    def _run(cmd, **kwargs):
        args = cmd[1:] if cmd and cmd[0] == "adb" else cmd
        # Strip an optional "-s <serial>" prefix.
        if args[:2] == ["-s", "DEVICE01"] or (len(args) >= 2 and args[0] == "-s"):
            args = args[2:]

        if args == ["version"]:
            return FakeCompleted(stdout="Android Debug Bridge version 1.0.41")
        if args == ["devices"]:
            return FakeCompleted(stdout="List of devices attached\nDEVICE01\tdevice\n")
        if args[:1] == ["shell"]:
            if args[1:3] == ["dpm", "list-owners"]:
                return FakeCompleted(stdout=dpm_output)
            if args[1:4] == ["pm", "list", "packages"]:
                return FakeCompleted(stdout=pm_list)
            if args[1] == "getprop":
                return FakeCompleted(stdout="UnitTestValue")
        return FakeCompleted(stdout="")

    return _run


def test_parse_dpm_device_owner():
    output = (
        "Device Owner:\n"
        "  admin= ComponentInfo{com.example.mdm/com.example.mdm.AdminReceiver}\n"
    )
    parsed = mdm_inspector.MDMInspector.parse_dpm_output(output)
    assert parsed["has_device_owner"] is True
    assert parsed["has_profile_owner"] is False
    assert parsed["active_admin_packages"] == ["com.example.mdm"]


def test_parse_dpm_profile_owner():
    output = (
        "Profile Owner:\n"
        "  admin= ComponentInfo{com.example.dpc/com.example.dpc.PolicyCtrl}\n"
    )
    parsed = mdm_inspector.MDMInspector.parse_dpm_output(output)
    assert parsed["has_device_owner"] is False
    assert parsed["has_profile_owner"] is True
    assert parsed["active_admin_packages"] == ["com.example.dpc"]


def test_parse_dpm_empty():
    parsed = mdm_inspector.MDMInspector.parse_dpm_output("(empty)")
    assert parsed["has_device_owner"] is False
    assert parsed["has_profile_owner"] is False
    assert parsed["active_admin_packages"] == []


def test_assess_risk_levels():
    do_case = mdm_inspector.MDMInspector.assess_risk(
        {"has_device_owner": True, "has_profile_owner": False}, []
    )
    assert do_case["level"] == "HIGH"

    pkg_case = mdm_inspector.MDMInspector.assess_risk(
        {"has_device_owner": False, "has_profile_owner": False},
        [{"package_name": "com.example.mdm", "description": "x"}],
    )
    assert pkg_case["level"] == "MEDIUM"

    clean_case = mdm_inspector.MDMInspector.assess_risk(
        {"has_device_owner": False, "has_profile_owner": False}, []
    )
    assert clean_case["level"] == "LOW"
    assert clean_case["findings"] == []


def test_adb_missing_raises_typed_error():
    with mock.patch.object(
        mdm_inspector.subprocess, "run", side_effect=FileNotFoundError
    ):
        with pytest.raises(ADBNotFoundError):
            MDMInspector()


def test_scan_mdm_packages_detection():
    pm_list = (
        "package:com.android.settings\n"
        "package:com.example.mdm\n"
        "package:com.payjoy.vanilla\n"
    )
    with mock.patch.object(
        mdm_inspector.subprocess, "run", side_effect=fake_run_factory(pm_list=pm_list)
    ):
        inspector = MDMInspector(device_id="DEVICE01")
        detected = inspector.scan_mdm_packages()

    names = {item["package_name"] for item in detected}
    assert "com.payjoy.vanilla" in names
    assert "com.example.mdm" not in names  # not in the known-signature DB
    assert all("description" in item for item in detected)


def test_full_report_generation():
    dpm_output = (
        "Device Owner:\n"
        "  admin= ComponentInfo{com.payjoy.vanilla/com.payjoy.vanilla.Admin}\n"
    )
    pm_list = "package:com.payjoy.vanilla\npackage:com.android.settings\n"
    with mock.patch.object(
        mdm_inspector.subprocess,
        "run",
        side_effect=fake_run_factory(pm_list=pm_list, dpm_output=dpm_output),
    ):
        inspector = MDMInspector(device_id="DEVICE01")
        report = inspector.generate_audit_report()

    assert report["device_policy_management"]["has_device_owner"] is True
    assert report["device_policy_management"]["active_admin_packages"] == ["com.payjoy.vanilla"]
    assert report["detected_mdm_packages"][0]["package_name"] == "com.payjoy.vanilla"
    assert report["risk_assessment"]["level"] == "HIGH"
    assert report["read_only_audit"] is True
    assert "generated_at" in report


def test_cli_help_exits_zero(capsys):
    parser = build_arg_parser()
    with pytest.raises(SystemExit) as excinfo:
        parser.parse_args(["--help"])
    assert excinfo.value.code == 0
    captured = capsys.readouterr()
    assert "--device" in captured.out
    assert "--json" in captured.out


def test_cli_json_flag_parsed():
    args = build_arg_parser().parse_args(["--json", "--device", "ABC123", "--no-export"])
    assert args.json is True
    assert args.device == "ABC123"
    assert args.no_export is True
