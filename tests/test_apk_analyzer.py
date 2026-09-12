"""Tests for core/apk_analyzer.py using synthetic APK archives."""

import zipfile

import pytest
from apk_analyzer import APKAnalysisError, analyze_apk, analyze_manifest_bytes
from axml_builder import build_sample_mdm_manifest


def _write_apk(tmp_path, manifest_bytes):
    """Create a minimal APK (zip) containing the given manifest."""
    apk_path = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk_path, "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest_bytes)
        archive.writestr("classes.dex", b"not-a-real-dex")
    return str(apk_path)


def test_full_apk_analysis_detects_mdm_capabilities(tmp_path):
    apk = _write_apk(tmp_path, build_sample_mdm_manifest())
    report = analyze_apk(apk)

    assert report["package_name"] == "com.example.mdmtest"
    assert report["version_name"] == "1.4.2"
    assert report["version_code"] == 42
    assert report["min_sdk_version"] == 24
    assert report["target_sdk_version"] == 33
    assert report["declared_permissions_count"] == 5

    flagged = {item["permission"] for item in report["management_related_permissions"]}
    assert "android.permission.BIND_DEVICE_ADMIN" in flagged
    assert "android.permission.SYSTEM_ALERT_WINDOW" in flagged
    assert "android.permission.MANAGE_DEVICE_POLICY_LOCK_TASK" in flagged
    # INTERNET must NOT be flagged as management-related.
    assert "android.permission.INTERNET" not in flagged

    comps = report["components"]
    assert comps["device_admin_receivers"][0]["component"] == "com.example.mdmtest.AdminReceiver"
    assert comps["boot_receivers"][0]["component"] == "com.example.mdmtest.BootReceiver"

    assert "Device Administrator capability (DPM agent)." in report["management_indicators"]
    assert "Boot-time persistence (BOOT_COMPLETED receivers)." in report["management_indicators"]
    assert report["management_capability_level"] == "HIGH"


def test_analyze_manifest_bytes_directly():
    report = analyze_manifest_bytes(build_sample_mdm_manifest(utf8=True))
    assert report["package_name"] == "com.example.mdmtest"
    assert report["management_capability_level"] == "HIGH"


def test_benign_manifest_reports_none(tmp_path):
    from axml_builder import AXMLBuilder

    builder = AXMLBuilder()
    builder.start("manifest", attrs=[(None, "package", "com.example.benign")])
    builder.start(
        "uses-permission",
        attrs=[("http://schemas.android.com/apk/res/android", "name",
                "android.permission.INTERNET")],
    )
    builder.end("uses-permission")
    builder.end("manifest")

    report = analyze_manifest_bytes(builder.build())
    assert report["management_related_permissions"] == []
    assert report["management_indicators"] == []
    assert report["management_capability_level"] == "NONE"


def test_missing_file_raises(tmp_path):
    with pytest.raises(APKAnalysisError, match="not found"):
        analyze_apk(str(tmp_path / "missing.apk"))


def test_invalid_zip_raises(tmp_path):
    bad = tmp_path / "bad.apk"
    bad.write_bytes(b"this is not a zip archive")
    with pytest.raises(APKAnalysisError, match="not a valid APK"):
        analyze_apk(str(bad))


def test_zip_without_manifest_raises(tmp_path):
    apk_path = tmp_path / "nomanifest.apk"
    with zipfile.ZipFile(apk_path, "w") as archive:
        archive.writestr("classes.dex", b"x")
    with pytest.raises(APKAnalysisError, match="AndroidManifest.xml"):
        analyze_apk(str(apk_path))


def test_plain_text_manifest_rejected(tmp_path):
    apk_path = tmp_path / "textmanifest.apk"
    with zipfile.ZipFile(apk_path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"<manifest package='x'/>")
    with pytest.raises(APKAnalysisError, match="plain text"):
        analyze_apk(str(apk_path))
