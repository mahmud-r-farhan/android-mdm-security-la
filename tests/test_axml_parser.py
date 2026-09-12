"""Tests for core/axml_parser.py using byte-accurate synthetic fixtures."""

import pytest
from axml_parser import AXMLFormatError, parse_axml
from axml_builder import ANDROID_NS_URI, AXMLBuilder, build_sample_mdm_manifest


def test_parse_utf16_sample_manifest():
    root = parse_axml(build_sample_mdm_manifest(utf8=False))
    assert root.tag == "manifest"
    assert root.attributes["package"] == "com.example.mdmtest"
    assert root.attributes["versionName"] == "1.4.2"
    assert root.attributes["versionCode"] == 42


def test_parse_utf8_sample_manifest():
    root = parse_axml(build_sample_mdm_manifest(utf8=True))
    assert root.tag == "manifest"
    assert root.attributes["package"] == "com.example.mdmtest"


def test_uses_permission_extraction():
    root = parse_axml(build_sample_mdm_manifest())
    permissions = [
        node.attributes.get(f"{{{ANDROID_NS_URI}}}name")
        or node.attributes.get("name")
        for node in root.find_all("uses-permission")
    ]
    assert "android.permission.BIND_DEVICE_ADMIN" in permissions
    assert "android.permission.MANAGE_DEVICE_POLICY_LOCK_TASK" in permissions
    assert len(permissions) == 5


def test_nested_tree_and_namespaced_attributes():
    root = parse_axml(build_sample_mdm_manifest())
    sdk = root.find("uses-sdk")
    assert sdk is not None
    assert sdk.attributes[f"{{{ANDROID_NS_URI}}}minSdkVersion"] == 24
    assert sdk.attributes[f"{{{ANDROID_NS_URI}}}targetSdkVersion"] == 33

    receivers = root.find_all("receiver")
    assert len(receivers) == 2
    boot = receivers[1]
    actions = boot.find_all("action")
    assert actions[0].attributes.get("name") == "android.intent.action.BOOT_COMPLETED"


def test_invalid_magic_raises_format_error():
    with pytest.raises(AXMLFormatError):
        parse_axml(b"\x00\x00\x08\x00" + b"\x00" * 16)


def test_truncated_buffer_raises_format_error():
    with pytest.raises(AXMLFormatError):
        parse_axml(b"\x03")


def test_minimal_empty_element_document():
    builder = AXMLBuilder()
    builder.start("root")
    builder.end("root")
    root = parse_axml(builder.build())
    assert root.tag == "root"
    assert root.attributes == {}
    assert root.children == []


def test_to_dict_serialization():
    root = parse_axml(build_sample_mdm_manifest())
    as_dict = root.to_dict()
    assert as_dict["tag"] == "manifest"
    assert isinstance(as_dict["children"], list)
    assert as_dict["children"][0]["tag"] == "uses-sdk"
