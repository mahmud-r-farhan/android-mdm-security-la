"""Minimal encoder for compiled Android binary XML (AXML) documents.

Used by the test-suite to produce byte-accurate ``AndroidManifest.xml``
fixtures for the pure-Python parser in ``core/axml_parser.py``. Implements
the same ResChunk wire format the Android build tools (AAPT2) emit.
"""

import struct
from typing import Any, Dict, List, Optional, Tuple

ANDROID_NS_URI = "http://schemas.android.com/apk/res/android"

TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12
TYPE_REFERENCE = 0x01


class AXMLBuilder:
    """Builds a binary XML document from high-level element events."""

    def __init__(self, utf8: bool = False) -> None:
        self.utf8 = utf8
        self.strings: List[str] = []
        self._index: Dict[str, int] = {}
        self._chunks: List[bytes] = []
        self._line = 1

    # -- string pool helpers -------------------------------------------------
    def s(self, value: str) -> int:
        """Intern a string and return its pool index."""
        if value not in self._index:
            self._index[value] = len(self.strings)
            self.strings.append(value)
        return self._index[value]

    # -- element events ------------------------------------------------------
    def start(
        self,
        tag: str,
        attrs: Optional[List[Tuple[Optional[str], str, Any]]] = None,
        namespace: Optional[str] = None,
    ) -> None:
        """Emit a start-element event.

        attrs entries are ``(namespace_uri_or_None, name, value)`` where value
        may be str, int, bool, or an explicit ``(typed_type, data)`` tuple.
        """
        attrs = attrs or []
        ns_idx = self.s(namespace) if namespace else -1
        name_idx = self.s(tag)

        attr_bytes = bytearray()
        for attr_ns, attr_name, value in attrs:
            attr_ns_idx = self.s(attr_ns) if attr_ns else -1
            attr_name_idx = self.s(attr_name)

            if isinstance(value, tuple):
                typed_type, typed_data = value
                raw_idx = -1
            elif isinstance(value, bool):
                typed_type, typed_data = TYPE_INT_BOOLEAN, 1 if value else 0
                raw_idx = -1
            elif isinstance(value, int):
                typed_type, typed_data = TYPE_INT_DEC, value
                raw_idx = -1
            else:
                raw_idx = self.s(str(value))
                typed_type, typed_data = TYPE_STRING, raw_idx

            attr_bytes += struct.pack(
                "<iiiHBBI",
                attr_ns_idx,
                attr_name_idx,
                raw_idx,
                8,          # Res_value.size
                0,          # Res_value.res0
                typed_type,
                typed_data,
            )

        chunk_size = 36 + len(attr_bytes)
        header = struct.pack(
            "<HHIIIiiHHHHHH",
            0x0102,          # RES_XML_START_ELEMENT_TYPE
            36,              # headerSize (16 node hdr + 20 attrExt)
            chunk_size,
            self._line,
            0xFFFFFFFF,      # comment: none (sentinel)
            ns_idx,
            name_idx,
            20,              # attributeStart
            20,              # attributeSize
            len(attrs),
            0, 0, 0,         # idIndex / classIndex / styleIndex
        )
        self._chunks.append(header + bytes(attr_bytes))
        self._line += 1

    def end(self, tag: str, namespace: Optional[str] = None) -> None:
        """Emit an end-element event."""
        ns_idx = self.s(namespace) if namespace else -1
        chunk = struct.pack(
            "<HHIIIii",
            0x0103,          # RES_XML_END_ELEMENT_TYPE
            16,
            24,
            self._line,
            0xFFFFFFFF,      # comment: none (sentinel)
            ns_idx,
            self.s(tag),
        )
        self._chunks.append(chunk)
        self._line += 1

    # -- serialization -------------------------------------------------------
    def _encode_string_pool(self) -> bytes:
        flags = (1 << 8) if self.utf8 else 0
        entries = bytearray()
        offsets: List[int] = []

        for value in self.strings:
            offsets.append(len(entries))
            if self.utf8:
                encoded = value.encode("utf-8")
                char_len = len(value)
                byte_len = len(encoded)
                if char_len > 0x7F or byte_len > 0x7F:
                    raise ValueError("Test fixture strings must be < 128 units")
                entries += bytes([char_len, byte_len]) + encoded + b"\x00"
            else:
                utf16 = value.encode("utf-16-le")
                entries += struct.pack("<H", len(value)) + utf16 + b"\x00\x00"

        header_size = 28
        offsets_block = b"".join(struct.pack("<I", off) for off in offsets)
        strings_start = header_size + len(offsets_block)
        chunk_size = strings_start + len(entries)

        header = struct.pack(
            "<HHIIIIII",
            0x0001,          # RES_STRING_POOL_TYPE
            header_size,
            chunk_size,
            len(self.strings),
            0,               # styleCount
            flags,
            strings_start,
            chunk_size,      # stylesStart (no styles present)
        )
        return header + offsets_block + bytes(entries)

    def build(self) -> bytes:
        """Serialize the full binary XML document."""
        pool = self._encode_string_pool()
        body = b"".join(self._chunks)
        doc_size = 8 + len(pool) + len(body)
        doc_header = struct.pack("<HHI", 0x0003, 8, doc_size)
        return doc_header + pool + body


def build_sample_mdm_manifest(utf8: bool = False) -> bytes:
    """Build a realistic MDM-style AndroidManifest.xml binary for tests."""
    android = ANDROID_NS_URI
    builder = AXMLBuilder(utf8=utf8)

    builder.start(
        "manifest",
        attrs=[
            (None, "package", "com.example.mdmtest"),
            (None, "versionCode", 42),
            (None, "versionName", "1.4.2"),
        ],
    )
    builder.start(
        "uses-sdk",
        attrs=[
            (android, "minSdkVersion", 24),
            (android, "targetSdkVersion", 33),
        ],
    )
    builder.end("uses-sdk")

    for permission in (
        "android.permission.BIND_DEVICE_ADMIN",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.RECEIVE_BOOT_COMPLETED",
        "android.permission.MANAGE_DEVICE_POLICY_LOCK_TASK",
        "android.permission.INTERNET",
    ):
        builder.start(
            "uses-permission",
            attrs=[(android, "name", permission)],
        )
        builder.end("uses-permission")

    builder.start("application", attrs=[(android, "label", "MDM Test Agent")])

    # DeviceAdmin receiver with the standard device_admin meta-data tag.
    builder.start(
        "receiver",
        attrs=[
            (android, "name", "com.example.mdmtest.AdminReceiver"),
            (android, "permission", "android.permission.BIND_DEVICE_ADMIN"),
        ],
    )
    builder.start(
        "meta-data",
        attrs=[
            (android, "name", "android.app.device_admin"),
            (android, "resource", (TYPE_REFERENCE, 0x7F0A0001)),
        ],
    )
    builder.end("meta-data")
    builder.end("receiver")

    # Boot-persistence receiver with an intent-filter.
    builder.start(
        "receiver",
        attrs=[(android, "name", "com.example.mdmtest.BootReceiver")],
    )
    builder.start("intent-filter")
    builder.start(
        "action",
        attrs=[(android, "name", "android.intent.action.BOOT_COMPLETED")],
    )
    builder.end("action")
    builder.end("intent-filter")
    builder.end("receiver")

    builder.end("application")
    builder.end("manifest")
    return builder.build()
