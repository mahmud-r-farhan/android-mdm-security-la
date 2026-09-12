#!/usr/bin/env python3
"""
Android Enterprise Security Lab - Binary Android XML (AXML) Parser
------------------------------------------------------------------
Module: core/axml_parser.py
Description: Dependency-free parser for compiled Android binary XML files
             (``resources.arsc`` string-pool format), most commonly used to
             decode ``AndroidManifest.xml`` extracted from APK archives.

             Implements the documented ``ResChunk`` wire format:
               * RES_STRING_POOL_TYPE (0x0001)
               * RES_XML_TYPE            (0x0003)
               * RES_XML_RESOURCE_MAP    (0x0180)
               * RES_XML_START/END_NAMESPACE (0x0100 / 0x0101)
               * RES_XML_START/END_ELEMENT   (0x0102 / 0x0103)

             This module is strictly read-only and performs no I/O beyond
             operating on in-memory byte buffers supplied by the caller.

License: Apache License 2.0
"""

import struct
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Chunk type constants (frameworks/base/libs/androidfw/ResourceTypes.h)
# ---------------------------------------------------------------------------
RES_NULL_TYPE = 0x0000
RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104
RES_XML_RESOURCE_MAP_TYPE = 0x0180

# TypedValue.dataType codes we care about
TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12

UTF8_FLAG = 1 << 8


class AXMLFormatError(ValueError):
    """Raised when the supplied buffer is not a valid binary XML document."""


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _i32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<i", data, offset)[0]


def _decode_utf16_string(data: bytes, offset: int) -> Tuple[str, int]:
    """Decode one UTF-16 string-pool entry starting at ``offset``.

    Returns the decoded string and the offset just past its terminator.
    """
    char_count = _u16(data, offset)
    consumed = 2
    if char_count & 0x8000:  # large length: high word followed by low word
        low = _u16(data, offset + 2)
        char_count = ((char_count & 0x7FFF) << 16) | low
        consumed += 2
    start = offset + consumed
    end = start + char_count * 2
    raw = data[start:end]
    return raw.decode("utf-16-le", errors="replace"), end + 2


def _decode_utf8_string(data: bytes, offset: int) -> Tuple[str, int]:
    """Decode one UTF-8 string-pool entry starting at ``offset``.

    UTF-8 pool entries carry a character-count prefix and a byte-length
    prefix, each encoded in 1 or 2 bytes (high bit set => 2-byte form).
    """
    pos = offset
    char_len = data[pos]
    pos += 1
    if char_len & 0x80:
        char_len = ((char_len & 0x7F) << 8) | data[pos]
        pos += 1

    byte_len = data[pos]
    pos += 1
    if byte_len & 0x80:
        byte_len = ((byte_len & 0x7F) << 8) | data[pos]
        pos += 1

    raw = data[pos:pos + byte_len]
    return raw.decode("utf-8", errors="replace"), pos + byte_len + 1  # +1 NUL


class _StringPool:
    """Decoded RES_STRING_POOL chunk."""

    def __init__(self, data: bytes, chunk_offset: int) -> None:
        if len(data) < chunk_offset + 28:
            raise AXMLFormatError("String pool chunk is truncated")
        header_size = _u16(data, chunk_offset + 2)
        string_count = _u32(data, chunk_offset + 8)
        self.flags = _u32(data, chunk_offset + 16)
        strings_start = _u32(data, chunk_offset + 20)

        offsets_base = chunk_offset + header_size
        offsets = [
            _u32(data, offsets_base + i * 4) for i in range(string_count)
        ]
        data_base = chunk_offset + strings_start
        utf8 = bool(self.flags & UTF8_FLAG)

        self.strings: List[str] = []
        for off in offsets:
            pos = data_base + off
            if utf8:
                value, _ = _decode_utf8_string(data, pos)
            else:
                value, _ = _decode_utf16_string(data, pos)
            self.strings.append(value)

    def get(self, index: int) -> Optional[str]:
        """Return the string at ``index`` or None for sentinel (-1/0xFFFFFFFF)."""
        if index is None or index < 0 or index >= len(self.strings):
            return None
        return self.strings[index]


class AXMLNode:
    """A lightweight DOM node decoded from a binary XML document."""

    def __init__(self, tag: str, namespace: Optional[str] = None):
        self.tag: str = tag
        self.namespace: Optional[str] = namespace
        self.attributes: Dict[str, Any] = {}
        self.children: List["AXMLNode"] = []
        self.parent: Optional["AXMLNode"] = None

    def find_all(self, tag: str) -> List["AXMLNode"]:
        """Depth-first search for descendant nodes with the given tag."""
        found: List["AXMLNode"] = []
        for child in self.children:
            if child.tag == tag:
                found.append(child)
            found.extend(child.find_all(tag))
        return found

    def find(self, tag: str) -> Optional["AXMLNode"]:
        matches = self.find_all(tag)
        return matches[0] if matches else None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the node tree into plain dictionaries (JSON-friendly)."""
        return {
            "tag": self.tag,
            "namespace": self.namespace,
            "attributes": self.attributes,
            "children": [child.to_dict() for child in self.children],
        }


def _decode_typed_value(data: bytes, offset: int, pool: _StringPool) -> Any:
    """Decode a 8-byte Res_value record (size u16, res0 u8, type u8, data u32)."""
    data_type = data[offset + 3]
    value = _u32(data, offset + 4)
    if data_type == TYPE_STRING:
        return pool.get(value)
    if data_type == TYPE_INT_BOOLEAN:
        return value != 0
    if data_type in (TYPE_INT_DEC, TYPE_INT_HEX):
        return value
    return value


def parse_axml(data: bytes) -> AXMLNode:
    """Parse a compiled Android binary XML document.

    Args:
        data: Raw bytes of the binary XML file (e.g. ``AndroidManifest.xml``).

    Returns:
        The root ``AXMLNode`` of the decoded document tree.

    Raises:
        AXMLFormatError: If the buffer is not a valid binary XML document.
    """
    if len(data) < 8:
        raise AXMLFormatError("Buffer too small to be a binary XML document")

    file_type = _u16(data, 0)
    if file_type != RES_XML_TYPE:
        raise AXMLFormatError(
            f"Not a binary XML document (magic 0x{file_type:04X}, expected 0x0003)"
        )

    pool: Optional[_StringPool] = None
    root: Optional[AXMLNode] = None
    current: Optional[AXMLNode] = None
    namespaces: Dict[str, str] = {}  # prefix -> uri

    offset = 8
    total = len(data)
    while offset + 8 <= total:
        chunk_type = _u16(data, offset)
        header_size = _u16(data, offset + 2)
        chunk_size = _u32(data, offset + 4)
        if chunk_size < 8 or offset + chunk_size > total:
            raise AXMLFormatError("Corrupt chunk header in binary XML stream")

        if chunk_type == RES_STRING_POOL_TYPE:
            pool = _StringPool(data, offset)
        elif chunk_type == RES_XML_RESOURCE_MAP_TYPE:
            pass  # Resource IDs are not required for manifest auditing.
        elif chunk_type == RES_XML_START_NAMESPACE_TYPE:
            if pool is not None:
                prefix = pool.get(_i32(data, offset + header_size))
                uri = pool.get(_i32(data, offset + header_size + 4))
                if prefix and uri:
                    namespaces[prefix] = uri
        elif chunk_type == RES_XML_START_ELEMENT_TYPE:
            if pool is None:
                raise AXMLFormatError("Start element before string pool")
            # The 16-byte node header (chunk header + lineNumber + comment)
            # is followed by the 20-byte ResXMLTree_attrExt record.
            ext = offset + 16
            ns_index = _i32(data, ext)
            name_index = _i32(data, ext + 4)
            attribute_start = _u16(data, ext + 8) or 20
            attribute_size = _u16(data, ext + 10) or 20
            attribute_count = _u16(data, ext + 12)

            tag = pool.get(name_index) or f"<unknown:{name_index}>"
            node = AXMLNode(tag, pool.get(ns_index))

            # Attribute records begin attributeStart bytes into the attrExt
            # record (20 in every manifest produced by AAPT/AAPT2).
            attr_base = ext + attribute_start
            for i in range(attribute_count):
                aoff = attr_base + i * attribute_size
                a_ns_index = _i32(data, aoff)
                a_name_index = _i32(data, aoff + 4)
                raw_value_index = _i32(data, aoff + 8)
                name = pool.get(a_name_index) or f"attr{i}"
                value = _decode_typed_value(data, aoff + 12, pool)
                if value is None:
                    value = pool.get(raw_value_index)
                node.attributes[name] = value
                ns_uri = pool.get(a_ns_index)
                if ns_uri:
                    node.attributes[f"{{{ns_uri}}}{name}"] = value

            if current is None:
                root = node
            else:
                node.parent = current
                current.children.append(node)
            current = node
        elif chunk_type == RES_XML_END_ELEMENT_TYPE:
            if current is not None and current.parent is not None:
                current = current.parent
        # All other chunk types (END_NAMESPACE, CDATA) are safely skipped.

        offset += chunk_size

    if root is None:
        raise AXMLFormatError("No root element found in binary XML document")
    return root


def resolve_namespace_uri(prefix_map: Dict[str, str], prefix: str) -> str:
    """Return the canonical URI for a well-known Android namespace prefix."""
    defaults = {
        "android": "http://schemas.android.com/apk/res/android",
        "tools": "http://schemas.android.com/tools",
    }
    return prefix_map.get(prefix, defaults[prefix])
