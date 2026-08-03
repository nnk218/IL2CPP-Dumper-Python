#!/usr/bin/env python3
"""IL2CPP global-metadata.dat dumper - research / testing tool.

Parses Unity's global-metadata.dat and dumps string literals, metadata
strings, type definitions (classes), methods, fields, properties, events,
parameters, generic parameters/containers, nested types, interfaces, images
and assemblies, plus metadata usage lists/pairs (v27+).

XOR-protected metadata:
    Many IL2CPP "protectors" encrypt global-metadata.dat with a repeating XOR
    key that can be recovered from the game binary. Pass --xor-key <hex> to
    decrypt; the file (or from --xor-offset onward) is XORed cyclically with
    the key, matching the scheme used by the common Il2CppDumper XOR forks.

Usage:
    python3 il2cpp_meta_dumper.py -i global-metadata.dat
    python3 il2cpp_meta_dumper.py -i global-metadata.dat --xor-key 4b6d4f... -o dump.txt
"""

import argparse
import json
import struct
import sys
from typing import Dict, List, Optional

MAGIC = 0xFAB11BAF


class MetaError(Exception):
    pass


# --------------------------------------------------------------------------
# Header layout
# --------------------------------------------------------------------------

# v38+ replaced the per-table offset/size header fields with Il2CppSectionMetadata
# triplets (offset, size, count) in this exact order (roytu PR #903
# MetadataClass.cs Il2CppGlobalMetadataHeader).
V38_SECTIONS = [
    "stringLiterals", "stringLiteralData", "strings", "events", "properties",
    "methods", "parameterDefaultValues", "fieldDefaultValues",
    "fieldAndParameterDefaultValueData", "fieldMarshaledSizes",
    "parameters", "fields", "genericParameters", "genericParameterConstraints",
    "genericContainers", "nestedTypes", "interfaces", "vtableMethods",
    "interfaceOffsets", "typeDefinitions", "images", "assemblies", "fieldRefs",
    "referencedAssemblies", "attributeData", "attributeDataRanges",
    "unresolvedIndirectCallParameterTypes",
    "unresolvedIndirectCallParameterRanges",
    "windowsRuntimeTypeNames", "windowsRuntimeStrings",
    "exportedTypeDefinitions",
]


def get_index_size(count: int) -> int:
    """Width in bytes of a variable-width index type (1/2/4). Matches
    Metadata.GetIndexSize in PR #903 / vm/MetadataDeserialization.h."""
    if count <= 0xFF:
        return 1
    if count <= 0xFFFF:
        return 2
    return 4


def header_fields(version: int) -> List[str]:
    """Ordered metadata-header field names for a given version.

    Follows the real (Il2CppDumper) layout: tables are stored as byte
    offsets + byte SIZES, and several blocks are version-gated. Notable
    consequences for modern (>=25) metadata:
      - metadataUsageLists/Pairs exist only for v19-24.5 (from v25 on the
        usage tables live in the binary's Il2CppMetadataRegistration).
      - attributesInfo/attributeTypes (v21-27.2) are replaced by
        attributeData/attributeDataRange (v29+).
    """
    fields = ["sanity", "version"]
    for t in ["stringLiteral", "stringLiteralData", "string", "events", "properties",
              "methods", "parameterDefaultValues", "fieldDefaultValues",
              "fieldAndParameterDefaultValueData", "fieldMarshaledSizes",
              "parameters", "fields", "genericParameters", "genericParameterConstraints",
              "genericContainers", "nestedTypes", "interfaces", "vtableMethods",
              "interfaceOffsets", "typeDefinitions"]:
        fields += [t + "Offset", t + "Size"]
    if version <= 24.1:
        fields += ["rgctxEntriesOffset", "rgctxEntriesCount"]
    fields += ["imagesOffset", "imagesSize", "assembliesOffset", "assembliesSize"]
    if 19 <= version <= 24.5:
        fields += ["metadataUsageListsOffset", "metadataUsageListsCount",
                   "metadataUsagePairsOffset", "metadataUsagePairsCount"]
    if version >= 19:
        fields += ["fieldRefsOffset", "fieldRefsSize"]
    if version >= 20:
        fields += ["referencedAssembliesOffset", "referencedAssembliesSize"]
    if 21 <= version <= 27.2:
        fields += ["attributesInfoOffset", "attributesInfoCount",
                   "attributeTypesOffset", "attributeTypesCount"]
    if version >= 29:
        fields += ["attributeDataOffset", "attributeDataSize",
                   "attributeDataRangeOffset", "attributeDataRangeSize"]
    if version >= 22:
        fields += ["unresolvedVirtualCallParameterTypesOffset", "unresolvedVirtualCallParameterTypesSize",
                   "unresolvedVirtualCallParameterRangesOffset", "unresolvedVirtualCallParameterRangesSize"]
    if version >= 23:
        fields += ["windowsRuntimeTypeNamesOffset", "windowsRuntimeTypeNamesSize"]
    if version >= 27:
        fields += ["windowsRuntimeStringsOffset", "windowsRuntimeStringsSize"]
    if version >= 24:
        fields += ["exportedTypeDefinitionsOffset", "exportedTypeDefinitionsSize"]
    return fields


# --------------------------------------------------------------------------
# Version-gated struct layouts (real il2cpp-metadata / GlobalMetadataFileInternals.h)
# --------------------------------------------------------------------------

def type_def_layout(version: int) -> List[str]:
    """Il2CppTypeDefinition field names in order (see MetadataClass.cs gating).

    Modern (v25+) layout is 88 bytes: name, namespace, byvalType, declaringType,
    parentType, elementType, genericContainer, flags, 8 start indices, 8 ushort
    counts, bitfield, token. byrefTypeIndex/rgctx/customAttributeIndex only
    exist in older versions.
    """
    names = ["nameIndex", "namespaceIndex"]
    if version <= 24:
        names.append("customAttributeIndex")
    names.append("byvalTypeIndex")
    if version <= 24.5:
        names.append("byrefTypeIndex")
    names += ["declaringTypeIndex", "parentIndex", "elementTypeIndex"]
    if version <= 24.1:
        names += ["rgctxStartIndex", "rgctxCount"]
    names.append("genericContainerIndex")
    if version <= 22:
        names += ["delegateWrapperFromManagedToNativeIndex", "marshalingFunctionsIndex"]
    if 21 <= version <= 22:
        names += ["ccwFunctionIndex", "guidIndex"]
    names.append("flags")
    names += ["fieldStart", "methodStart", "eventStart", "propertyStart",
              "nestedTypesStart", "interfacesStart", "vtableStart", "interfaceOffsetsStart"]
    names += ["method_count", "property_count", "field_count", "event_count",
              "nested_type_count", "vtable_count", "interfaces_count", "interface_offsets_count"]
    names += ["bitfield", "token"]
    return names


def type_def_size(version: int) -> int:
    names = type_def_layout(version)
    return (len(names) - 10) * 4 + 8 * 2 + 8


def method_def_layout(version: int) -> List[str]:
    names = ["nameIndex", "declaringType", "returnType"]
    if version >= 31:
        names.append("returnParameterToken")
    names.append("parameterStart")
    if version <= 24:
        names.append("customAttributeIndex")
    names.append("genericContainerIndex")
    if version <= 24.1:
        names += ["methodIndex", "invokerIndex", "delegateWrapperIndex",
                  "rgctxStartIndex", "rgctxCount"]
    names += ["token", "flags", "iflags", "slot", "parameterCount"]
    return names


def method_def_size(version: int) -> int:
    names = method_def_layout(version)
    return (len(names) - 5) * 4 + 4 + 4 * 2


def image_layout(version: int) -> List[str]:
    names = ["nameIndex", "assemblyIndex", "typeStart", "typeCount"]
    if version >= 24:
        names += ["exportedTypeStart", "exportedTypeCount"]
    names.append("entryPointIndex")
    if version >= 19:
        names.append("token")
    if version >= 24.1:
        names += ["customAttributeStart", "customAttributeCount"]
    return names


def image_size(version: int) -> int:
    return len(image_layout(version)) * 4


def parse_header(data: bytes, version: Optional[int]) -> Dict[str, int]:
    if len(data) < 8:
        raise MetaError("file too small to be global-metadata.dat")
    sanity, ver = struct.unpack_from("<II", data, 0)
    if sanity != MAGIC:
        raise MetaError("bad magic 0x%08X - file may be protected/encrypted (try --xor-key)" % sanity)
    if version is not None:
        ver = version
    if ver >= 38:
        # v38+ header: Il2CppSectionMetadata triplets (offset/size/count) in order
        if len(data) < 8 + len(V38_SECTIONS) * 12:
            raise MetaError("file too small for v%d header (%d bytes)" % (
                ver, 8 + len(V38_SECTIONS) * 12))
        out: Dict[str, int] = {"sanity": sanity, "version": ver,
                               "_sections": {}, "_version": ver}
        for i, name in enumerate(V38_SECTIONS):
            out["_sections"][name] = struct.unpack_from("<III", data, 8 + i * 12)
        return out
    fields = header_fields(ver)
    if len(data) < len(fields) * 4:
        raise MetaError("file too small for v%d header (%d bytes)" % (ver, len(fields) * 4))
    out = {}
    for i, name in enumerate(fields):
        out[name] = struct.unpack_from("<I", data, i * 4)[0]
    out["_version"] = ver
    return out


# --------------------------------------------------------------------------
# XOR decryption
# --------------------------------------------------------------------------

def xor_decrypt(data: bytes, key: bytes, offset: int = 0) -> bytes:
    if not key:
        return data
    out = bytearray(data)
    n = len(key)
    for i in range(offset, len(out)):
        out[i] ^= key[(i - offset) % n]
    return bytes(out)


def auto_xor_key(data: bytes, max_len: int = 64) -> Optional[bytes]:
    """Recover a repeating-XOR protection key from an encrypted metadata file.

    The 4-byte magic (0xFAB11BAF) recovers key[0:4] exactly. For keys of length
    4 this fully determines the key. For longer keys we can only derive the
    first 4 bytes; we additionally try the common case where the key length is
    a multiple of 4 and the version u32 (offset 4) is stored XOR'd with key[4:8]
    such that the decrypted version is a sane il2cpp version -- this recovers
    key[4:8]. Keys longer than 8 bytes with unknown tails are reported as
    best-effort only when the first 8 bytes already yield a valid header.

    Returns the key, or None if the file doesn't look XOR-protected.
    """
    if len(data) < 16:
        return None
    magic_le = struct.pack("<I", MAGIC)
    key4 = bytes(data[i] ^ magic_le[i] for i in range(4))
    if key4 == b"\x00" * 4:
        return None  # plaintext already

    # Period-4 key: fully recovered.
    key4r = key4 * 4
    if _plausible_header(xor_decrypt(data[:64], key4r)):
        return key4r[:4]

    # Try version-derived keys: guess key[4:8] from a sane version at offset 4.
    for klen in (8, 12, 16, 24, 32, 48, 64):
        if klen > max_len:
            continue
        key = bytearray(klen)
        key[:4] = key4
        for ver_guess in range(1, 99):
            key[4] = data[4] ^ (ver_guess & 0xFF)
            if klen > 5:
                key[5] = data[5] ^ ((ver_guess >> 8) & 0xFF)
            if klen > 6:
                key[6] = data[6] ^ ((ver_guess >> 16) & 0xFF)
            if klen > 7:
                key[7] = data[7] ^ ((ver_guess >> 24) & 0xFF)
            dec = xor_decrypt(data[:64], bytes(key))
            if _plausible_header(dec):
                return bytes(key)
    return None


def _plausible_header(dec: bytes) -> bool:
    if len(dec) < 12:
        return False
    if struct.unpack_from("<I", dec, 0)[0] != MAGIC:
        return False
    ver = struct.unpack_from("<I", dec, 4)[0]
    if not (1 <= ver <= 99):
        return False
    # first field/section must be a sane offset/size (nonzero, < 1<<28)
    first = struct.unpack_from("<I", dec, 8)[0]
    return 0 <= first < (1 << 28)


# --------------------------------------------------------------------------
# Metadata model
# --------------------------------------------------------------------------

class Metadata:
    def __init__(self, data: bytes, version: Optional[int] = None,
                 type_region_offset: Optional[int] = None):
        self.data = data
        self.header = parse_header(data, version)
        self.version = self.header["_version"]

        self.strings: List[str] = []
        self.string_literals: List[str] = []
        self.type_defs: List[Dict] = []
        self.methods: List[Dict] = []
        self.fields: List[Dict] = []
        self.params: List[Dict] = []
        self.properties: List[Dict] = []
        self.events: List[Dict] = []
        self.generic_params: List[Dict] = []
        self.generic_containers: List[Dict] = []
        self.nested_types: List[Dict] = []
        self.interfaces: List[int] = []
        self.interface_offsets: List[Dict] = []
        self.images: List[Dict] = []
        self.assemblies: List[Dict] = []
        self.fields_refs: List[Dict] = []
        self.field_defaults: List[Dict] = []
        self.param_defaults: List[Dict] = []
        self.usage_lists: List[List[int]] = []
        self.usage_pairs: List[Dict] = []

        self.byval_to_name: Dict[int, str] = {}
        self.byref_to_name: Dict[int, str] = {}
        self._methods_by_td: Dict[int, List[Dict]] = {}

        self.il2cpp_type_size = 16 if self.version >= 31 else 12
        self.type_region_offset: Optional[int] = None
        self._td_size = type_def_size(self.version)
        self._im_size = image_size(self.version)

        # Variable-width index sizes (v38+); all 4 bytes before that.
        self._idx_sizes = {"T": 4, "D": 4, "G": 4, "P": 4}
        if self.version >= 38:
            sec = self.header["_sections"]
            pcount = sec["parameters"][2]
            if pcount:
                # Il2CppParameterDefinition = nameIndex + token + TypeIndex
                type_index_size = sec["parameters"][1] // pcount - 8
                if 1 <= type_index_size <= 4:
                    self._idx_sizes["T"] = type_index_size
            self._idx_sizes["D"] = get_index_size(sec["typeDefinitions"][2])
            self._idx_sizes["G"] = get_index_size(sec["genericContainers"][2])
            self._idx_sizes["P"] = get_index_size(sec["parameters"][2])

        self._parse()
        self._locate_type_region(type_region_offset)

    # -- low-level helpers ------------------------------------------------
    def _rd(self, fmt: str, off: int):
        if off < 0 or off + struct.calcsize("<" + fmt) > len(self.data):
            return None
        return struct.unpack_from("<" + fmt, self.data, off)

    def _ints(self, off: int, count: int) -> List[int]:
        if off <= 0 or count <= 0 or off + 4 * count > len(self.data):
            return []
        return list(struct.unpack_from("<%di" % count, self.data, off))

    # -- version-aware table helpers --------------------------------------

    def _sec_name(self, table: str) -> str:
        if self.version >= 38:
            return {
                "stringLiteral": "stringLiterals",
                "string": "strings",
            }.get(table, table)
        return table

    def _sec_off(self, table: str) -> int:
        if self.version >= 38:
            return self.header["_sections"].get(self._sec_name(table), (0, 0, 0))[0]
        return self.header.get(table + "Offset", 0)

    def _sec_size(self, table: str) -> int:
        if self.version >= 38:
            return self.header["_sections"].get(self._sec_name(table), (0, 0, 0))[1]
        return self.header.get(table + "Size", self.header.get(table + "Count", 0))

    def _sec_count(self, table: str) -> int:
        if self.version >= 38:
            return self.header["_sections"].get(self._sec_name(table), (0, 0, 0))[2]
        return 0

    # index-size-aware field reader (kinds: T/D/G/P variable, I/i/H/h fixed)
    def _fmt_size(self, fmt: str) -> int:
        if fmt in self._idx_sizes:
            return self._idx_sizes[fmt]
        return {"I": 4, "i": 4, "H": 2, "h": 2, "B": 1}[fmt]

    def _fmt_read(self, fmt: str, off: int) -> int:
        if fmt in self._idx_sizes:
            size = self._idx_sizes[fmt]
            if size == 1:
                val = self.data[off]
                return -1 if val == 0xFF else val
            if size == 2:
                val = struct.unpack_from("<H", self.data, off)[0]
                return -1 if val == 0xFFFF else val
            val = struct.unpack_from("<I", self.data, off)[0]
            return -1 if val == 0xFFFFFFFF else val
        if fmt == "I":
            return struct.unpack_from("<I", self.data, off)[0]
        if fmt == "i":
            return struct.unpack_from("<i", self.data, off)[0]
        if fmt == "H":
            return struct.unpack_from("<H", self.data, off)[0]
        if fmt == "h":
            return struct.unpack_from("<h", self.data, off)[0]
        return self.data[off]

    def _read_fields(self, off: int, spec) -> Optional[Dict[str, int]]:
        size = sum(self._fmt_size(f) for _, f in spec)
        if off < 0 or off + size > len(self.data):
            return None
        out = {}
        cur = off
        for name, fmt in spec:
            out[name] = self._fmt_read(fmt, cur)
            cur += self._fmt_size(fmt)
        return out

    def _tab_off(self, table: str) -> int:
        return self._sec_off(table)

    def _elem_size(self, table: str) -> int:
        v = self.version
        fixed = {
            "stringLiteral": 4 if v >= 35 else 8, "stringLiteralData": 1, "string": 4,
            "parameterDefaultValues": 12, "fieldDefaultValues": 12,
            "fieldAndParameterDefaultValueData": 1, "fieldMarshaledSizes": 8,
            "parameters": 12, "fields": 12, "genericParameters": 16,
            "genericParameterConstraints": 4, "genericContainers": 16,
            "nestedTypes": 4, "interfaces": 4, "vtableMethods": 4,
            "interfaceOffsets": 8, "rgctxEntries": 8,
            "metadataUsageLists": 8, "metadataUsagePairs": 8, "fieldRefs": 8,
            "referencedAssemblies": 4, "attributeTypes": 4, "attributeData": 1,
            "attributeDataRange": 8, "unresolvedVirtualCallParameterTypes": 4,
            "unresolvedVirtualCallParameterRanges": 8,
            "windowsRuntimeTypeNames": 8, "windowsRuntimeStrings": 4,
            "exportedTypeDefinitions": 4,
        }
        if table in fixed:
            return fixed[table]
        if table == "events":
            return 24 if v >= 24.1 else 28
        if table == "properties":
            return 20 if v >= 24.1 else 24
        if table == "methods":
            return method_def_size(v)
        if table == "typeDefinitions":
            return type_def_size(v)
        if table == "images":
            return image_size(v)
        if table == "assemblies":
            return 16 if v >= 24.1 else 12
        if table == "attributesInfo":
            return 12 if v >= 24.1 else 8
        return 0

    def _count(self, table: str) -> int:
        if self.version >= 38:
            return self._sec_count(table)
        off = self._tab_off(table)
        size = self.header.get(table + "Size", self.header.get(table + "Count", 0))
        if off <= 0 or size <= 0:
            return 0
        elem = self._elem_size(table)
        return size // elem if elem else 0

    def read_string(self, index: int) -> str:
        if index < 0:
            return ""
        base = self._sec_off("string")
        size = self._sec_size("string")
        if base <= 0 or size <= 0 or index >= size:
            return "<str:%d>" % index
        pos = base + index
        end = self.data.find(b"\x00", pos, min(pos + 512, base + size))
        if end == -1:
            end = min(pos + 512, base + size)
        try:
            return self.data[pos:end].decode("utf-8", "replace")
        except Exception:
            return ""

    # -- parsers ----------------------------------------------------------
    def _parse(self):
        h = self.header
        v = self.version

        # strings: for <=35 this is an int32-offset table (fixture-compatible);
        # for v38+ the "strings" section is a blob of NUL-terminated strings
        # indexed by direct byte offset (matching Il2CppDumper). We expose a
        # best-effort list by splitting the blob.
        if v >= 38:
            base = self._sec_off("string")
            size = self._sec_size("string")
            if base > 0 and size > 0:
                self.strings = [s for s in self.data[base:base + size].split(b"\x00")]
            self.strings = [s.decode("utf-8", "replace") for s in self.strings]
        else:
            self.strings = [self.read_string(i) for i in range(self._count("string"))]

        # string literals
        slo = self._tab_off("stringLiteral")
        slc = self._count("stringLiteral")
        slbase = self._sec_off("stringLiteralData")
        slsize = self._sec_size("stringLiteralData")
        if v >= 35:
            # v35+ removed Il2CppStringLiteral.length: {dataIndex}, length is
            # derived from the next literal's dataIndex.
            for i in range(slc):
                di = self._fmt_read("i", slo + i * 4) if slo > 0 else -1
                if di < 0:
                    break
                nxt = slsize
                if i + 1 < slc:
                    nxt = self._fmt_read("i", slo + (i + 1) * 4)
                if nxt < di or slbase + nxt > len(self.data):
                    nxt = slsize
                lit = self.data[slbase + di: slbase + nxt]
                self.string_literals.append(lit.decode("utf-8", "replace"))
        else:
            for i in range(slc):
                rec = self._rd("Ii", slo + i * 8)
                if rec is None:
                    break
                length, data_index = rec
                lit = self.data[slbase + data_index: slbase + data_index + length]
                self.string_literals.append(lit.decode("utf-8", "replace"))

        # type definitions (version-gated Il2CppTypeDefinition)
        tdo = self._tab_off("typeDefinitions")
        tdc = self._count("typeDefinitions")
        if v >= 38:
            td_spec = [
                ("nameIndex", "i"), ("namespaceIndex", "i"),
                ("byvalTypeIndex", "T"), ("declaringTypeIndex", "T"),
                ("parentIndex", "T"), ("genericContainerIndex", "G"),
                ("flags", "i"),
                ("fieldStart", "i"), ("methodStart", "i"), ("eventStart", "i"),
                ("propertyStart", "i"), ("nestedTypesStart", "i"),
                ("interfacesStart", "i"), ("vtableStart", "i"),
                ("interfaceOffsetsStart", "i"),
                ("method_count", "H"), ("property_count", "H"),
                ("field_count", "H"), ("event_count", "H"),
                ("nested_type_count", "H"), ("vtable_count", "H"),
                ("interfaces_count", "H"), ("interface_offsets_count", "H"),
                ("bitfield", "i"), ("token", "i"),
            ]
            td_stride = sum(self._fmt_size(f) for _, f in td_spec)
            for i in range(tdc):
                rec = self._read_fields(tdo + i * td_stride, td_spec)
                if rec is None:
                    break
                rec["_index"] = i
                self.type_defs.append(rec)
        else:
            td_names = type_def_layout(v)
            td_fmt = "%di8HII" % (len(td_names) - 10)
            td_size = type_def_size(v)
            for i in range(tdc):
                rec = self._rd(td_fmt, tdo + i * td_size)
                if rec is None:
                    break
                d = dict(zip(td_names, rec))
                d["_index"] = i
                self.type_defs.append(d)

        # methods (version-gated Il2CppMethodDefinition)
        mo = self._tab_off("methods")
        mc = self._count("methods")
        if v >= 38:
            m_spec = [
                ("nameIndex", "i"), ("declaringType", "D"), ("returnType", "T"),
                ("returnParameterToken", "i"), ("parameterStart", "P"),
                ("genericContainerIndex", "G"), ("token", "i"),
                ("flags", "H"), ("iflags", "H"), ("slot", "H"),
                ("parameterCount", "H"),
            ]
            m_stride = sum(self._fmt_size(f) for _, f in m_spec)
            for i in range(mc):
                rec = self._read_fields(mo + i * m_stride, m_spec)
                if rec is None:
                    break
                rec["_index"] = i
                self.methods.append(rec)
        else:
            m_names = method_def_layout(v)
            m_fmt = "%diI4H" % (len(m_names) - 5)
            m_size = method_def_size(v)
            for i in range(mc):
                rec = self._rd(m_fmt, mo + i * m_size)
                if rec is None:
                    break
                d = dict(zip(m_names, rec))
                d["_index"] = i
                self.methods.append(d)

        # fields
        fo = self._tab_off("fields")
        fc = self._count("fields")
        if v >= 38:
            f_spec = [("nameIndex", "i"), ("typeIndex", "T"), ("token", "i")]
            f_stride = sum(self._fmt_size(f) for _, f in f_spec)
            for i in range(fc):
                rec = self._read_fields(fo + i * f_stride, f_spec)
                if rec is None:
                    break
                self.fields.append(rec)
        else:
            for i in range(fc):
                rec = self._rd("2iI", fo + i * 12)
                if rec is None:
                    break
                self.fields.append(dict(zip(["nameIndex", "typeIndex", "token"], rec)))

        # parameters
        po = self._tab_off("parameters")
        pc = self._count("parameters")
        if v >= 38:
            p_spec = [("nameIndex", "i"), ("token", "i"), ("typeIndex", "T")]
            p_stride = sum(self._fmt_size(f) for _, f in p_spec)
            for i in range(pc):
                rec = self._read_fields(po + i * p_stride, p_spec)
                if rec is None:
                    break
                self.params.append(rec)
        else:
            for i in range(pc):
                rec = self._rd("iIi", po + i * 12)
                if rec is None:
                    break
                self.params.append(dict(zip(["nameIndex", "token", "typeIndex"], rec)))

        # properties
        pro = self._tab_off("properties")
        prc = self._count("properties")
        if v >= 24.1:
            p_names = ["nameIndex", "get", "set", "attrs", "token"]
            p_fmt, p_size = "3iII", 20
        else:
            p_names = ["nameIndex", "get", "set", "attrs", "customAttributeIndex", "token"]
            p_fmt, p_size = "3iIiI", 24
        for i in range(prc):
            rec = self._rd(p_fmt, pro + i * p_size)
            if rec is None:
                break
            self.properties.append(dict(zip(p_names, rec)))

        # events
        eo = self._tab_off("events")
        ec = self._count("events")
        if v >= 24.1:
            e_names = ["nameIndex", "typeIndex", "add", "remove", "raise", "token"]
            e_fmt, e_size = "5iI", 24
        else:
            e_names = ["nameIndex", "typeIndex", "add", "remove", "raise",
                       "customAttributeIndex", "token"]
            e_fmt, e_size = "6iI", 28
        for i in range(ec):
            rec = self._rd(e_fmt, eo + i * e_size)
            if rec is None:
                break
            self.events.append(dict(zip(e_names, rec)))

        # generic parameters
        gpo = self._tab_off("genericParameters")
        gpc = self._count("genericParameters")
        if v >= 38:
            gp_spec = [("ownerIndex", "G"), ("nameIndex", "i"),
                       ("constraintsStart", "h"), ("constraintsCount", "h"),
                       ("num", "H"), ("flags", "H")]
            gp_stride = sum(self._fmt_size(f) for _, f in gp_spec)
            for i in range(gpc):
                rec = self._read_fields(gpo + i * gp_stride, gp_spec)
                if rec is None:
                    break
                self.generic_params.append(rec)
        else:
            for i in range(gpc):
                rec = self._rd("iI4H", gpo + i * 16)
                if rec is None:
                    break
                self.generic_params.append(dict(zip(
                    ["ownerIndex", "nameIndex", "constraintsStart", "constraintsCount",
                     "num", "flags"], rec)))

        # generic containers
        gco = self._tab_off("genericContainers")
        gcc = self._count("genericContainers")
        for i in range(gcc):
            rec = self._rd("4i", gco + i * 16)
            if rec is None:
                break
            self.generic_containers.append(dict(zip(
                ["ownerIndex", "type_argc", "is_method", "genericParameterStart"], rec)))

        # nested types (plain array of 4-byte TypeDefinitionIndex)
        ntc = self._count("nestedTypes")
        self.nested_types = self._ints(self._tab_off("nestedTypes"), ntc)

        # interfaces (flat TypeIndex[]; v38+ only - the v38 section is a
        # TypeIndex array, NOT interface-offset pairs)
        if v >= 38:
            ito = self._tab_off("interfaces")
            itc = self._count("interfaces")
            ts = self._idx_sizes["T"]
            for i in range(itc):
                self.interfaces.append(self._fmt_read("T", ito + i * ts))

        # interface offsets (Il2CppInterfaceOffsetPair)
        ioo = self._tab_off("interfaceOffsets")
        ioc = self._count("interfaceOffsets")
        if v >= 38:
            io_spec = [("interfaceTypeIndex", "T"), ("offset", "i")]
            io_stride = sum(self._fmt_size(f) for _, f in io_spec)
            for i in range(ioc):
                rec = self._read_fields(ioo + i * io_stride, io_spec)
                if rec is None:
                    break
                self.interface_offsets.append(rec)
        else:
            for i in range(ioc):
                rec = self._rd("2i", ioo + i * 8)
                if rec is None:
                    break
                self.interface_offsets.append(dict(zip(["interfaceTypeIndex", "offset"], rec)))

        # images (version-gated Il2CppImageDefinition)
        imo = self._tab_off("images")
        imc = self._count("images")
        if v >= 38:
            im_spec = [
                ("nameIndex", "i"), ("assemblyIndex", "i"), ("typeStart", "D"),
                ("typeCount", "i"), ("exportedTypeStart", "D"),
                ("exportedTypeCount", "i"), ("entryPointIndex", "i"),
                ("token", "i"), ("customAttributeStart", "i"),
                ("customAttributeCount", "i"),
            ]
            im_stride = sum(self._fmt_size(f) for _, f in im_spec)
            for i in range(imc):
                rec = self._read_fields(imo + i * im_stride, im_spec)
                if rec is None:
                    break
                self.images.append(rec)
        else:
            im_names = image_layout(v)
            im_fmt = "%di" % len(im_names)
            im_size = image_size(v)
            for i in range(imc):
                rec = self._rd(im_fmt, imo + i * im_size)
                if rec is None:
                    break
                self.images.append(dict(zip(im_names, rec)))

        # assemblies (v38+ includes moduleToken + full Il2CppAssemblyNameDefinition)
        ao = self._tab_off("assemblies")
        ac = self._count("assemblies")
        if v >= 38:
            for i in range(ac):
                rec = struct.unpack_from("<iIIIii", self.data, ao + i * 68)
                self.assemblies.append(dict(zip(
                    ["imageIndex", "token", "moduleToken", "referencedAssemblyStart",
                     "referencedAssemblyCount", "nameIndex"], rec)))
        elif v >= 24.1:
            a_names = ["imageIndex", "token", "referencedAssemblyStart", "referencedAssemblyCount"]
            a_fmt, a_size = "iI2i", 16
            for i in range(ac):
                rec = self._rd(a_fmt, ao + i * a_size)
                if rec is None:
                    break
                self.assemblies.append(dict(zip(a_names, rec)))
        else:
            a_names = ["imageIndex", "referencedAssemblyStart", "referencedAssemblyCount"]
            a_fmt, a_size = "3i", 12
            for i in range(ac):
                rec = self._rd(a_fmt, ao + i * a_size)
                if rec is None:
                    break
                self.assemblies.append(dict(zip(a_names, rec)))

        # field refs (Il2CppFieldRef). v38+ uses variable-width TypeIndex.
        fro = self._tab_off("fieldRefs")
        frc = self._count("fieldRefs")
        if fro > 0 and frc > 0:
            if v >= 38:
                fr_spec = [("typeIndex", "T"), ("fieldIndex", "i")]
                fr_stride = sum(self._fmt_size(f) for _, f in fr_spec)
                for i in range(frc):
                    rec = self._read_fields(fro + i * fr_stride, fr_spec)
                    if rec is None:
                        break
                    self.fields_refs.append(rec)
            else:
                for i in range(frc):
                    rec = self._rd("2i", fro + i * 8)
                    if rec is None:
                        break
                    self.fields_refs.append(dict(zip(["typeIndex", "fieldIndex"], rec)))

        # field default values (Il2CppFieldDefaultValue)
        fdo = self._tab_off("fieldDefaultValues")
        fdc = self._count("fieldDefaultValues")
        if fdo > 0 and fdc > 0:
            if v >= 38:
                fd_spec = [("fieldIndex", "i"), ("typeIndex", "T"), ("dataIndex", "i")]
                fd_stride = sum(self._fmt_size(f) for _, f in fd_spec)
                for i in range(fdc):
                    rec = self._read_fields(fdo + i * fd_stride, fd_spec)
                    if rec is None:
                        break
                    self.field_defaults.append(rec)
            else:
                for i in range(fdc):
                    rec = self._rd("3i", fdo + i * 12)
                    if rec is None:
                        break
                    self.field_defaults.append(dict(zip(["fieldIndex", "typeIndex", "dataIndex"], rec)))

        # parameter default values (Il2CppParameterDefaultValue)
        pdo = self._tab_off("parameterDefaultValues")
        pdc = self._count("parameterDefaultValues")
        if pdo > 0 and pdc > 0:
            if v >= 38:
                pd_spec = [("parameterIndex", "P"), ("typeIndex", "T"), ("dataIndex", "i")]
                pd_stride = sum(self._fmt_size(f) for _, f in pd_spec)
                for i in range(pdc):
                    rec = self._read_fields(pdo + i * pd_stride, pd_spec)
                    if rec is None:
                        break
                    self.param_defaults.append(rec)
            else:
                for i in range(pdc):
                    rec = self._rd("3i", pdo + i * 12)
                    if rec is None:
                        break
                    self.param_defaults.append(dict(zip(["parameterIndex", "typeIndex", "dataIndex"], rec)))

        # metadata usage lists / pairs (v19-24.5 only; modern metadata keeps
        # these in the binary's Il2CppMetadataRegistration instead)
        mlo = self._tab_off("metadataUsageLists")
        mlc = self._count("metadataUsageLists")
        mpo = self._tab_off("metadataUsagePairs")
        if mlo and mlc and mpo:
            for i in range(mlc):
                rec = self._rd("2I", mlo + i * 8)
                if rec is None:
                    break
                start, count = rec
                self.usage_lists.append(self._ints(mpo + start * 8, count)
                                        if start >= 0 else [])
        for i in range(self._count("metadataUsagePairs")):
            rec = self._rd("II", mpo + i * 8)
            if rec is None:
                break
            self.usage_pairs.append(dict(zip(["destinationIndex", "encodedSourceIndex"], rec)))

        # build type-index -> name maps for class references
        for td in self.type_defs:
            ns = self.read_string(td["namespaceIndex"])
            name = self.read_string(td["nameIndex"])
            full = (ns + "." + name) if ns else name
            self.byval_to_name[td["byvalTypeIndex"]] = full
            if "byrefTypeIndex" in td and td["byrefTypeIndex"] >= 0:
                self.byref_to_name[td["byrefTypeIndex"]] = full

        # index methods by declaring type definition (avoids O(n^2) lookups)
        for m in self.methods:
            self._methods_by_td.setdefault(m["declaringType"], []).append(m)

    # -- resolution --------------------------------------------------------

    # Every table that can appear in the header. The inline Il2CppType region
    # is not declared in the header; it lives right after the last table. We
    # recover its start as the maximum end offset (offset + byte size) of every
    # declared table.
    _ALL_TABLES = [
        "stringLiteral", "stringLiteralData", "string", "events", "properties",
        "methods", "parameterDefaultValues", "fieldDefaultValues",
        "fieldAndParameterDefaultValueData", "fieldMarshaledSizes",
        "parameters", "fields", "genericParameters", "genericParameterConstraints",
        "genericContainers", "nestedTypes", "interfaces", "vtableMethods",
        "interfaceOffsets", "typeDefinitions", "rgctxEntries", "images",
        "assemblies", "metadataUsageLists", "metadataUsagePairs", "fieldRefs",
        "referencedAssemblies", "attributesInfo", "attributeTypes",
        "attributeData", "attributeDataRange",
        "unresolvedVirtualCallParameterTypes", "unresolvedVirtualCallParameterRanges",
        "windowsRuntimeTypeNames", "windowsRuntimeStrings",
        "exportedTypeDefinitions",
    ]

    def _locate_type_region(self, override: Optional[int] = None):
        if override is not None:
            self.type_region_offset = override
            return
        max_end = 0
        for table in self._ALL_TABLES:
            off = self._sec_off(table)
            size = self._sec_size(table)
            if off and size:
                max_end = max(max_end, off + size)
        if max_end > 0 and max_end < len(self.data):
            self.type_region_offset = max_end

    def _read_type_slot(self, index: int) -> Optional[Dict]:
        if index < 0 or self.type_region_offset is None:
            return None
        off = self.type_region_offset + index * self.il2cpp_type_size
        if off + self.il2cpp_type_size > len(self.data):
            return None
        if self.version >= 31:
            vals = struct.unpack_from("<IIIBBBB", self.data, off)
            return {"type_index": vals[0], "data": vals[1], "attrs": vals[2],
                    "code": vals[3], "num_mods": vals[4], "flags": vals[5]}
        vals = struct.unpack_from("<IIBBBB", self.data, off)
        return {"type_index": None, "data": vals[0], "attrs": vals[1],
                "code": vals[2], "num_mods": vals[3], "flags": vals[4]}

    def _elem_index(self, t: Dict) -> Optional[int]:
        if t["type_index"] is not None:
            return t["type_index"]
        kind = t["data"] & 3
        return t["data"] >> 2 if kind == 0 else None

    def _klass_index(self, t: Dict) -> Optional[int]:
        if self.version >= 31 or self.version <= 27:
            return t["data"]
        kind = t["data"] & 3
        return t["data"] >> 2 if kind == 1 else None

    _PRIMITIVES = {
        0x01: "void", 0x02: "bool", 0x03: "char", 0x04: "sbyte",
        0x05: "byte", 0x06: "short", 0x07: "ushort", 0x08: "int",
        0x09: "uint", 0x0A: "long", 0x0B: "ulong", 0x0C: "float",
        0x0D: "double", 0x0E: "string", 0x16: "System.TypedReference",
        0x17: "IntPtr", 0x18: "UIntPtr", 0x1A: "object",
    }

    def decode_type_index(self, idx: int, depth: int = 0) -> str:
        if idx in (-1, 0xFFFFFFFF, 0x80000000):
            return "void"
        if depth > 8:
            return "<...>"
        # references to defined classes use the class's own byval type slot
        if idx in self.byval_to_name:
            return self.byval_to_name[idx]
        if idx in self.byref_to_name:
            return self.byref_to_name[idx] + "&"
        t = self._read_type_slot(idx)
        if t is None:
            return "<TypeIndex:%d>" % idx
        code = t["code"]
        if code in self._PRIMITIVES:
            return self._PRIMITIVES[code]
        if code in (0x11, 0x12):  # valuetype / class
            klass = self._klass_index(t)
            if klass is not None and 0 <= klass < len(self.type_defs):
                return self.type_def_name(klass)
            return "<class:%s>" % (klass if klass is not None else "?")
        if code == 0x0F:  # ptr
            e = self._elem_index(t)
            return self.decode_type_index(e, depth + 1) + "*" if e is not None else "void*"
        if code == 0x10:  # byref
            e = self._elem_index(t)
            return self.decode_type_index(e, depth + 1) + "&" if e is not None else "void&"
        if code == 0x1D:  # szarray
            e = self._elem_index(t)
            return self.decode_type_index(e, depth + 1) + "[]" if e is not None else "[]"
        if code == 0x14:  # array (multi-dim)
            e = self._elem_index(t)
            return self.decode_type_index(e, depth + 1) + "[...]" if e is not None else "[...]"
        if code == 0x15:  # genericinst
            e = self._elem_index(t)
            base = self.decode_type_index(e, depth + 1) if e is not None else "<gen>"
            return base + "<...>"
        if code in (0x13, 0x1C):  # var / mvar
            return "T%d" % (t["data"] >> 2)
        if code == 0x19:  # fnptr
            return "delegate*<>"
        return "<type:0x%02X>" % code

    def type_index_to_name(self, idx: int) -> str:
        return self.decode_type_index(idx)

    @staticmethod
    def visibility(flags: int) -> str:
        vis = flags & 0x7
        return {0: "private", 1: "private", 2: "protected internal",
                3: "internal", 4: "protected", 5: "protected internal",
                6: "public", 7: "internal"}.get(vis, "private")

    def type_def_name(self, idx: int) -> str:
        if 0 <= idx < len(self.type_defs):
            td = self.type_defs[idx]
            ns = self.read_string(td["namespaceIndex"])
            name = self.read_string(td["nameIndex"])
            return (ns + "." + name) if ns else name
        return "<TypeDef:%d>" % idx

    # -- rendering ---------------------------------------------------------
    def render_text(self, include_strings: bool = False) -> str:
        L: List[str] = []
        L.append("IL2CPP global-metadata dump")
        L.append("  version : %d" % self.version)
        L.append("  size    : %d bytes" % len(self.data))
        L.append("  strings : %d  string literals: %d" % (
            self._count("string"), len(self.string_literals)))
        L.append("  typeDefs: %d  methods: %d  fields: %d  params: %d" % (
            len(self.type_defs), len(self.methods), len(self.fields), len(self.params)))
        L.append("  images  : %d  assemblies: %d" % (len(self.images), len(self.assemblies)))

        if include_strings:
            L.append("")
            L.append("== String literals ==")
            for i, s in enumerate(self.string_literals):
                L.append("  [%5d] %r" % (i, s))
            L.append("")
            L.append("== Metadata strings ==")
            if self.version >= 38:
                # v38+: strings are indexed by absolute byte offset into the
                # blob, so enumerate the ones actually referenced (dedup) rather
                # than splitting the blob (which includes padding gaps).
                refs = set()
                for td in self.type_defs:
                    for k in ("nameIndex", "namespaceIndex"):
                        if k in td and td[k] >= 0:
                            refs.add(td[k])
                for m in self.methods:
                    if m.get("nameIndex", -1) >= 0:
                        refs.add(m["nameIndex"])
                for f in self.fields:
                    if f.get("nameIndex", -1) >= 0:
                        refs.add(f["nameIndex"])
                for img in self.images:
                    if img.get("nameIndex", -1) >= 0:
                        refs.add(img["nameIndex"])
                for i, s in sorted((i, self.read_string(i)) for i in refs):
                    L.append("  [%6d] %s" % (i, s))
            else:
                for i, s in enumerate(self.strings):
                    L.append("  [%5d] %s" % (i, s))

        if self.assemblies:
            L.append("")
            L.append("== Assemblies / Images ==")
            for a in self.assemblies:
                img = self.images[a["imageIndex"]] if 0 <= a["imageIndex"] < len(self.images) else None
                name = self.read_string(img["nameIndex"]) if img else "?"
                L.append("  [asm] %s (token 0x%08X)" % (name, a["token"]))
                if img:
                    L.append("        types: %s (start %d)" % (img["typeCount"], img["typeStart"]))

        L.append("")
        L.append("== Types ==")
        for td in self.type_defs:
            ns = self.read_string(td["namespaceIndex"])
            name = self.read_string(td["nameIndex"])
            mods = []
            if td["flags"] & 0x1:
                mods.append("public")
            if td["flags"] & 0x100:
                mods.append("sealed")
            if td["flags"] & 0x80:
                mods.append("abstract")
            mods = " ".join(mods) + " " if mods else ""
            parent = self.type_index_to_name(td["parentIndex"]) if td["parentIndex"] >= 0 else ""
            base = " : " + parent if parent else ""
            decl = "  %sclass %s%s" % (mods, name, base)
            if ns:
                L.append("namespace %s" % ns)
                L.append("{")
                decl = "  " + decl
            L.append(decl)
            L.append("  {")
            for f in self.fields_for(td):
                L.append("    %s %s;" % (
                    self.type_index_to_name(f["typeIndex"]),
                    self.read_string(f["nameIndex"])))
            for p in self.properties_for(td):
                L.append("    %s property %s;" % (self.read_string(p["nameIndex"]), p["token"] and "{}" or "{}"))
            for m in self.methods_for(td):
                L.append("    %s;" % self.method_signature(m))
            L.append("  }")
            if ns:
                L.append("}")
            L.append("")

        L.append("== Methods (global) ==")
        for m in self.methods:
            L.append("  %s :: %s" % (self.type_def_name(m["declaringType"]), self.method_signature(m)))

        L.append("")
        L.append("== Fields (global) ==")
        for f in self.fields:
            L.append("  %s %s" % (
                self.type_index_to_name(f["typeIndex"]),
                self.read_string(f["nameIndex"])))
        return "\n".join(L)

    def methods_for(self, td: Dict) -> List[Dict]:
        idx = td.get("_index", self.type_defs.index(td))
        return self._methods_by_td.get(idx, [])

    def fields_for(self, td: Dict) -> List[Dict]:
        start = max(0, td.get("fieldStart", 0))
        return self.fields[start: start + td.get("field_count", 0)]

    def properties_for(self, td: Dict) -> List[Dict]:
        start = max(0, td.get("propertyStart", 0))
        return self.properties[start: start + td.get("property_count", 0)]

    def method_signature(self, m: Dict) -> str:
        ret = self.type_index_to_name(m["returnType"])
        pstart, pcount = m["parameterStart"], m["parameterCount"]
        args = ", ".join(
            self.type_index_to_name(self.params[pstart + i]["typeIndex"])
            for i in range(pcount) if pstart + i < len(self.params))
        mods = []
        if m["flags"] & 0x10:
            mods.append("static")
        if m["flags"] & 0x40:
            mods.append("virtual")
        if m["flags"] & 0x400:
            mods.append("abstract")
        mods = " ".join(mods) + " " if mods else ""
        return "%s %s%s %s(%s)" % (
            self.visibility(m["flags"]), mods, ret,
            self.read_string(m["nameIndex"]), args)

    def to_json(self) -> Dict:
        return {
            "version": self.version,
            "strings": self.strings,
            "string_literals": self.string_literals,
            "type_definitions": self.type_defs,
            "methods": self.methods,
            "fields": self.fields,
            "parameters": self.params,
            "properties": self.properties,
            "events": self.events,
            "generic_parameters": self.generic_params,
            "generic_containers": self.generic_containers,
            "nested_types": self.nested_types,
            "interface_offsets": self.interface_offsets,
            "images": self.images,
            "assemblies": self.assemblies,
            "metadata_usage_lists": self.usage_lists,
            "metadata_usage_pairs": self.usage_pairs,
        }


def main() -> int:
    ap = argparse.ArgumentParser(
        description="IL2CPP global-metadata.dat dumper (research/testing tool).")
    ap.add_argument("-i", "--input", required=True, help="path to global-metadata.dat")
    ap.add_argument("-o", "--output", help="write text dump to file (default stdout)")
    ap.add_argument("--version", type=int, help="force metadata version override")
    ap.add_argument("--xor-key", metavar="HEX", help="repeating XOR key (hex) to decrypt protected metadata")
    ap.add_argument("--xor-offset", type=lambda s: int(s, 0), default=0,
                    help="start XOR decryption at this offset (default 0)")
    ap.add_argument("--type-region-offset", type=lambda s: int(s, 0), default=None,
                    help="override auto-detected Il2CppType region start (for real files with padding)")
    ap.add_argument("--json", action="store_true", help="also write <output>.json dump")
    ap.add_argument("--strings", action="store_true", help="include string literal/string tables in dump")
    args = ap.parse_args()

    with open(args.input, "rb") as f:
        raw = f.read()

    key = bytes.fromhex(args.xor_key) if args.xor_key else b""
    decrypted = xor_decrypt(raw, key, args.xor_offset)
    protected = decrypted is not raw

    try:
        meta = Metadata(decrypted, version=args.version,
                        type_region_offset=args.type_region_offset)
    except MetaError as e:
        if key:
            print("error: %s" % e, file=sys.stderr)
        else:
            print("error: %s" % e, file=sys.stderr)
            print("hint: if this file is protected, recover the XOR key from the game binary",
                  file=sys.stderr)
            print("      and retry with: --xor-key <hex>", file=sys.stderr)
        return 1

    text = meta.render_text(include_strings=args.strings)
    if protected:
        text += "\n[x] protected metadata decrypted with XOR key (offset %d)" % args.xor_offset
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    else:
        print(text)

    if args.json:
        jpath = (args.output or args.input) + ".json"
        with open(jpath, "w", encoding="utf-8") as f:
            json.dump(meta.to_json(), f, indent=1, ensure_ascii=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
