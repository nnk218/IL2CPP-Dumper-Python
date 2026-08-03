#!/usr/bin/env python3
"""Generate a synthetic global-metadata.dat (v31) for testing the dumper.

Writes two files:
    sample.dat        - plain metadata
    sample_xor.dat    - same metadata XOR-encrypted with a 32-byte key

The XOR scheme matches the common Il2CppDumper XOR forks: the entire file is
XORed cyclically with the key.

Layouts follow the REAL il2cpp metadata structures (GlobalMetadataFileInternals.h
+ Il2CppDumper version gating):
  - header stores byte sizes (Offset/Size pairs), usage lists are NOT in the
    v31 header (they moved to the binary's Il2CppMetadataRegistration)
  - Il2CppTypeDefinition v31: 88 bytes (name, ns, byvalType, declaringType,
    parentType, elementType, genericContainer, flags, 8 start indices,
    8 x u16 counts, bitfield, token)
  - Il2CppMethodDefinition v31: 36 bytes (name, declaringType, returnType,
    returnParameterToken, parameterStart, genericContainer, token, flags,
    iflags, slot, parameterCount)

Usage:
    python3 make_test_metadata.py
    python3 il2cpp_meta_dumper.py -i sample_xor.dat --xor-key <printed key> -o dump.txt
"""

import struct
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from il2cpp_meta_dumper import MAGIC, header_fields

VERSION = 31
KEY = bytes.fromhex("00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f")

OUT_PLAIN = "sample.dat"
OUT_XOR = "sample_xor.dat"

STRINGS = [
    "Assembly-CSharp",  # 0
    "Test",             # 1
    "TestClass",        # 2
    "System",           # 3
    "Object",           # 4
    "Int32",            # 5
    "Field1",           # 6
    "Array1",           # 7
    "Gen1",             # 8
    "ObjRef",           # 9
    "Method1",          # 10
    "Param0",           # 11
    "Param1",           # 12
    "mscorlib.dll",     # 13
]
STRIDX = {s: i for i, s in enumerate(STRINGS)}


def pack_table(data: bytearray, header, name, payload):
    if payload is None or len(payload) == 0:
        header[name + "Offset"] = 0
        header[name + "Size"] = 0
        return
    header[name + "Offset"] = len(data)
    header[name + "Size"] = len(payload)
    data += payload


def build(image_name: str = "Assembly-CSharp") -> bytes:
    header = {}
    hfields = header_fields(VERSION)
    hsize = len(hfields) * 4
    buf = bytearray(hsize)  # reserve header space so recorded offsets are absolute

    # string table: a NUL-terminated blob; string indexes are direct byte
    # offsets into this blob (real metadata layout, all versions)
    sdata = bytearray()
    soff = {}
    for s in STRINGS:
        soff[s] = len(sdata)
        sdata += s.encode("utf-8") + b"\x00"
    pack_table(buf, header, "string", bytes(sdata))
    global STRIDX
    STRIDX = {s: soff[s] for s in STRINGS}

    # string literal data (literal bytes live here)
    LITERALS = ["Hello World!", "Test string 你好"]
    lit_off = {}
    ldata = bytearray()
    for lit in LITERALS:
        lit_off[lit] = len(ldata)
        ldata += lit.encode("utf-8") + b"\x00"
    pack_table(buf, header, "stringLiteralData", bytes(ldata))

    # stringLiteral: records of (length i4, dataIndex i4) into stringLiteralData
    lit_table = b"".join(
        struct.pack("<Ii", len(lit.encode("utf-8")), lit_off[lit])
        for lit in LITERALS)
    pack_table(buf, header, "stringLiteral", lit_table)

    # type definitions (real v31 layout: 16 i4 + 8 u2 + u4 + u4 = 88 bytes)
    def mk_td(name, ns, byval, declaring, parent, element, gcontainer, flags,
              field_start, method_start, mcount, fcount, token):
        return struct.pack("<16i8HII",
                           STRIDX[name], STRIDX[ns], byval, declaring, parent,
                           element, gcontainer, flags,
                           field_start, method_start, 0, 0, 0, 0, 0, 0,
                           mcount, 0, fcount, 0, 0, 0, 0, 0,
                           0, token)

    type_defs = b"".join([
        mk_td("Object", "System", 0, -1, -1, -1, -1, 0x21, 0, 0, 0, 0, 0x20000000),
        mk_td("TestClass", "Test", 2, -1, 0, -1, -1, 0x21, 0, 0, 1, 4, 0x20000001),
        mk_td("Int32", "System", 4, -1, -1, -1, -1, 0x21, 0, 0, 0, 0, 0x20000002),
    ])
    pack_table(buf, header, "typeDefinitions", type_defs)

    # methods (real v31 layout: name, declaringType, returnType,
    #          returnParameterToken, parameterStart, genericContainer,
    #          token, flags, iflags, slot, parameterCount = 36 bytes)
    methods = struct.pack("<6iI4H",
                          STRIDX["Method1"], 1, 7, 0, 0, -1, 0x60000001,
                          0x6, 0, 0, 2)
    pack_table(buf, header, "methods", methods)

    # parameters: nameIndex, token, typeIndex (System.Int32 = type slot 4)
    params = b"".join([
        struct.pack("<iIi", STRIDX["Param0"], 0x80000000, 4),
        struct.pack("<iIi", STRIDX["Param1"], 0x80000001, 4),
    ])
    pack_table(buf, header, "parameters", params)

    # fields: nameIndex, typeIndex, token
    fields = b"".join([
        struct.pack("<2iI", STRIDX["Field1"], 4, 0x40000001),    # System.Int32
        struct.pack("<2iI", STRIDX["Array1"], 6, 0x40000002),    # System.Int32[]
        struct.pack("<2iI", STRIDX["Gen1"], 9, 0x40000003),      # Test.TestClass<...>
        struct.pack("<2iI", STRIDX["ObjRef"], 10, 0x40000004),   # System.Object (via klass)
    ])
    pack_table(buf, header, "fields", fields)

    # images (real v31 layout: name, assembly, typeStart, typeCount,
    #          exportedTypeStart, exportedTypeCount, entryPoint, token,
    #          customAttributeStart, customAttributeCount = 40 bytes)
    images = struct.pack("<10i",
                         STRIDX[image_name], 0, 0, 3, -1, 0, -1,
                         0x20000001, 0, 0)
    pack_table(buf, header, "images", images)

    # assemblies: imageIndex, token, referencedAssemblyStart, referencedAssemblyCount
    assemblies = struct.pack("<iI2i", 0, 0x20000001, 0, 0)
    pack_table(buf, header, "assemblies", assemblies)

    # vtable methods (one slot, invalid) so typeDef vtable_count==0 stays consistent
    pack_table(buf, header, "vtableMethods", struct.pack("<i", -1))

    # remaining v31 header tables: empty (fieldRefs, referencedAssemblies,
    # attributeData, attributeDataRange, unresolvedVirtualCall*,
    # windowsRuntimeTypeNames/strings, exportedTypeDefinitions)
    for t in ["fieldRefs", "referencedAssemblies", "attributeData",
              "attributeDataRange", "unresolvedVirtualCallParameterTypes",
              "unresolvedVirtualCallParameterRanges", "windowsRuntimeTypeNames",
              "windowsRuntimeStrings", "exportedTypeDefinitions"]:
        pack_table(buf, header, t, b"")

    # Inline Il2CppType region (NOT declared in the header). Lives at the end
    # of the file; the dumper finds it as the max end of all declared tables.
    # v31 slot: typeIndex(I), data(I), attrs(I), type(B), num_mods(B),
    #           flags(B), padding(B) = 16 bytes
    def mk_type(ti, data, code, klass=None):
        return struct.pack("<IIIBBBB", ti, klass if klass is not None else data,
                           0, code, 0, 0, 0)

    type_region = b"".join([
        mk_type(0, 0, 0x12, klass=0),      # 0 Object class (byval)
        mk_type(0, 0, 0x10),               # 1 Object&   (byref of 0)
        mk_type(0, 0, 0x12, klass=1),      # 2 TestClass class (byval)
        mk_type(0, 0, 0x10),               # 3 TestClass& (byref of 2)
        mk_type(0, 0, 0x12, klass=2),      # 4 Int32 class (byval)
        mk_type(0, 0, 0x10),               # 5 Int32& (byref of 4)
        mk_type(4, 0, 0x1D),               # 6 System.Int32[] (szarray, elem=4)
        mk_type(0, 0, 0x0E),               # 7 string primitive
        mk_type(0, 0, 0x13),               # 8 generic param placeholder
        mk_type(2, 0, 0x15),               # 9 Test.TestClass<...> (genericinst)
        mk_type(0, 0, 0x12, klass=0),      # 10 Object via klassIndex
    ])
    buf += type_region

    # assemble header
    hfields = header_fields(VERSION)
    hsize = len(hfields) * 4
    header_bytes = bytearray(hsize)
    for i, name in enumerate(hfields):
        struct.pack_into("<I", header_bytes, i * 4, header.get(name, 0))
    struct.pack_into("<II", header_bytes, 0, MAGIC, VERSION)

    return bytes(header_bytes) + bytes(buf[hsize:])


def main():
    plain = build("Assembly-CSharp")

    # sanity check the plain file parses
    from il2cpp_meta_dumper import Metadata
    meta = Metadata(plain)
    assert meta.version == VERSION
    assert len(meta.type_defs) == 3
    assert meta.type_region_offset is not None, "type region not located"
    assert meta.decode_type_index(4) == "System.Int32"
    assert meta.decode_type_index(6) == "System.Int32[]"
    assert meta.decode_type_index(7) == "string"
    assert meta.decode_type_index(10) == "System.Object"
    assert meta.decode_type_index(9) == "Test.TestClass<...>"
    assert meta.decode_type_index(1) == "System.Object&"
    assert meta.string_literals == ["Hello World!", "Test string 你好"], meta.string_literals

    mscorlib = build("mscorlib.dll")
    meta_m = Metadata(mscorlib)
    assert len(meta_m.images) == 1
    assert meta_m.read_string(meta_m.images[0]["nameIndex"]) == "mscorlib.dll"

    # XOR-encrypt whole file
    enc = bytearray(plain)
    for i in range(len(enc)):
        enc[i] ^= KEY[i % len(KEY)]

    with open(OUT_PLAIN, "wb") as f:
        f.write(plain)
    with open(OUT_XOR, "wb") as f:
        f.write(enc)
    with open("sample_mscorlib.dat", "wb") as f:
        f.write(mscorlib)

    # protected mscorlib variant (pairs with libil2cpp_scan_test*.so)
    enc_m = bytearray(mscorlib)
    for i in range(len(enc_m)):
        enc_m[i] ^= KEY[i % len(KEY)]
    with open("sample_mscorlib_xor.dat", "wb") as f:
        f.write(enc_m)

    print("wrote %s (%d bytes, version %d)" % (OUT_PLAIN, len(plain), VERSION))
    print("wrote %s (%d bytes, XOR key: %s)" % (OUT_XOR, len(enc), KEY.hex()))
    print("wrote sample_mscorlib.dat (%d bytes, image 'mscorlib.dll')" % len(mscorlib))
    print("wrote sample_mscorlib_xor.dat (%d bytes, XOR key: %s)" % (len(enc_m), KEY.hex()))


if __name__ == "__main__":
    main()
