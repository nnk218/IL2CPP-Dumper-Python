#!/usr/bin/env python3
"""Generate synthetic ELF fixtures for testing il2cpp_bin_dumper.py.

  --bits 64 (default): 64-bit ELF (x86-64)
     libil2cpp_test.so       - symbol-search fixture (v31 code registration,
                               exported g_CodeRegistration /
                               g_MetadataRegistration). Pairs with sample.dat /
                               sample_xor.dat.
     libil2cpp_scan_test.so  - section-scan fixture (no symbols; 29.0-layout code
                               registration whose codeGenModule is named
                               "mscorlib.dll", plus the (3,3,ptr) metadata-registration
                               scan pattern). Pairs with sample_mscorlib.dat.
  --bits 32: 32-bit ELF (ARM), same two fixtures with 4-byte pointers, named
     libil2cpp_test32.so / libil2cpp_scan_test32.so.

The scan chain for the code registration is:
    "mscorlib.dll" string  <-moduleName field (offset 0 of codeGenModule)
      <- codeGenModules[0]   <- codeGenModules field in CodeRegistration
and the codeGenModulesCount field (refva3 - P) must equal imageCount (1).
"""

import argparse
import struct
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

BASE = 0x400000
METHOD_VA = 0x18000
TYPES_COUNT = 11


def pfmt(bits):
    return "Q" if bits == 64 else "I"


def align(bits):
    return 8 if bits == 64 else 4


def data_off_for(bits):
    return (64 + 56) if bits == 64 else (52 + 32)  # ELF header + program header


def va(off, data_off):
    return BASE + data_off + off


def build_data(scan_path: bool, bits: int, data_off: int):
    """Return (bytearray data, dict of data-relative offsets)."""
    pf = pfmt(bits)
    al = align(bits)
    data = bytearray()

    def blk(size):
        nonlocal data
        off = len(data)
        data += b"\x00" * size
        return off

    def put(off, fmt, *vals):
        struct.pack_into(fmt, data, off, *vals)

    def alignp():
        nonlocal data
        while len(data) % al:
            data += b"\x00"

    offs = {}

    # --- Il2CppType structs (datapoint ptr + bits u32) ---
    tsize = (8 if bits == 64 else 4) + 4
    offs["types"] = blk(TYPES_COUNT * tsize)
    bits_class = 0x12 << 16
    bits_byref = 0x10 << 16
    bits_szarr = 0x1D << 16
    bits_str = 0x0E << 16
    bits_var = 0x13 << 16
    bits_geninst = 0x15 << 16

    def mk_type(slot, data_value, bits_):
        put(offs["types"] + slot * tsize, "<" + pf + "I", data_value, bits_)

    t0 = offs["types"] + 0 * tsize
    t2 = offs["types"] + 2 * tsize
    t4 = offs["types"] + 4 * tsize
    mk_type(0, 0, bits_class)                 # 0 Object (TypeDefIndex 0)
    mk_type(1, va(t0, data_off), bits_byref)  # 1 Object&
    mk_type(2, 1, bits_class)                 # 2 TestClass (TypeDefIndex 1)
    mk_type(3, va(t2, data_off), bits_byref)  # 3 TestClass&
    mk_type(4, 2, bits_class)                 # 4 Int32 (TypeDefIndex 2)
    mk_type(5, va(t4, data_off), bits_byref)  # 5 Int32&
    mk_type(6, va(t4, data_off), bits_szarr)  # 6 Int32[]
    mk_type(7, 0, bits_str)                   # 7 string
    mk_type(8, 0, bits_var)                   # 8 generic param placeholder
    mk_type(9, 0, bits_geninst)               # 9 TestClass<Int32> (below)
    mk_type(10, 0, bits_class)                # 10 Object

    p2 = pf * 2
    p4 = pf * 4
    offs["gen_class"] = blk(4 * (8 if bits == 64 else 4))
    offs["gen_inst"] = blk(2 * (8 if bits == 64 else 4))
    offs["argv"] = blk(8 if bits == 64 else 4)
    put(offs["gen_class"], "<" + p4, va(t2, data_off), va(offs["gen_inst"], data_off), 0, 0)
    put(offs["gen_inst"], "<" + p2, 1, va(offs["argv"], data_off))
    put(offs["argv"], "<" + pf, va(t4, data_off))
    put(offs["types"] + 9 * tsize, "<" + pf + "I", va(offs["gen_class"], data_off), bits_geninst)

    offs["type_ptrs"] = blk(TYPES_COUNT * (8 if bits == 64 else 4))
    for i in range(TYPES_COUNT):
        put(offs["type_ptrs"] + i * (8 if bits == 64 else 4), "<" + pf,
            va(offs["types"] + i * tsize, data_off))

    offs["gen_inst_ptrs"] = blk(8 if bits == 64 else 4)
    put(offs["gen_inst_ptrs"], "<" + pf, va(offs["gen_inst"], data_off))

    # --- codeGenModule (moduleName is field 0, so VA(module) == VA(moduleName)) ---
    alignp()
    offs["cgm_ptrs"] = blk(8 if bits == 64 else 4)
    offs["cgm"] = blk(17 * (8 if bits == 64 else 4))
    module_name = "mscorlib.dll" if scan_path else "Assembly-CSharp"
    offs["module_name"] = blk(len(module_name) + 1)
    data[offs["module_name"]:offs["module_name"] + len(module_name)] = module_name.encode()
    offs["method_ptr_arr"] = blk(8 if bits == 64 else 4)
    put(offs["method_ptr_arr"], "<" + pf, METHOD_VA)
    put(offs["cgm_ptrs"], "<" + pf, va(offs["cgm"], data_off))
    put(offs["cgm"], "<" + pf * 17,
        va(offs["module_name"], data_off),  # moduleName
        1,                                  # methodPointerCount
        va(offs["method_ptr_arr"], data_off),  # methodPointers
        0, 0,                               # adjustorThunkCount/Thunks
        0,                                  # invokerIndices
        0, 0,                               # reversePInvokeWrapperCount/Indices
        0, 0,                               # rgctxRangesCount/Ranges
        0, 0,                               # rgctxsCount/rgctxs
        0,                                  # debuggerMetadata
        0,                                  # moduleInitializer
        0,                                  # staticConstructorTypeIndices
        0, 0)                               # metadataRegistration/codeRegistaration

    if scan_path:
        # decoy pointer array consumed by find_metadata_registration
        offs["fake_ptr_arr"] = blk(3 * (8 if bits == 64 else 4))
        for i in range(3):
            put(offs["fake_ptr_arr"] + i * (8 if bits == 64 else 4), "<" + pf,
                va(offs["types"] + i * tsize, data_off))

    alignp()
    if scan_path:
        # Il2CppCodeRegistration, 29.0 layout (15 fields, no
        # unresolvedInstanceCall/unresolvedStaticCall).
        offs["code_reg"] = blk(15 * (8 if bits == 64 else 4))
        put(offs["code_reg"], "<" + pf * 15,
            0,                      # reversePInvokeWrapperCount
            0,                      # reversePInvokeWrappers
            0,                      # genericMethodPointersCount
            0,                      # genericMethodPointers
            0,                      # genericAdjustorThunks
            0,                      # invokerPointersCount
            0,                      # invokerPointers
            0,                      # unresolvedVirtualCallCount
            0,                      # unresolvedVirtualCallPointers
            0,                      # interopDataCount
            0,                      # interopData
            0,                      # windowsRuntimeFactoryCount
            0,                      # windowsRuntimeFactoryTable
            1,                      # codeGenModulesCount
            va(offs["cgm_ptrs"], data_off))  # codeGenModules
    else:
        # Il2CppCodeRegistration, v31 layout (17 fields)
        offs["code_reg"] = blk(17 * (8 if bits == 64 else 4))
        put(offs["code_reg"], "<" + pf * 17,
            0,                      # reversePInvokeWrapperCount
            0,                      # reversePInvokeWrappers
            0,                      # genericMethodPointersCount
            0,                      # genericMethodPointers
            0,                      # genericAdjustorThunks
            0,                      # invokerPointersCount
            0,                      # invokerPointers
            0,                      # unresolvedVirtualCallCount
            0,                      # unresolvedVirtualCallPointers
            0,                      # unresolvedInstanceCallPointers
            0,                      # unresolvedStaticCallPointers
            0,                      # interopDataCount
            0,                      # interopData
            0,                      # windowsRuntimeFactoryCount
            0,                      # windowsRuntimeFactoryTable
            1,                      # codeGenModulesCount
            va(offs["cgm_ptrs"], data_off))  # codeGenModules

    offs["meta_reg"] = blk(16 * (8 if bits == 64 else 4))
    if scan_path:
        # v39 struct: typeDefinitionsCount at +0x50 (+10*ptr), typeDefinitions at +0x58,
        # fieldOffsetsCount at +0x60 (+12*ptr), fieldOffsets at +0x68 (+13*ptr).
        # find_metadata_registration checks count1=typeDefinitionsCount,
        # count2=typeDefinitionsCount at +2*ptr, pointer at +3*ptr.
        put(offs["meta_reg"], "<" + pf * 16,
            0,                      # genericClassesCount
            0,                      # genericClasses
            1,                      # genericInstsCount
            va(offs["gen_inst_ptrs"], data_off),  # genericInsts
            0,                      # genericMethodTableCount
            0,                      # genericMethodTable
            TYPES_COUNT,            # typesCount
            va(offs["type_ptrs"], data_off),  # types
            0,                      # methodSpecsCount
            0,                      # methodSpecs
            3,                      # typeDefinitionsCount (count1)
            va(offs["type_ptrs"], data_off),  # typeDefinitions
            3,                      # fieldOffsetsCount (count2)
            va(offs["fake_ptr_arr"], data_off),  # fieldOffsets (ptr for check)
            0,                      # typeDefinitionsSizesCount
            0)                      # metadataUsagesCount
    else:
        put(offs["meta_reg"], "<" + pf * 16,
            0, 0, 1, va(offs["gen_inst_ptrs"], data_off),
            0, 0, TYPES_COUNT, va(offs["type_ptrs"], data_off),
            0, 0, 0, 0, 0, 0, 0, 0)

    alignp()
    offs["usages"] = blk(3 * (8 if bits == 64 else 4))
    put(offs["usages"], "<" + pf * 3,
        ((1 << 29) | (4 << 1)) + 1,    # type_info  -> types[4] System.Int32
        ((3 << 29) | (0 << 1)) + 1,    # method_def -> methods[0] Method1
        ((5 << 29) | (0 << 1)) + 1)    # string_literal (no-op)

    return data, offs


def assemble_elf(data, syms, bits: int):
    """syms: list of (name, st_value) or None (=> no symbol table)."""
    pf = pfmt(bits)
    if bits == 64:
        phoff = 64
        phentsize = 56
        shentsize = 64
        shdr_fmt = "<IIQQQQIIQQ"
        sym_fmt = "<IBBHQQ"
        sym_entsize = 24
        elf_class = 2
        machine = 62  # x86-64
    else:
        phoff = 52
        phentsize = 32
        shentsize = 40
        shdr_fmt = "<IIIIIIIIII"
        sym_fmt = "<IBBHII"
        sym_entsize = 16
        elf_class = 1
        machine = 40  # ARM

    data_off = phoff + phentsize
    data_size = len(data)

    shstr = bytearray(b"\x00")
    sections = [None]  # index 0 = NULL, filled below

    def add_section(name, stype, flags, addr, offset, size, link, info, addralign, entsize):
        sections.append((name, stype, flags, addr, offset, size, link, info,
                         addralign, entsize))
        return len(sections) - 1

    dynsym_off = dynstr_off = dynstr = None
    shstr_off = data_off + data_size
    if syms:
        dynsym_size = len(syms) * sym_entsize
        dynsym_off = data_off + data_size
        dynstr_off = dynsym_off + dynsym_size
        dynstr = b"\x00"
        name_off = {}
        for nm, _ in syms:
            name_off[nm] = len(dynstr)
            dynstr += nm.encode("utf-8") + b"\x00"
        shstr_off = dynstr_off + len(dynstr)

    sections[0] = ("", 0, 0, 0, 0, 0, 0, 0, 0, 0)
    idx_data = add_section(".data", 1, 3, va(0, data_off), data_off, data_size, 0, 0, 8, 0)
    if syms:
        add_section(".dynsym", 11, 2, 0, dynsym_off,
                    len(syms) * sym_entsize, len(sections) + 1, 1, 8, sym_entsize)
        add_section(".dynstr", 3, 2, 0, dynstr_off, len(dynstr), 0, 0, 1, 0)

    # build .shstrtab contents from the section names added so far
    shstr = bytearray(b"\x00")
    name_off2 = {}
    for i in range(1, len(sections)):
        name_off2[i] = len(shstr)
        shstr += sections[i][0].encode("utf-8") + b"\x00"
    idx_shstr = add_section(".shstrtab", 3, 0, 0, shstr_off, 0, 0, 0, 1, 0)
    name_off2[idx_shstr] = len(shstr)
    shstr += b".shstrtab\x00"

    shoff = shstr_off + len(shstr)
    shnum = len(sections)
    filesz = shoff + shnum * shentsize

    e_ident = bytes([0x7F, 0x45, 0x4C, 0x46, elf_class, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0])

    file = bytearray(filesz)
    if bits == 64:
        phdr = struct.pack("<IIQQQQQQ", 1, 6, 0, BASE, BASE, filesz, filesz, 0x1000)
        file[0:16] = e_ident
        struct.pack_into("<HHIQQQIHHHHHH", file, 16,
                         3,          # e_type ET_DYN
                         machine,    # e_machine
                         1,          # e_version
                         0,          # e_entry
                         phoff,      # e_phoff
                         shoff,      # e_shoff
                         0,          # e_flags
                         64,         # e_ehsize
                         phentsize,  # e_phentsize
                         1,          # e_phnum
                         shentsize,  # e_shentsize
                         shnum,      # e_shnum
                         idx_shstr)  # e_shstrndx
    else:
        phdr = struct.pack("<IIIIIIII", 1, 0, BASE, BASE, filesz, filesz, 6, 0x1000)
        file[0:16] = e_ident
        struct.pack_into("<HHIIIIIHHHHHH", file, 16,
                         3,          # e_type ET_DYN
                         machine,    # e_machine
                         1,          # e_version
                         0,          # e_entry
                         phoff,      # e_phoff
                         shoff,      # e_shoff
                         0,          # e_flags
                         52,         # e_ehsize
                         phentsize,  # e_phentsize
                         1,          # e_phnum
                         shentsize,  # e_shentsize
                         shnum,      # e_shnum
                         idx_shstr)  # e_shstrndx
    file[phoff:phoff + phentsize] = phdr
    file[data_off:data_off + data_size] = data
    if syms:
        symbytes = b"".join(
            struct.pack(sym_fmt, name_off[nm], 0x11, 0, idx_data, st_value, 0)
            for nm, st_value in syms)
        file[dynsym_off:dynsym_off + len(symbytes)] = symbytes
        file[dynstr_off:dynstr_off + len(dynstr)] = dynstr
    file[shstr_off:shstr_off + len(shstr)] = shstr
    for i in range(1, shnum):
        nm, stype, flags, addr, offset, size, link, info, addralign, entsize = sections[i]
        if i == idx_shstr:
            size = len(shstr)
        struct.pack_into(shdr_fmt, file, shoff + i * shentsize,
                         name_off2[i], stype, flags, addr, offset, size,
                         link, info, addralign, entsize)
    return bytes(file), data_off


def self_check_elf(path, meta_path, expect_scan, bits):
    if bits == 64:
        from il2cpp_bin_dumper import Elf64Binary as ElfBinary_
    else:
        from il2cpp_bin_dumper import Elf32Binary as ElfBinary_
    from il2cpp_bin_dumper import SectionHelper
    from il2cpp_meta_dumper import Metadata

    b = ElfBinary_(open(path, "rb").read())
    assert b.ptr == (8 if bits == 64 else 4)
    meta = Metadata(open(meta_path, "rb").read())
    c, m = b.symbol_search()
    if expect_scan:
        assert c == 0 and m == 0
        sh = SectionHelper(b, meta.version, len(meta.methods),
                           len(meta.type_defs), len(meta.images))
        code_reg = sh.find_code_registration()
        meta_reg = sh.find_metadata_registration()
        print("scan: CodeReg=0x%x MetaReg=0x%x" % (code_reg, meta_reg))
        return code_reg, meta_reg
    else:
        assert c != 0 and m != 0
        print("symbols: CodeReg=0x%x MetaReg=0x%x" % (c, m))
        return c, m


def main():
    ap = argparse.ArgumentParser(description="Generate ELF fixtures.")
    ap.add_argument("--bits", type=int, choices=(64, 32), default=64)
    args = ap.parse_args()
    bits = args.bits
    suffix = "" if bits == 64 else "32"
    data_off = data_off_for(bits)

    # ---- symbol-path fixture: sample.dat / sample_xor.dat ----
    data, offs = build_data(scan_path=False, bits=bits, data_off=data_off)
    blob, _ = assemble_elf(data, [("g_CodeRegistration", va(offs["code_reg"], data_off)),
                                  ("g_MetadataRegistration", va(offs["meta_reg"], data_off))],
                           bits)
    sym_name = "libil2cpp_test%s.so" % suffix
    with open(sym_name, "wb") as f:
        f.write(blob)
    c, m = self_check_elf(sym_name, "sample.dat", expect_scan=False, bits=bits)
    assert c == va(offs["code_reg"], data_off) and m == va(offs["meta_reg"], data_off), \
        (hex(c), hex(m))
    print("wrote %s (%d bytes)" % (sym_name, len(blob)))

    # ---- scan-path fixture: sample_mscorlib.dat ----
    data2, offs2 = build_data(scan_path=True, bits=bits, data_off=data_off)
    blob2, _ = assemble_elf(data2, None, bits)
    scan_name = "libil2cpp_scan_test%s.so" % suffix
    with open(scan_name, "wb") as f:
        f.write(blob2)
    c2, m2 = self_check_elf(scan_name, "sample_mscorlib.dat", expect_scan=True, bits=bits)
    assert c2 == va(offs2["code_reg"], data_off) and m2 == va(offs2["meta_reg"], data_off), \
        (hex(c2), hex(m2))
    print("wrote %s (%d bytes)" % (scan_name, len(blob2)))


if __name__ == "__main__":
    main()
