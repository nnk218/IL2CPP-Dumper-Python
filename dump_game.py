#!/usr/bin/env python3
"""IL2CPP binary dumper - research / testing tool.

Given a Unity game binary (libil2cpp.so / GameAssembly.dll) and the matching
global-metadata.dat, locates Il2CppCodeRegistration / Il2CppMetadataRegistration
and produces a script.json + stringliteral.json with method/type/string
addresses, mirroring Perfare/Il2CppDumper's output schema.

Lookup strategy (matches Il2CppDumper):
  1. SymbolSearch: exported symbols g_CodeRegistration / g_MetadataRegistration
  2. SectionHelper scan (stripped binaries): "mscorlib.dll" reference walk for
     CodeRegistration; typeDefinitionsCount heuristic for MetadataRegistration

Supported metadata versions: 24-35 (modern gating). Binaries: ELF64
(x86-64/ARM64), ELF32 (ARM/x86 - pointer-sized struct fields read as 4 bytes),
PE32+. For v27+ the string-literal / type-info usage table is recovered by
scanning the binary's data segments for encoded tokens (EncodedMethodIndex:
top 3 bits = usage kind, LSB = 1).

Usage:
    python3 dump_game.py -g game.apk -o outdir/          # auto-discover from APK/AAB/XAPK
    python3 dump_game.py -g game/ -o outdir/             # or an extracted game directory
    python3 dump_game.py -b libil2cpp.so -m global-metadata.dat -o outdir/   # explicit pair

When several ABIs are present inside the game package, arm64-v8a (64-bit) is
preferred over armeabi-v7a (32-bit); a lone candidate is used as-is.
"""

import argparse
import json
import os
import struct
import sys
import tempfile
import zipfile
from typing import Dict, List, Optional, Tuple

from dump_metadata import Metadata, method_def_size, type_def_size

# --------------------------------------------------------------------------
# Version-gated struct layouts (Il2CppClass.cs). Spec: (name, kind, [(min,max)])
# Each field is pointer-sized (8 bytes for 64-bit, 4 bytes for 32-bit targets).
# --------------------------------------------------------------------------

def _in_ranges(version, ranges):
    return any((mn is None or version >= mn) and (mx is None or version <= mx)
               for mn, mx in ranges)

CODE_REG_SPEC = [
    ("methodPointersCount", [(None, 24.1)]),
    ("methodPointers", [(None, 24.1)]),
    ("delegateWrappersFromNativeToManagedCount", [(None, 21)]),
    ("delegateWrappersFromNativeToManaged", [(None, 21)]),
    ("reversePInvokeWrapperCount", [(22, None)]),
    ("reversePInvokeWrappers", [(22, None)]),
    ("delegateWrappersFromManagedToNativeCount", [(None, 22)]),
    ("delegateWrappersFromManagedToNative", [(None, 22)]),
    ("marshalingFunctionsCount", [(None, 22)]),
    ("marshalingFunctions", [(None, 22)]),
    ("ccwMarshalingFunctionsCount", [(21, 22)]),
    ("ccwMarshalingFunctions", [(21, 22)]),
    ("genericMethodPointersCount", [(None, None)]),
    ("genericMethodPointers", [(None, None)]),
    ("genericAdjustorThunks", [(24.5, 24.5), (27.1, None)]),
    ("invokerPointersCount", [(None, None)]),
    ("invokerPointers", [(None, None)]),
    ("customAttributeCount", [(None, 24.5)]),
    ("customAttributeGenerators", [(None, 24.5)]),
    ("guidCount", [(21, 22)]),
    ("guids", [(21, 22)]),
    ("unresolvedVirtualCallCount", [(22, None)]),
    ("unresolvedVirtualCallPointers", [(22, None)]),
    ("unresolvedInstanceCallPointers", [(29.1, None)]),
    ("unresolvedStaticCallPointers", [(29.1, None)]),
    ("interopDataCount", [(23, None)]),
    ("interopData", [(23, None)]),
    ("windowsRuntimeFactoryCount", [(24.3, None)]),
    ("windowsRuntimeFactoryTable", [(24.3, None)]),
    ("codeGenModulesCount", [(24.2, None)]),
    ("codeGenModules", [(24.2, None)]),
]

META_REG_SPEC = [
    ("genericClassesCount", [(None, None)]),
    ("genericClasses", [(None, None)]),
    ("genericInstsCount", [(None, None)]),
    ("genericInsts", [(None, None)]),
    ("genericMethodTableCount", [(None, None)]),
    ("genericMethodTable", [(None, None)]),
    ("typesCount", [(None, None)]),
    ("types", [(None, None)]),
    ("methodSpecsCount", [(None, None)]),
    ("methodSpecs", [(None, None)]),
    ("methodReferencesCount", [(None, 16)]),
    ("methodReferences", [(None, 16)]),
    ("fieldOffsetsCount", [(None, None)]),
    ("fieldOffsets", [(None, None)]),
    ("typeDefinitionsSizesCount", [(None, None)]),
    ("typeDefinitionsSizes", [(None, None)]),
    ("metadataUsagesCount", [(19, None)]),
    ("metadataUsages", [(19, None)]),
]

CODE_GEN_MODULE_SPEC = [
    ("moduleName", [(None, None)]),
    ("methodPointerCount", [(None, None)]),
    ("methodPointers", [(None, None)]),
    ("adjustorThunkCount", [(24.5, 24.5), (27.1, None)]),
    ("adjustorThunks", [(24.5, 24.5), (27.1, None)]),
    ("invokerIndices", [(None, None)]),
    ("reversePInvokeWrapperCount", [(None, None)]),
    ("reversePInvokeWrapperIndices", [(None, None)]),
    ("rgctxRangesCount", [(None, None)]),
    ("rgctxRanges", [(None, None)]),
    ("rgctxsCount", [(None, None)]),
    ("rgctxs", [(None, None)]),
    ("debuggerMetadata", [(None, None)]),
    ("customAttributeCacheGenerator", [(27, 27.2)]),
    ("moduleInitializer", [(27, None)]),
    ("staticConstructorTypeIndices", [(27, None)]),
    ("metadataRegistration", [(27, None)]),
    ("codeRegistaration", [(27, None)]),
]


def read_struct(data: bytes, va_off: Optional[int], spec, version, ptr: int = 8) -> Optional[Dict[str, int]]:
    if va_off is None or va_off + ptr * len(spec) > len(data):
        return None
    out = {}
    cur = va_off
    for name, ranges in spec:
        if not _in_ranges(version, ranges):
            continue
        fmt = "Q" if ptr == 8 else "I"
        out[name] = struct.unpack_from("<" + fmt, data, cur)[0]
        cur += ptr
    return out


def struct_size(version, spec, ptr: int = 8) -> int:
    return ptr * sum(1 for _, ranges in spec if _in_ranges(version, ranges))


# --------------------------------------------------------------------------
# Binary formats
# --------------------------------------------------------------------------

class Binary:
    """Base: byte buffer with VA<->file-offset mapping."""
    def __init__(self, data: bytes):
        self.data = bytearray(data)
        self.ptr = 8  # pointer size; 32-bit formats override with 4

    def apply_relocations(self):
        """Apply ELF/PE relocations in place (matches Il2CppDumper's
        RelocationProcessing/ApplyRelocation): writes the load-time pointer
        values that the section scan depends on for stripped binaries.
        No-op for formats/versions without a relocation pass."""
        return

    def map_va_to_off(self, va: int) -> Optional[int]:
        raise NotImplementedError

    def map_off_to_va(self, off: int) -> int:
        raise NotImplementedError

    def get_rva(self, va: int) -> int:
        return va

    def read_fields(self, va, spec) -> Optional[Dict[str, int]]:
        return read_struct(self.data, self.map_va_to_off(va), spec, self.version, self.ptr)

    def read_u64(self, va: int) -> Optional[int]:
        off = self.map_va_to_off(va)
        if off is None or off + 8 > len(self.data):
            return None
        return struct.unpack_from("<Q", self.data, off)[0]

    def read_i64(self, va: int) -> Optional[int]:
        v = self.read_u64(va)
        if v is None or v >= 1 << 63:
            return None
        return v

    def read_u64_array(self, va: int, count: int) -> List[int]:
        if count <= 0:
            return []
        off = self.map_va_to_off(va)
        if off is None or off + 8 * count > len(self.data):
            return []
        return list(struct.unpack_from("<%dQ" % count, self.data, off))

    def read_ptr(self, va: int) -> Optional[int]:
        off = self.map_va_to_off(va)
        if off is None or off + self.ptr > len(self.data):
            return None
        fmt = "Q" if self.ptr == 8 else "I"
        return struct.unpack_from("<" + fmt, self.data, off)[0]

    def read_ptr_array(self, va: int, count: int) -> List[int]:
        if count <= 0:
            return []
        off = self.map_va_to_off(va)
        if off is None or off + self.ptr * count > len(self.data):
            return []
        fmt = "<%d%s" % (count, "Q" if self.ptr == 8 else "I")
        return list(struct.unpack_from(fmt, self.data, off))

    def read_cstr(self, va: int) -> str:
        off = self.map_va_to_off(va)
        if off is None:
            return ""
        end = self.data.find(b"\x00", off)
        if end == -1:
            end = len(self.data)
        try:
            return self.data[off:end].decode("utf-8", "replace")
        except Exception:
            return ""

    def data_scan_ranges(self) -> List[Tuple[int, int]]:
        raise NotImplementedError


class ElfBinary(Binary):
    """Shared ELF logic; program/section headers are parsed by the subclass."""

    def map_va_to_off(self, va: int) -> Optional[int]:
        for p in self.phdrs:
            if p["type"] != 1:  # PT_LOAD
                continue
            if p["vaddr"] <= va < p["vaddr"] + p["memsz"]:
                return va - p["vaddr"] + p["offset"]
        return None

    def map_off_to_va(self, off: int) -> int:
        for p in self.phdrs:
            if p["offset"] <= off < p["offset"] + p["filesz"]:
                return off - p["offset"] + p["vaddr"]
        return 0

    def data_scan_ranges(self) -> List[Tuple[int, int]]:
        ranges = []
        for p in self.phdrs:
            if p["type"] != 1 or p["filesz"] == 0:
                continue
            # PF_R(4)|PF_W(2) => data; PF_R|PF_X(1) => exec
            if p["flags"] in (2, 4, 6):
                ranges.append((p["offset"], p["offset"] + p["filesz"]))
        return ranges

    def read_symtable(self) -> List[Tuple[str, int]]:
        """Gather (name, st_value) from .dynsym/.symtab via section table."""
        def_entsize = 24 if self.ptr == 8 else 16
        fmt = "<IBBHQQ" if self.ptr == 8 else "<IBBHII"
        syms = []
        for i, s in enumerate(self.shdrs):
            if s["type"] not in (2, 11):  # SHT_SYMTAB / SHT_DYNSYM
                continue
            name = self.section_names[i]
            strtab = None
            if s["link"] < len(self.shdrs):
                st = self.shdrs[s["link"]]
                strtab = self.data[st["offset"]: st["offset"] + st["size"]]
            if strtab is None:
                continue
            entsize = s["entsize"] or def_entsize
            for j in range(s["size"] // entsize):
                off = s["offset"] + j * entsize
                st_name, st_info, st_other, st_shndx, st_value, st_size = \
                    struct.unpack_from(fmt, self.data, off)
                if st_name >= len(strtab):
                    continue
                end = strtab.find(b"\x00", st_name)
                nm = strtab[st_name:end].decode("utf-8", "replace") if end != -1 else ""
                if nm and (name == ".dynsym" or st_shndx != 0):
                    syms.append((nm, st_value))
        return syms

    def symbol_search(self) -> Tuple[int, int]:
        code_reg = meta_reg = 0
        for nm, val in self.read_symtable():
            if nm == "g_CodeRegistration":
                code_reg = val
            elif nm == "g_MetadataRegistration":
                meta_reg = val
        return code_reg, meta_reg


class Elf64Binary(ElfBinary):
    def __init__(self, data: bytes):
        Binary.__init__(self, data)
        if len(data) < 64 or data[:4] != b"\x7fELF":
            raise ValueError("not an ELF file")
        if data[4] != 2:
            raise ValueError("only 64-bit ELF supported")
        e_phoff, e_shoff = struct.unpack_from("<QQ", data, 32)
        e_machine, = struct.unpack_from("<H", data, 18)
        e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
        self.machine = e_machine
        self.phdrs = []
        for i in range(e_phnum):
            p = struct.unpack_from("<IIQQQQQQ", data, e_phoff + i * e_phentsize)
            self.phdrs.append({
                "type": p[0], "flags": p[1], "offset": p[2], "vaddr": p[3],
                "paddr": p[4], "filesz": p[5], "memsz": p[6], "align": p[7],
            })
        self.shdrs = []
        if e_shoff and e_shnum:
            for i in range(e_shnum):
                s = struct.unpack_from("<IIQQQQIIQQ", data, e_shoff + i * e_shentsize)
                self.shdrs.append({
                    "name": s[0], "type": s[1], "flags": s[2], "addr": s[3],
                    "offset": s[4], "size": s[5], "link": s[6], "info": s[7],
                    "addralign": s[8], "entsize": s[9],
                })
        self.section_names = []
        if self.shdrs and e_shstrndx < len(self.shdrs) and self.shdrs[e_shstrndx]["type"] != 0:
            shstr = self.shdrs[e_shstrndx]
            names = data[shstr["offset"]: shstr["offset"] + shstr["size"]]
            for s in self.shdrs:
                end = names.find(b"\x00", s["name"])
                self.section_names.append(names[s["name"]:end].decode("utf-8", "replace") if end != -1 else "")
        else:
            self.section_names = [""] * len(self.shdrs)

    def _dyn_val(self, tag: int) -> Optional[int]:
        """Return the d_un value for a given DT_* tag from the PT_DYNAMIC segment."""
        for p in self.phdrs:
            if p["type"] != 2:  # PT_DYNAMIC
                continue
            off = p["offset"]
            end = off + p["filesz"]
            for pos in range(off, end - 16 + 1, 16):
                d_tag, d_un = struct.unpack_from("<qq", self.data, pos)
                if d_tag == tag:
                    return d_un if d_un >= 0 else None
                if d_tag == 0:
                    break
        return None

    def apply_relocations(self):
        d_rela = self._dyn_val(7)  # DT_RELA
        d_relasz = self._dyn_val(8)  # DT_RELASZ
        d_rel = self._dyn_val(17)  # DT_REL
        d_relsz = self._dyn_val(18)  # DT_RELSZ
        d_jmprel = self._dyn_val(23)  # DT_JMPREL
        d_pltrelsz = self._dyn_val(2)  # DT_PLTRELSZ

        # symbol table (for ABS64 resolving against symbol values)
        sym_values: List[int] = []
        d_symtab = self._dyn_val(6)  # DT_SYMTAB
        d_syment = self._dyn_val(11)  # DT_SYMENT
        if d_symtab is not None:
            off = self.map_va_to_off(d_symtab)
            if off is not None:
                ent = d_syment or 24
                for pos in range(off, len(self.data) - 23, ent):
                    st_name, st_info, st_other, st_shndx, st_value, st_size = \
                        struct.unpack_from("<IBBHQQ", self.data, pos)
                    sym_values.append(st_value)

        def reloc(addr_va: int, sym: int, addend: int, relative: bool, symbol_resolved: bool):
            poff = self.map_va_to_off(addr_va)
            if poff is None or poff + 8 > len(self.data):
                return
            if relative:
                struct.pack_into("<Q", self.data, poff, addend)
            elif symbol_resolved and 0 <= sym < len(sym_values):
                struct.pack_into("<Q", self.data, poff, sym_values[sym] + addend)

        # AArch64
        if self.machine == 183:
            if d_rela is not None and d_relasz:
                roff = self.map_va_to_off(d_rela)
                for pos in range(roff, roff + d_relasz - 23, 24):
                    r_offset, r_info, r_addend = struct.unpack_from("<QQq", self.data, pos)
                    typ = r_info & 0xFFFFFFFF
                    sym = r_info >> 32
                    if typ == 0x401:  # R_AARCH64_ABS64
                        reloc(r_offset, sym, r_addend, False, True)
                    elif typ == 0x403:  # R_AARCH64_RELATIVE
                        reloc(r_offset, sym, r_addend, True, True)
        # x86-64
        elif self.machine == 62:
            if d_rela is not None and d_relasz:
                roff = self.map_va_to_off(d_rela)
                for pos in range(roff, roff + d_relasz - 23, 24):
                    r_offset, r_info, r_addend = struct.unpack_from("<QQq", self.data, pos)
                    typ = r_info & 0xFFFFFFFF
                    sym = r_info >> 32
                    if typ == 1:  # R_X86_64_64
                        reloc(r_offset, sym, r_addend, False, True)
                    elif typ == 8:  # R_X86_64_RELATIVE
                        reloc(r_offset, sym, r_addend, True, True)
            if d_jmprel is not None and d_pltrelsz:
                roff = self.map_va_to_off(d_jmprel)
                for pos in range(roff, roff + d_pltrelsz - 23, 24):
                    r_offset, r_info, r_addend = struct.unpack_from("<QQq", self.data, pos)
                    typ = r_info & 0xFFFFFFFF
                    sym = r_info >> 32
                    if typ in (1, 8):
                        reloc(r_offset, sym, r_addend, typ == 8, True)
            if d_rel is not None and d_relsz:
                roff = self.map_va_to_off(d_rel)
                for pos in range(roff, roff + d_relsz - 15, 16):
                    r_offset, r_info = struct.unpack_from("<QQ", self.data, pos)
                    typ = r_info & 0xFFFFFFFF
                    sym = r_info >> 32
                    if typ == 1:
                        reloc(r_offset, sym, 0, False, True)
                    elif typ == 8:
                        reloc(r_offset, sym, 0, True, True)


class Elf32Binary(ElfBinary):
    def __init__(self, data: bytes):
        Binary.__init__(self, data)
        if len(data) < 52 or data[:4] != b"\x7fELF":
            raise ValueError("not an ELF file")
        if data[4] != 1:
            raise ValueError("only 32-bit ELF supported")
        self.ptr = 4
        e_phoff, e_shoff = struct.unpack_from("<II", data, 28)
        e_machine, = struct.unpack_from("<H", data, 18)
        e_phentsize, e_phnum = struct.unpack_from("<HH", data, 42)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 46)
        self.machine = e_machine
        self.phdrs = []
        for i in range(e_phnum):
            p = struct.unpack_from("<IIIIIIII", data, e_phoff + i * e_phentsize)
            self.phdrs.append({
                "type": p[0], "offset": p[1], "vaddr": p[2], "paddr": p[3],
                "filesz": p[4], "memsz": p[5], "flags": p[6], "align": p[7],
            })
        self.shdrs = []
        if e_shoff and e_shnum:
            for i in range(e_shnum):
                s = struct.unpack_from("<IIIIIIIIII", data, e_shoff + i * e_shentsize)
                self.shdrs.append({
                    "name": s[0], "type": s[1], "flags": s[2], "addr": s[3],
                    "offset": s[4], "size": s[5], "link": s[6], "info": s[7],
                    "addralign": s[8], "entsize": s[9],
                })
        self.section_names = []
        if self.shdrs and e_shstrndx < len(self.shdrs) and self.shdrs[e_shstrndx]["type"] != 0:
            shstr = self.shdrs[e_shstrndx]
            names = data[shstr["offset"]: shstr["offset"] + shstr["size"]]
            for s in self.shdrs:
                end = names.find(b"\x00", s["name"])
                self.section_names.append(names[s["name"]:end].decode("utf-8", "replace") if end != -1 else "")
        else:
            self.section_names = [""] * len(self.shdrs)


class PEBinary(Binary):
    def __init__(self, data: bytes):
        super().__init__(data)
        if data[:2] != b"MZ":
            raise ValueError("not a PE file")
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            raise ValueError("bad PE signature")
        machine, num_sections, _, _, _, opt_size, characteristics = \
            struct.unpack_from("<HHIIIHH", data, e_lfanew + 4)
        opt = e_lfanew + 24
        magic, = struct.unpack_from("<H", data, opt)
        if magic != 0x20B:
            raise ValueError("only PE32+ (64-bit) supported")
        self.image_base = struct.unpack_from("<Q", data, opt + 24)[0]
        self.sections = []
        base = opt + opt_size
        for i in range(num_sections):
            s = struct.unpack_from("<8sIIIIIIHHI", data, base + i * 40)
            self.sections.append({
                "name": s[0].decode("ascii", "replace").rstrip("\x00"),
                "virtual_size": s[1], "virtual_address": s[2],
                "raw_size": s[3], "raw_ptr": s[4],
                "characteristics": s[7],
            })
        # export directory (data directory 0)
        num_dd = struct.unpack_from("<I", data, opt + 108)[0]
        self.export_rva = self.export_size = 0
        if num_dd > 0:
            self.export_rva, self.export_size = struct.unpack_from("<II", data, opt + 112)

    def _va_to_off(self, va: int, use_virtual_size: bool) -> Optional[int]:
        rva = va - self.image_base
        if rva < 0:
            return None
        for s in self.sections:
            end = s["virtual_size"] if use_virtual_size else s["raw_size"]
            if s["virtual_address"] <= rva < s["virtual_address"] + end:
                return s["raw_ptr"] + (rva - s["virtual_address"])
        return None

    def map_va_to_off(self, va: int) -> Optional[int]:
        return self._va_to_off(va, True)

    def map_off_to_va(self, off: int) -> int:
        for s in self.sections:
            if s["raw_ptr"] <= off < s["raw_ptr"] + s["raw_size"]:
                return self.image_base + s["virtual_address"] + (off - s["raw_ptr"])
        return 0

    def get_rva(self, va: int) -> int:
        return va - self.image_base

    def data_scan_ranges(self) -> List[Tuple[int, int]]:
        ranges = []
        for s in self.sections:
            if s["raw_size"] and (s["characteristics"] & 0x20000000) == 0:  # non-exec
                ranges.append((s["raw_ptr"], s["raw_ptr"] + s["raw_size"]))
        return ranges

    def symbol_search(self) -> Tuple[int, int]:
        code_reg = meta_reg = 0
        if not self.export_rva:
            return 0, 0
        exp_off = self.map_va_to_off(self.image_base + self.export_rva)
        if exp_off is None:
            return 0, 0
        n_names, addr_funcs, addr_names, addr_ordinals = \
            struct.unpack_from("<IIII", self.data, exp_off + 24)
        for i in range(n_names):
            name_rva = struct.unpack_from("<I", self.data, exp_off + addr_names + 4 * i)[0]
            name = self.read_cstr(self.image_base + name_rva)
            ordinal = struct.unpack_from("<H", self.data, exp_off + addr_ordinals + 2 * i)[0]
            func_rva = struct.unpack_from("<I", self.data, exp_off + addr_funcs + 4 * ordinal)[0]
            if name == "g_CodeRegistration":
                code_reg = self.image_base + func_rva
            elif name == "g_MetadataRegistration":
                meta_reg = self.image_base + func_rva
        return code_reg, meta_reg


# --------------------------------------------------------------------------
# SectionHelper port (stripped-binary registration search)
# --------------------------------------------------------------------------

class SectionHelper:
    def __init__(self, bin: Binary, version, method_count, type_defs_count, image_count):
        self.bin = bin
        self.version = version
        self.method_count = method_count
        self.type_defs_count = type_defs_count
        self.image_count = image_count
        self._ref_index: Optional[Dict[int, List[int]]] = None
        self._progress = None  # optional callable(frac) for scan progress

    def find_reference(self, addr: int) -> List[int]:
        if self._ref_index is None:
            idx: Dict[int, List[int]] = {}
            ptr = self.bin.ptr
            fmt = "Q" if ptr == 8 else "I"
            total_bytes = sum(end - off for off, end in self.bin.data_scan_ranges())
            done = 0
            for off, end in self.bin.data_scan_ranges():
                for pos in range(off, max(off, end - ptr), ptr):
                    if pos + ptr > end:
                        break
                    v = struct.unpack_from("<" + fmt, self.bin.data, pos)[0]
                    idx.setdefault(v, []).append(self.bin.map_off_to_va(pos))
                if self._progress and total_bytes:
                    done += end - off
                    self._progress(done / total_bytes)
            self._ref_index = idx
        return self._ref_index.get(addr, [])

    def find_code_registration(self) -> int:
        ptr = self.bin.ptr
        fmt = "q" if ptr == 8 else "i"
        feature = b"mscorlib.dll\x00"
        for off, end in self.bin.data_scan_ranges():
            buf = self.bin.data[off:end]
            idx = 0
            while True:
                idx = buf.find(feature, idx)
                if idx == -1:
                    break
                dllva = self.bin.map_off_to_va(off + idx)
                for refva in self.find_reference(dllva):
                    for refva2 in self.find_reference(refva):
                        if self.version >= 27:
                            for i in range(self.image_count - 1, -1, -1):
                                for refva3 in self.find_reference(refva2 - i * ptr):
                                    poff = self.bin.map_va_to_off(refva3 - ptr)
                                    if poff is not None and poff + ptr <= len(self.bin.data):
                                        if struct.unpack_from("<" + fmt, self.bin.data, poff)[0] == self.image_count:
                                            if self.version >= 35:
                                                return refva3 - 16 * ptr
                                            n = 14 if self.version >= 29 else 13
                                            return refva3 - n * ptr
                        else:
                            for i in range(self.image_count):
                                for refva3 in self.find_reference(refva2 - i * ptr):
                                    return refva3 - 13 * ptr
                idx += len(feature)
        return 0

    def find_metadata_registration(self) -> int:
        if self.version < 27:
            return 0
        ptr = self.bin.ptr
        fmt_i = "q" if ptr == 8 else "i"
        fmt_u = "Q" if ptr == 8 else "I"
        # Reference FindMetadataRegistrationV21 scans data sections for the
        # pattern [count, <any>, count, pointer] where both counts equal
        # typeDefinitionsCount (the counts sit at +0x50/+0x60 of the struct,
        # i.e. typeDefinitionsCount and fieldOffsetsCount).
        for off, end in self.bin.data_scan_ranges():
            pos = off
            last = min(end, len(self.bin.data)) - ptr
            while pos < last:
                v = struct.unpack_from("<" + fmt_i, self.bin.data, pos)[0]
                if v == self.type_defs_count:
                    nxt = struct.unpack_from("<" + fmt_i, self.bin.data, pos + 2 * ptr)[0]
                    if nxt == self.type_defs_count:
                        pva = struct.unpack_from("<" + fmt_u, self.bin.data, pos + 3 * ptr)[0]
                        poff = self.bin.map_va_to_off(pva)
                        if poff is not None and poff + ptr * self.type_defs_count <= len(self.bin.data):
                            return self.bin.map_off_to_va(pos - 10 * ptr)
                pos += ptr
        return 0


# --------------------------------------------------------------------------
# Type name rendering (from binary Il2CppType)
# --------------------------------------------------------------------------

TYPE_NAMES = {
    0x01: "System.Void", 0x02: "System.Boolean", 0x03: "System.Char",
    0x04: "System.SByte", 0x05: "System.Byte", 0x06: "System.Int16",
    0x07: "System.UInt16", 0x08: "System.Int32", 0x09: "System.UInt32",
    0x0A: "System.Int64", 0x0B: "System.UInt64", 0x0C: "System.Single",
    0x0D: "System.Double", 0x0E: "System.String", 0x16: "System.TypedReference",
    0x18: "System.IntPtr", 0x19: "System.UIntPtr", 0x1C: "System.Object",
}

# short C# names used by dump.cs (matches Il2CppExecutor.TypeString)
TYPE_SHORT_NAMES = {
    0x01: "void", 0x02: "bool", 0x03: "char",
    0x04: "sbyte", 0x05: "byte", 0x06: "short",
    0x07: "ushort", 0x08: "int", 0x09: "uint",
    0x0A: "long", 0x0B: "ulong", 0x0C: "float",
    0x0D: "double", 0x0E: "string", 0x16: "TypedReference",
    0x18: "IntPtr", 0x19: "UIntPtr", 0x1C: "object",
}


class Il2CppTypeInfo:
    def __init__(self, datapoint: int, bits: int, version: float):
        self.datapoint = datapoint
        self.bits = bits
        self.attrs = bits & 0xffff
        self.code = (bits >> 16) & 0xff
        if version >= 27.2:
            self.num_mods = (bits >> 24) & 0x1f
            self.byref = (bits >> 29) & 1
            self.pinned = (bits >> 30) & 1
            self.valuetype = bits >> 31
        else:
            self.num_mods = (bits >> 24) & 0x3f
            self.byref = (bits >> 30) & 1
            self.pinned = bits >> 31
            self.valuetype = 0
        self.data = datapoint


class Il2CppContext:
    """Binary + metadata glue for resolving types and method pointers."""

    def __init__(self, bin: Binary, meta: Metadata, version: float):
        self.bin = bin
        self.meta = meta
        self.version = version
        self.method_pointers: Dict[str, List[int]] = {}
        self.generic_method_pointers: List[int] = []
        self.invoker_pointers: List[int] = []
        self.reverse_pinvoke_wrappers: List[int] = []
        self.unresolved_virtual_call_pointers: List[int] = []
        self.types: List[Il2CppTypeInfo] = []
        self.generic_insts: List[Dict] = []
        self.method_specs: List[Dict] = []
        self.method_def_method_specs: Dict[int, List[int]] = {}
        self.method_spec_generic_pointers: Dict[int, int] = {}
        self.type_name_cache: Dict[int, str] = {}
        self.field_offsets: List[int] = []          # per-typeDef first-field offset (v<=21)
        self.field_offset_ptrs: List[int] = []      # per-typeDef ptr to int32[] field offsets (v>21)
        self.field_offsets_are_pointers = False
        self.meta_reg_va: int = 0

    # -- low-level reads ---------------------------------------------------
    def read_type(self, va: int) -> Optional[Il2CppTypeInfo]:
        off = self.bin.map_va_to_off(va)
        if off is None or off + self.bin.ptr + 4 > len(self.bin.data):
            return None
        fmt = "QI" if self.bin.ptr == 8 else "II"
        dp, bits = struct.unpack_from("<" + fmt, self.bin.data, off)
        return Il2CppTypeInfo(dp, bits, self.version)

    def read_generic_class(self, va: int) -> Optional[Dict]:
        off = self.bin.map_va_to_off(va)
        size = 4 * self.bin.ptr
        if off is None or off + size > len(self.bin.data):
            return None
        fmt = "QQQQ" if self.bin.ptr == 8 else "IIII"
        typ, class_inst, method_inst, cached = struct.unpack_from("<" + fmt, self.bin.data, off)
        return {"type": typ, "class_inst": class_inst, "method_inst": method_inst}

    def read_generic_inst(self, va: int) -> Optional[Dict]:
        off = self.bin.map_va_to_off(va)
        size = 2 * self.bin.ptr
        if off is None or off + size > len(self.bin.data):
            return None
        fmt = "QQ" if self.bin.ptr == 8 else "II"
        argc, argv = struct.unpack_from("<" + fmt, self.bin.data, off)
        return {"type_argc": argc, "type_argv": argv}

    def read_array_type(self, va: int) -> Optional[Dict]:
        off = self.bin.map_va_to_off(va)
        if off is None or off + self.bin.ptr + 4 > len(self.bin.data):
            return None
        fmt = "QI" if self.bin.ptr == 8 else "II"
        etype, rank = struct.unpack_from("<" + fmt, self.bin.data, off)
        return {"etype": etype, "rank": rank}

    def generic_inst_args(self, inst: Optional[Dict], short_names: bool = False,
                          add_namespace: bool = True) -> List[str]:
        if inst is None:
            return []
        if inst["type_argc"] <= 0 or inst["type_argc"] > 64:
            return []
        argv = self.bin.read_ptr_array(inst["type_argv"], inst["type_argc"])
        out = []
        for p in argv:
            t = self.read_type(p)
            out.append(self.type_name(t, short_names, add_namespace) if t else "<unknown>")
        return out

    def get_generic_inst_params(self, inst: Optional[Dict]) -> str:
        return "<" + ", ".join(self.generic_inst_args(inst, short_names=True, add_namespace=False)) + ">"

    def type_def_name(self, idx: int, short_names: bool = False, add_namespace: bool = True) -> str:
        tds = self.meta.type_defs
        if not (0 <= idx < len(tds)):
            return "<TypeDef:%d>" % idx
        td = tds[idx]
        name = self.meta.read_string(td["nameIndex"])
        # strip generic arity suffix (``...``) like the reference
        backtick = name.find("`")
        if backtick != -1:
            name = name[:backtick]
        declaring = td.get("declaringTypeIndex", -1)
        if declaring >= 0:
            # v38+: declaringTypeIndex is a TypeIndex into the binary Il2CppType
            # array (not a TypeDefinitionIndex); resolve to its type def.
            if declaring < len(self.types):
                dt = self.types[declaring]
                # primitive declaring types (e.g. System.String) render their
                # short name, matching Il2CppExecutor.GetTypeName
                if dt.code in TYPE_SHORT_NAMES:
                    return TYPE_SHORT_NAMES[dt.code] + "." + name
                parent_td = self.get_type_def(dt)
                if parent_td >= 0:
                    return self.type_def_name(parent_td, short_names, add_namespace) + "." + name
            return "<parent:%d>.%s" % (declaring, name)
        ns = self.meta.read_string(td["namespaceIndex"])
        if add_namespace and ns:
            return ns + "." + name
        return name

    def get_type_def(self, t: Optional[Il2CppTypeInfo]) -> int:
        if t is None:
            return -1
        if t.code in (0x11, 0x12, 0x1C):
            return t.data if t.data < (1 << 40) else -1
        if t.code == 0x15:  # genericinst
            gc = self.read_generic_class(t.data)
            if gc:
                base = self.read_type(gc["type"])
                return self.get_type_def(base)
        return -1

    def type_name(self, t: Optional[Il2CppTypeInfo], short_names: bool = False,
                  add_namespace: bool = True) -> str:
        if t is None:
            return "<unknown>"
        code = t.code
        table = TYPE_SHORT_NAMES if short_names else TYPE_NAMES
        if code in table:
            return table[code]
        if code in (0x11, 0x12):  # valuetype / class
            td = self.get_type_def(t)
            if td >= 0:
                return self.type_def_name(td, short_names=short_names, add_namespace=add_namespace)
            return "<class:%d>" % t.data
        if code == 0x1C:  # object
            td = self.get_type_def(t)
            if td >= 0:
                return self.type_def_name(td, short_names=short_names, add_namespace=add_namespace)
            return "object" if short_names else "System.Object"
        if code == 0x0F:  # ptr
            e = self.read_type(t.data)
            return self.type_name(e, short_names, add_namespace) + "*" if e else "<ptr>"
        if code == 0x10:  # byref
            e = self.read_type(t.data)
            return self.type_name(e, short_names, add_namespace) + "&" if e else "<byref>"
        if code == 0x1D:  # szarray
            e = self.read_type(t.data)
            return self.type_name(e, short_names, add_namespace) + "[]" if e else "<array>"
        if code == 0x14:  # array
            at = self.read_array_type(t.data)
            if at:
                e = self.read_type(at["etype"])
                rank = max(at["rank"] - 1, 0)
                return self.type_name(e, short_names, add_namespace) + "[" + "," * rank + "]" if e else "<array>"
            return "<array>"
        if code == 0x15:  # genericinst
            gc = self.read_generic_class(t.data)
            if not gc:
                return "<genericinst>"
            base = self.read_type(gc["type"])
            base_name = self.type_name(base, short_names, add_namespace) if base else "<gen>"
            args = self.generic_inst_args(self.read_generic_inst(gc["class_inst"]), short_names, add_namespace)
            return base_name + "<" + ", ".join(args) + ">"
        if code in (0x13, 0x1E):  # var / mvar
            gps = self.meta.generic_params
            idx = t.data
            if 0 <= idx < len(gps):
                return self.meta.read_string(gps[idx]["nameIndex"]) or "T%d" % gps[idx].get("num", idx)
            return "T?"
        return "<type:0x%02X>" % code

    # -- method pointers ---------------------------------------------------
    def get_method_pointer(self, image_name: str, method_def: Dict) -> int:
        if self.version >= 24.2:
            ptrs = self.method_pointers.get(image_name, [])
            idx = (method_def.get("token", 0) & 0x00FFFFFF) - 1
            if 0 <= idx < len(ptrs):
                return ptrs[idx]
            return 0
        else:
            mi = method_def.get("methodIndex", -1)
            if 0 <= mi < len(self.generic_method_pointers):
                return self.generic_method_pointers[mi]
            return 0

    def method_name(self, method_def: Dict) -> str:
        return self.meta.read_string(method_def.get("nameIndex", -1))

    def field_offset(self, type_index: int, field_index_in_type: int, field_index: int,
                     is_value_type: bool, is_static: bool) -> int:
        """Mirror Il2Cpp.GetFieldOffsetFromIndex (Il2Cpp.cs:275-315)."""
        offset = -1
        if self.field_offsets_are_pointers:
            ptr = self.field_offset_ptrs[type_index] if 0 <= type_index < len(self.field_offset_ptrs) else 0
            if ptr > 0:
                poff = self.bin.map_va_to_off(ptr)
                if poff is not None:
                    off_pos = poff + 4 * field_index_in_type
                    if off_pos + 4 <= len(self.bin.data):
                        offset = struct.unpack_from("<I", self.bin.data, off_pos)[0]
        else:
            if 0 <= field_index < len(self.field_offsets):
                offset = self.field_offsets[field_index]
        if offset is not None and offset > 0:
            if is_value_type and not is_static:
                offset -= 16 if self.bin.ptr == 8 else 8
        return offset if offset is not None else 0


# --------------------------------------------------------------------------
# Main pipeline
# --------------------------------------------------------------------------

def load_binary(path: str) -> Binary:
    with open(path, "rb") as f:
        data = f.read()
    for cls in (Elf64Binary, Elf32Binary, PEBinary):
        try:
            b = cls(data)
            b.apply_relocations()
            return b
        except ValueError:
            pass
    raise ValueError("unsupported binary format (need ELF64, ELF32 or PE32+)")


def auto_plus_init(bin: Binary, meta: Metadata, version, code_reg, meta_reg):
    """Version-correction heuristics from Il2CppDumper.AutoPlusInit."""
    limit = 0x50000
    ptr = bin.ptr
    if code_reg and version >= 24.2:
        code = read_struct(bin.data, bin.map_va_to_off(code_reg), CODE_REG_SPEC, version, ptr)
        if code is None:
            return version, code_reg, meta_reg
        if version == 31:
            if code.get("genericMethodPointersCount", 0) > limit:
                code_reg -= ptr * 2
            else:
                version = 29.0
        if version == 29:
            code = read_struct(bin.data, bin.map_va_to_off(code_reg), CODE_REG_SPEC, version, ptr)
            if code.get("genericMethodPointersCount", 0) > limit:
                version = 29.1
                code_reg -= ptr * 2
        if version == 27:
            code = read_struct(bin.data, bin.map_va_to_off(code_reg), CODE_REG_SPEC, version, ptr)
            if code.get("reversePInvokeWrapperCount", 0) > limit:
                version = 27.1
                code_reg -= ptr
    return version, code_reg, meta_reg


def init(ctx: Il2CppContext, bin: Binary, version, code_reg, meta_reg) -> bool:
    code = bin.read_fields(code_reg, CODE_REG_SPEC)
    meta_reg_fields = bin.read_fields(meta_reg, META_REG_SPEC)
    if code is None or meta_reg_fields is None:
        return False
    ctx.meta_reg_va = meta_reg

    ctx.generic_method_pointers = bin.read_ptr_array(
        code.get("genericMethodPointers", 0), code.get("genericMethodPointersCount", 0))
    ctx.invoker_pointers = bin.read_ptr_array(
        code.get("invokerPointers", 0), code.get("invokerPointersCount", 0))
    if code.get("reversePInvokeWrappers", 0):
        ctx.reverse_pinvoke_wrappers = bin.read_ptr_array(
            code["reversePInvokeWrappers"], code.get("reversePInvokeWrapperCount", 0))
    if code.get("unresolvedVirtualCallPointers", 0):
        ctx.unresolved_virtual_call_pointers = bin.read_ptr_array(
            code["unresolvedVirtualCallPointers"], code.get("unresolvedVirtualCallCount", 0))

    # types: array of pointers to Il2CppType structs
    ptypes = bin.read_ptr_array(meta_reg_fields.get("types", 0), meta_reg_fields.get("typesCount", 0))
    ctx.types = [t for t in (ctx.read_type(p) for p in ptypes) if t is not None]

    # field offsets (v>21: array of pointers to int32[] per typeDef)
    fo_ptr = meta_reg_fields.get("fieldOffsets", 0)
    fo_count = meta_reg_fields.get("fieldOffsetsCount", 0)
    if version > 21 and fo_ptr and fo_count > 0:
        ptrs = bin.read_ptr_array(fo_ptr, fo_count)
        ctx.field_offsets_are_pointers = True
        ctx.field_offset_ptrs = ptrs
    elif fo_ptr and fo_count > 0:
        ctx.field_offsets = bin.read_ptr_array(fo_ptr, fo_count)

    # codeGenModules (v24.2+) -> per-image method pointers
    if version >= 24.2:
        pmodules = bin.read_ptr_array(code.get("codeGenModules", 0), code.get("codeGenModulesCount", 0))
        for pm in pmodules:
            m = bin.read_fields(pm, CODE_GEN_MODULE_SPEC)
            if m is None:
                continue
            name = bin.read_cstr(m.get("moduleName", 0))
            mpc = m.get("methodPointerCount", 0)
            ptrs = bin.read_ptr_array(m.get("methodPointers", 0), mpc)
            if name:
                ctx.method_pointers[name] = ptrs

    # generic insts
    pgis = bin.read_ptr_array(meta_reg_fields.get("genericInsts", 0),
                              meta_reg_fields.get("genericInstsCount", 0))
    ctx.generic_insts = [gi for gi in (ctx.read_generic_inst(p) for p in pgis)
                         if gi is not None and 0 < gi["type_argc"] <= 64]

    # method specs
    spec_va = meta_reg_fields.get("methodSpecs", 0)
    spec_count = meta_reg_fields.get("methodSpecsCount", 0)
    for i in range(spec_count):
        off = bin.map_va_to_off(spec_va + 12 * i)
        if off is None or off + 12 > len(bin.data):
            break
        mdi, cii, mii = struct.unpack_from("<iii", bin.data, off)
        ctx.method_specs.append({"methodDefinitionIndex": mdi,
                                 "classIndexIndex": cii, "methodIndexIndex": mii})

    # generic method table -> methodSpec generic pointers
    gmt = meta_reg_fields.get("genericMethodTable", 0)
    gmtc = meta_reg_fields.get("genericMethodTableCount", 0)
    ent = 16 if version >= 27.1 else 12
    for i in range(gmtc):
        off = bin.map_va_to_off(gmt + ent * i)
        if off is None or off + ent > len(bin.data):
            break
        vals = struct.unpack_from("<iii", bin.data, off)[:3]  # gmi, methodIdx, invokerIdx
        gmi = vals[0]
        if not (0 <= gmi < len(ctx.method_specs)):
            continue
        spec = ctx.method_specs[gmi]
        mdi = spec["methodDefinitionIndex"]
        ctx.method_def_method_specs.setdefault(mdi, []).append(gmi)
        mp = ctx.generic_method_pointers[vals[1]] if vals[1] < len(ctx.generic_method_pointers) else 0
        ctx.method_spec_generic_pointers[gmi] = mp
    return True


def build_script(ctx: Il2CppContext, bin: Binary, meta: Metadata, version) -> Dict:
    json_out = {
        "ScriptMethod": [],
        "ScriptString": [],
        "ScriptMetadata": [],
        "ScriptMetadataMethod": [],
        "Addresses": [],
    }

    # image name per type def
    image_names = {}
    for img in meta.images:
        iname = meta.read_string(img.get("nameIndex", -1))
        ts, tc = img.get("typeStart", 0), img.get("typeCount", 0)
        for t in range(ts, min(ts + tc, len(meta.type_defs))):
            image_names[t] = iname

    # methods
    seen_pointers = set()
    for t_idx, td in enumerate(meta.type_defs):
        iname = image_names.get(t_idx, "")
        type_name = ctx.type_def_name(t_idx)
        mstart, mcount = td.get("methodStart", 0), td.get("method_count", 0)
        for i in range(mstart, min(mstart + mcount, len(meta.methods))):
            md = meta.methods[i]
            mp = ctx.get_method_pointer(iname, md) if iname else 0
            if mp > 0:
                seen_pointers.add(mp)
                mname = ctx.method_name(md)
                json_out["ScriptMethod"].append({
                    "Address": bin.get_rva(mp),
                    "Name": type_name + "$$" + mname,
                    "Signature": "",
                    "TypeSignature": "",
                })
            # generic instantiations
            for gmi in ctx.method_def_method_specs.get(i, []):
                gmp = ctx.method_spec_generic_pointers.get(gmi, 0)
                if gmp > 0:
                    seen_pointers.add(gmp)
                    spec = ctx.method_specs[gmi]
                    json_out["ScriptMethod"].append({
                        "Address": bin.get_rva(gmp),
                        "Name": type_name + "$$" + ctx.method_name(md) + "<...>",
                        "Signature": "",
                        "TypeSignature": "",
                    })

    # Addresses
    ordered = []
    for ptrs in ctx.method_pointers.values():
        ordered.extend(ptrs)
    ordered.extend(ctx.generic_method_pointers)
    ordered.extend(ctx.invoker_pointers)
    ordered.extend(ctx.reverse_pinvoke_wrappers)
    ordered.extend(ctx.unresolved_virtual_call_pointers)
    ordered = sorted(set(ordered) - {0})
    json_out["Addresses"] = [bin.get_rva(p) for p in ordered]

    # metadata usage scan (v27+)
    if version >= 27:
        scan_metadata_usage(ctx, bin, meta, json_out)

    return json_out


# --------------------------------------------------------------------------
# dump.cs generation (mirrors Il2CppDumper's Il2CppDecompiler output)
# --------------------------------------------------------------------------

# TypeAttributes (ECMA-335)
TA_VISIBILITY_MASK = 0x07
TA_NOT_PUBLIC, TA_PUBLIC, TA_NESTED_PUBLIC = 0x0, 0x1, 0x2
TA_NESTED_PRIVATE, TA_NESTED_FAMILY = 0x3, 0x4
TA_NESTED_ASSEMBLY, TA_NESTED_FAM_AND_ASSEM = 0x5, 0x6
TA_NESTED_FAM_OR_ASSEM = 0x7
TA_INTERFACE = 0x20
TA_ABSTRACT = 0x80
TA_SEALED = 0x100
TA_SERIALIZABLE = 0x2000
TA_CLASS = 0x100000

# FieldAttributes
FA_ACCESS_MASK = 0x0007
FA_PRIVATE, FA_FAM_AND_ASSEM, FA_ASSEMBLY = 0x0001, 0x0002, 0x0003
FA_FAMILY, FA_FAM_OR_ASSEM, FA_PUBLIC = 0x0004, 0x0005, 0x0006
FA_STATIC, FA_INIT_ONLY, FA_LITERAL = 0x0010, 0x0020, 0x0040

# MethodAttributes
MA_ACCESS_MASK = 0x0007
MA_PRIVATE, MA_FAM_AND_ASSEM, MA_ASSEM = 0x0001, 0x0002, 0x0003
MA_FAMILY, MA_FAM_OR_ASSEM, MA_PUBLIC = 0x0004, 0x0005, 0x0006
MA_STATIC, MA_FINAL, MA_VIRTUAL = 0x0010, 0x0020, 0x0040
MA_VTABLE_LAYOUT_MASK, MA_REUSE_SLOT, MA_NEW_SLOT = 0x0100, 0x0000, 0x0100
MA_ABSTRACT, MA_PINVOKE_IMPL = 0x0400, 0x2000

# ParamAttributes
PA_IN, PA_OUT = 0x0001, 0x0002


def read_compressed_uint(data: bytes, pos: int) -> Tuple[int, int]:
    """Read a compressed uint32 (BinaryReaderExtensions.ReadCompressedUInt32).
    Returns (value, new_pos)."""
    b0 = data[pos]
    pos += 1
    if (b0 & 0x80) == 0:
        return b0, pos
    if (b0 & 0xC0) == 0x80:
        val = (b0 & ~0x80) << 8 | data[pos]
        return val, pos + 1
    if (b0 & 0xE0) == 0xC0:
        val = (b0 & ~0xC0) << 24 | data[pos] << 16 | data[pos + 1] << 8 | data[pos + 2]
        return val, pos + 3
    if b0 == 0xF0:
        return int.from_bytes(data[pos:pos + 4], "little"), pos + 4
    if b0 == 0xFE:
        return 0xFFFFFFFE, pos
    if b0 == 0xFF:
        return 0xFFFFFFFF, pos
    raise ValueError("invalid compressed integer format")


def read_compressed_int(data: bytes, pos: int) -> Tuple[int, int]:
    encoded, pos = read_compressed_uint(data, pos)
    if encoded == 0xFFFFFFFF:
        return -(1 << 31), pos
    neg = (encoded & 1) != 0
    encoded >>= 1
    return (-(int(encoded) + 1) if neg else int(encoded)), pos


class BlobValue:
    def __init__(self, value, code: int = 0):
        self.value = value
        self.code = code


def decode_constant(data: bytes, pos: int, code: int, version: float) -> Tuple[Optional[BlobValue], int]:
    """Decode a default value from fieldAndParameterDefaultValueData at pos.
    Returns (BlobValue|None, new_pos), mirroring GetConstantValueFromBlob."""
    if code == 0x02:  # bool
        return BlobValue(bool(data[pos])), pos + 1
    if code == 0x05:  # u1
        return BlobValue(data[pos]), pos + 1
    if code == 0x04:  # i1
        return BlobValue(struct.unpack_from("<b", data, pos)[0]), pos + 1
    if code == 0x03:  # char
        return BlobValue(struct.unpack_from("<H", data, pos)[0], code), pos + 2
    if code == 0x07:  # u2
        return BlobValue(struct.unpack_from("<H", data, pos)[0]), pos + 2
    if code == 0x06:  # i2
        return BlobValue(struct.unpack_from("<h", data, pos)[0]), pos + 2
    if code == 0x09:  # u4
        if version >= 29:
            val, pos = read_compressed_uint(data, pos)
        else:
            val = struct.unpack_from("<I", data, pos)[0]; pos += 4
        return BlobValue(val), pos
    if code == 0x08:  # i4
        if version >= 29:
            val, pos = read_compressed_int(data, pos)
        else:
            val = struct.unpack_from("<i", data, pos)[0]; pos += 4
        return BlobValue(val), pos
    if code == 0x0B:  # u8
        return BlobValue(struct.unpack_from("<Q", data, pos)[0]), pos + 8
    if code == 0x0A:  # i8
        return BlobValue(struct.unpack_from("<q", data, pos)[0]), pos + 8
    if code == 0x0C:  # r4
        return BlobValue(struct.unpack_from("<f", data, pos)[0], code), pos + 4
    if code == 0x0D:  # r8
        return BlobValue(struct.unpack_from("<d", data, pos)[0], code), pos + 8
    if code == 0x0E:  # string
        if version >= 29:
            length, pos = read_compressed_int(data, pos)
            if length == -1:
                return BlobValue(None), pos
            s = data[pos:pos + length].decode("utf-8", "replace")
            return BlobValue(s), pos + length
        else:
            length = struct.unpack_from("<i", data, pos)[0]; pos += 4
            if length < 0:
                return BlobValue(None), pos
            s = data[pos:pos + length].decode("utf-8", "replace")
            return BlobValue(s), pos + length
    return None, pos


def _type_visibility(flags: int) -> str:
    v = flags & TA_VISIBILITY_MASK
    if v in (TA_PUBLIC, TA_NESTED_PUBLIC):
        return "public "
    if v in (TA_NOT_PUBLIC, TA_NESTED_FAM_AND_ASSEM, TA_NESTED_ASSEMBLY):
        return "internal "
    if v == TA_NESTED_PRIVATE:
        return "private "
    if v == TA_NESTED_FAMILY:
        return "protected "
    if v == TA_NESTED_FAM_OR_ASSEM:
        return "protected internal "
    return ""


def _method_access(flags: int) -> str:
    a = flags & MA_ACCESS_MASK
    if a == MA_PRIVATE:
        return "private "
    if a == MA_PUBLIC:
        return "public "
    if a == MA_FAMILY:
        return "protected "
    if a in (MA_ASSEM, MA_FAM_AND_ASSEM):
        return "internal "
    if a == MA_FAM_OR_ASSEM:
        return "protected internal "
    return ""


def _method_modifiers(flags: int) -> str:
    s = _method_access(flags)
    if flags & MA_STATIC:
        s += "static "
    if flags & MA_ABSTRACT:
        s += "abstract "
        if (flags & MA_VTABLE_LAYOUT_MASK) == MA_REUSE_SLOT:
            s += "override "
    elif flags & MA_FINAL:
        if (flags & MA_VTABLE_LAYOUT_MASK) == MA_REUSE_SLOT:
            s += "sealed override "
    elif flags & MA_VIRTUAL:
        if (flags & MA_VTABLE_LAYOUT_MASK) == MA_NEW_SLOT:
            s += "virtual "
        else:
            s += "override "
    if flags & MA_PINVOKE_IMPL:
        s += "extern "
    return s


def _field_modifiers(attrs: int) -> str:
    a = attrs & FA_ACCESS_MASK
    if a == FA_PRIVATE:
        s = "private "
    elif a == FA_PUBLIC:
        s = "public "
    elif a == FA_FAMILY:
        s = "protected "
    elif a in (FA_ASSEMBLY, FA_FAM_AND_ASSEM):
        s = "internal "
    elif a == FA_FAM_OR_ASSEM:
        s = "protected internal "
    else:
        s = ""
    if attrs & FA_LITERAL:
        return s + "const "
    if attrs & FA_STATIC:
        s += "static "
    if attrs & FA_INIT_ONLY:
        s += "readonly "
    return s


class DumpCsGenerator:
    """Produces dump.cs mirroring Il2CppDumper's Il2CppDecompiler output."""

    def __init__(self, ctx: "Il2CppContext", bin: Binary, meta: Metadata, version: float):
        self.ctx = ctx
        self.bin = bin
        self.meta = meta
        self.version = version

    def generate(self, config: Optional[Dict] = None) -> str:
        cfg = {
            "DumpMethod": True, "DumpField": True, "DumpProperty": True,
            "DumpAttribute": False, "DumpFieldOffset": True, "DumpMethodOffset": True,
            "DumpTypeDefIndex": True,
        }
        if config:
            cfg.update(config)
        L: List[str] = []
        for image_index, img in enumerate(self.meta.images):
            iname = self.meta.read_string(img.get("nameIndex", -1))
            L.append("// Image %d: %s - %d" % (image_index, iname, img.get("typeStart", 0)))
        for img in self.meta.images:
            image_name = self.meta.read_string(img.get("nameIndex", -1))
            type_start = img.get("typeStart", 0)
            type_count = img.get("typeCount", 0)
            for td_idx in range(type_start, min(type_start + type_count, len(self.meta.type_defs))):
                try:
                    L.extend(self._dump_type(td_idx, image_name, cfg))
                except Exception:
                    L.append("}")
        return "\n".join(L) + "\n"

    def _dump_type(self, td_idx: int, image_name: str, cfg: Dict) -> List[str]:
        meta = self.meta
        ctx = self.ctx
        td = meta.type_defs[td_idx]
        flags = td.get("flags", 0)
        is_value_type = (td.get("bitfield", 0) & 0x1) == 1
        is_enum = ((td.get("bitfield", 0) >> 1) & 0x1) == 1
        ns = meta.read_string(td.get("namespaceIndex", -1))

        L: List[str] = []
        L.append("")
        L.append("// Namespace: %s" % ns)

        # base type / interfaces
        extends = []
        parent = td.get("parentIndex", -1)
        if parent >= 0 and 0 <= parent < len(ctx.types):
            parent_name = ctx.type_name(ctx.types[parent], short_names=True, add_namespace=False)
            if not is_value_type and not is_enum and parent_name != "object":
                extends.append(parent_name)
        # NOTE: mirrors Il2CppDecompiler.cs which reads the interfaces section as
        # Il2CppInterfaceOffsetPair (TypeIndex + int32 offset), so the effective
        # flat TypeIndex index for pair i is i*(T+4)//T, and it uses the global
        # index i (not interfacesStart+i) -- a reference quirk we keep for
        # byte-identical output.
        if td.get("interfaces_count", 0) > 0:
            t_size = self.meta._idx_sizes.get("T", 4)
            pair_stride = (t_size + 4) // t_size
            for i in range(td["interfaces_count"]):
                fi = pair_stride * i
                if 0 <= fi < len(meta.interfaces):
                    ti = meta.interfaces[fi]
                    if 0 <= ti < len(ctx.types):
                        iname = ctx.type_name(ctx.types[ti], short_names=True, add_namespace=False)
                        if iname != "object":
                            extends.append(iname)

        visibility = _type_visibility(flags)
        if (flags & TA_ABSTRACT) and (flags & TA_SEALED):
            kind_mod = "static "
        elif (flags & TA_INTERFACE) == 0 and (flags & TA_ABSTRACT):
            kind_mod = "abstract "
        elif not is_value_type and not is_enum and (flags & TA_SEALED):
            kind_mod = "sealed "
        else:
            kind_mod = ""
        if flags & TA_INTERFACE:
            kind = "interface"
        elif is_enum:
            kind = "enum"
        elif is_value_type:
            kind = "struct"
        else:
            kind = "class"

        type_name = ctx.type_def_name(td_idx, short_names=True, add_namespace=False)
        if td.get("genericContainerIndex", -1) >= 0:
            type_name += self._generic_container_params(td["genericContainerIndex"])
        header = "%s%s%s %s" % (visibility, kind_mod, kind, type_name)
        if extends:
            header += " : " + ", ".join(extends)
        if cfg["DumpTypeDefIndex"]:
            header += " // TypeDefIndex: %d" % td_idx
        has_content = (cfg["DumpField"] and td.get("field_count", 0) > 0) or \
                      (cfg["DumpProperty"] and td.get("property_count", 0) > 0) or \
                      (cfg["DumpMethod"] and td.get("method_count", 0) > 0)
        if not has_content:
            L.append(header)
            L.append("{}")
            return L
        header += "\n{"
        L.append(header)

        # fields
        fstart = td.get("fieldStart", 0)
        fcount = td.get("field_count", 0)
        if cfg["DumpField"] and fcount > 0:
            L.append("\t// Fields")
            for fi in range(fstart, min(fstart + fcount, len(meta.fields))):
                fd = meta.fields[fi]
                ft = ctx.types[fd.get("typeIndex", -1)] if 0 <= fd.get("typeIndex", -1) < len(ctx.types) else None
                ftype_name = ctx.type_name(ft, short_names=True, add_namespace=False) if ft else "<unknown>"
                fname = meta.read_string(fd.get("nameIndex", -1))
                attrs = ft.attrs if ft else 0
                is_const = (attrs & FA_LITERAL) != 0
                is_static = (attrs & FA_STATIC) != 0
                line = "\t%s%s %s" % (_field_modifiers(attrs), ftype_name, fname)
                # default value: decoded literal for scalars, or a metadata-offset
                # comment for array/blob/unknown types (matches reference; the
                # metadata offset is the default-value dataIndex).
                dv = self._field_default_value(fi)
                if dv is not None and dv[0] is None and dv[1] is not None:
                    line += " /*Metadata offset 0x%X*/" % dv[1]
                elif dv is not None and dv[0] is not None:
                    line += " = %s" % self._render_value(dv[0])
                if cfg["DumpFieldOffset"] and not is_const:
                    off = ctx.field_offset(td_idx, fi - fstart, fi, is_value_type, is_static)
                    line += "; // 0x%X" % off
                else:
                    line += ";"
                L.append(line)

        # properties
        pstart = td.get("propertyStart", 0)
        pcount = td.get("property_count", 0)
        if cfg["DumpProperty"] and pcount > 0:
            L.append("\t// Properties")
            for pi in range(pstart, min(pstart + pcount, len(meta.properties))):
                pd = meta.properties[pi]
                line = "\t"
                if pd.get("get", -1) >= 0:
                    m_idx = td.get("methodStart", 0) + pd["get"]
                    if 0 <= m_idx < len(meta.methods):
                        md = meta.methods[m_idx]
                        line += _method_modifiers(md.get("flags", 0))
                        rt = ctx.types[md.get("returnType", -1)] if 0 <= md.get("returnType", -1) < len(ctx.types) else None
                        line += ctx.type_name(rt, short_names=True, add_namespace=False) if rt else "<unknown>"
                        line += " " + meta.read_string(pd.get("nameIndex", -1)) + " { "
                elif pd.get("set", -1) >= 0:
                    m_idx = td.get("methodStart", 0) + pd["set"]
                    if 0 <= m_idx < len(meta.methods):
                        md = meta.methods[m_idx]
                        line += _method_modifiers(md.get("flags", 0))
                        pstart2 = md.get("parameterStart", 0)
                        if pstart2 < len(meta.params):
                            pt = ctx.types[meta.params[pstart2].get("typeIndex", -1)] if 0 <= meta.params[pstart2].get("typeIndex", -1) < len(ctx.types) else None
                            line += ctx.type_name(pt, short_names=True, add_namespace=False) if pt else "<unknown>"
                            line += " " + meta.read_string(pd.get("nameIndex", -1)) + " { "
                if pd.get("get", -1) >= 0:
                    line += "get; "
                if pd.get("set", -1) >= 0:
                    line += "set; "
                line += "}"
                L.append(line)

        # methods
        mstart = td.get("methodStart", 0)
        mcount = td.get("method_count", 0)
        if cfg["DumpMethod"] and mcount > 0:
            L.append("\t// Methods")
            for mi in range(mstart, min(mstart + mcount, len(meta.methods))):
                md = meta.methods[mi]
                is_abstract = (md.get("flags", 0) & MA_ABSTRACT) != 0
                L.append("")
                if cfg["DumpMethodOffset"]:
                    mp = ctx.get_method_pointer(image_name, md)
                    if not is_abstract and mp > 0:
                        rva = self.bin.get_rva(mp)
                        off = self.bin.map_va_to_off(mp) or 0
                        line = "\t// RVA: 0x%X Offset: 0x%X VA: 0x%X" % (rva, off, mp)
                        slot = md.get("slot", -1)
                        if slot != 0xFFFF:
                            line += " Slot: %d" % slot
                    else:
                        line = "\t// RVA: -1 Offset: -1"
                    L.append(line)
                mods = _method_modifiers(md.get("flags", 0))
                mname = meta.read_string(md.get("nameIndex", -1))
                gci = md.get("genericContainerIndex", -1)
                if gci >= 0:
                    mname += self._generic_container_params(gci)
                rt = ctx.types[md.get("returnType", -1)] if 0 <= md.get("returnType", -1) < len(ctx.types) else None
                ret_name = ctx.type_name(rt, short_names=True, add_namespace=False) if rt else "<unknown>"
                if rt and rt.byref == 1:
                    ret_name = "ref " + ret_name
                params = self._method_params(md)
                L.append("\t%s%s %s(%s)%s" % (mods, ret_name, mname, ", ".join(params),
                                              "; " if is_abstract else " { }"))
                # GenericInstMethod block (mirrors Il2CppDecompiler)
                method_specs = ctx.method_def_method_specs.get(mi, [])
                if method_specs:
                    L.append("\t/* GenericInstMethod :")
                    groups = {}
                    for gmi in method_specs:
                        gmp = ctx.method_spec_generic_pointers.get(gmi, 0)
                        groups.setdefault(gmp, []).append(gmi)
                    for gmp, gm_specs in groups.items():
                        L.append("\t|")
                        if gmp > 0:
                            grva = self.bin.get_rva(gmp)
                            goff = self.bin.map_va_to_off(gmp) or 0
                            L.append("\t|-RVA: 0x%X Offset: 0x%X VA: 0x%X" % (grva, goff, gmp))
                        else:
                            L.append("\t|-RVA: -1 Offset: -1")
                        for gmi in gm_specs:
                            spec = ctx.method_specs[gmi]
                            L.append("\t|-" + self._method_spec_name(spec))
                    L.append("\t*/")
        L.append("}")
        return L

    def _method_spec_name(self, spec: Dict) -> str:
        meta = self.meta
        ctx = self.ctx
        mdi = spec.get("methodDefinitionIndex", -1)
        md = meta.methods[mdi] if 0 <= mdi < len(meta.methods) else None
        if md is None:
            return "?"
        td_idx = md.get("declaringType", -1)
        td = meta.type_defs[td_idx] if 0 <= td_idx < len(meta.type_defs) else None
        type_name = ctx.type_def_name(td_idx, short_names=True, add_namespace=False) if td else "?"
        if spec.get("classIndexIndex", -1) >= 0:
            cii = spec["classIndexIndex"]
            if 0 <= cii < len(ctx.generic_insts):
                type_name += ctx.get_generic_inst_params(ctx.generic_insts[cii])
        method_name = meta.read_string(md.get("nameIndex", -1))
        if spec.get("methodIndexIndex", -1) >= 0:
            mii = spec["methodIndexIndex"]
            if 0 <= mii < len(ctx.generic_insts):
                method_name += ctx.get_generic_inst_params(ctx.generic_insts[mii])
        return type_name + "." + method_name

    def _generic_container_params(self, gci: int) -> str:
        gps = self.meta.generic_params
        out = []
        for gp in gps:
            if gp.get("ownerIndex", -1) == gci:
                out.append(self.meta.read_string(gp.get("nameIndex", -1)))
        return "<" + ", ".join(out) + ">"

    def _method_params(self, md: Dict) -> List[str]:
        meta = self.meta
        ctx = self.ctx
        pstart = md.get("parameterStart", 0)
        pcount = md.get("parameterCount", 0)
        out = []
        for j in range(pcount):
            idx = pstart + j
            if not (0 <= idx < len(meta.params)):
                out.append("? ?")
                continue
            pd = meta.params[idx]
            pname = meta.read_string(pd.get("nameIndex", -1))
            pt = ctx.types[pd.get("typeIndex", -1)] if 0 <= pd.get("typeIndex", -1) < len(ctx.types) else None
            ptype_name = ctx.type_name(pt, short_names=True, add_namespace=False) if pt else "<unknown>"
            prefix = ""
            if pt and pt.byref == 1:
                if (pt.attrs & PA_OUT) and not (pt.attrs & PA_IN):
                    prefix = "out "
                elif not (pt.attrs & PA_OUT) and (pt.attrs & PA_IN):
                    prefix = "in "
                else:
                    prefix = "ref "
            else:
                if pt and (pt.attrs & PA_IN):
                    prefix = "[In] "
                if pt and (pt.attrs & PA_OUT):
                    prefix += "[Out] "
            p_str = "%s%s %s" % (prefix, ptype_name, pname)
            out.append(p_str)
        return out

    def _field_default_value(self, field_index: int):
        """Return (BlobValue|None, metadata_offset|None). When the type is a
        blob/array default the value can't be decoded into a literal, so the
        reference emits the raw dataIndex as /*Metadata offset 0x..*/."""
        meta = self.meta
        for fd in meta.field_defaults:
            if fd.get("fieldIndex", -1) == field_index:
                data_index = fd.get("dataIndex", -1)
                if data_index < 0:
                    return None, None
                base = meta._sec_off("fieldAndParameterDefaultValueData")
                size = meta._sec_size("fieldAndParameterDefaultValueData")
                if base <= 0 or data_index >= size:
                    return None, None
                ti = fd.get("typeIndex", -1)
                code = -1
                if 0 <= ti < len(self.ctx.types):
                    code = self.ctx.types[ti].code
                if code in (0x1D, 0x14, 0x15, 0x11, 0x12, 0x1C, -1):  # blob/array/class/object/unknown
                    return None, base + data_index
                val, _ = decode_constant(meta.data, base + data_index, code, self.version)
                return val, None
        return None, None

    def _param_default_value(self, param_index: int):
        meta = self.meta
        for pd in meta.param_defaults:
            if pd.get("parameterIndex", -1) == param_index:
                data_index = pd.get("dataIndex", -1)
                if data_index < 0:
                    return None, None
                base = meta._sec_off("fieldAndParameterDefaultValueData")
                size = meta._sec_size("fieldAndParameterDefaultValueData")
                if base <= 0 or data_index >= size:
                    return None, None
                ti = pd.get("typeIndex", -1)
                code = -1
                if 0 <= ti < len(self.ctx.types):
                    code = self.ctx.types[ti].code
                if code in (0x1D, 0x14, 0x15, -1):
                    return None, data_index
                val, _ = decode_constant(meta.data, base + data_index, code, self.version)
                return val, None
        return None, None

    def _render_value(self, bv: Optional[BlobValue]) -> str:
        if bv is None:
            return "null"
        v = bv.value
        if isinstance(v, str):
            return '"%s"' % self._escape_string(v)
        if isinstance(v, bool):
            return "True" if v else "False"
        if isinstance(v, float):
            import math
            if math.isnan(v):
                return "NaN"
            if math.isinf(v):
                return "∞" if v > 0 else "-∞"
            if bv.code == 0x0D:  # double (r8): full precision
                s = repr(v)
                if s.endswith(".0"):
                    return s[:-2]
            else:  # float (r4): shortest float32 round-trip
                f32 = struct.unpack("<f", struct.pack("<f", v))[0]
                # shortest representation between decimal and scientific that
                # round-trips to this float32 (matches C# float ToString)
                best = None
                for prec in range(1, 10):
                    s = "%.*g" % (prec, f32)
                    try:
                        if struct.unpack("<f", struct.pack("<f", float(s)))[0] == f32:
                            best = s
                            break
                    except OverflowError:
                        continue
                # prefer decimal form if it round-trips and C# would use it
                # (C# float ToString uses decimal for |v| < 1e8, scientific above)
                if f32.is_integer() and abs(f32) <= 1e8:
                    s = str(int(f32))
                else:
                    s = best
            # C# uses uppercase E for exponents
            s = s.replace("e", "E")
            return s
        if isinstance(v, int):
            if bv.code == 0x03:  # char
                return "'\\x%x'" % v
            return str(v)
        if isinstance(v, bytes):
            return '"\\x%s"' % v.hex()
        return str(v)

    def _escape_string(self, s: str) -> str:
        table = {
            "'": "\\'", '"': '\\"', "\\": "\\\\", "\0": "\\0", "\a": "\\a",
            "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t",
            "\v": "\\v", "\u0085": "\\u0085", "\u2028": "\\u2028", "\u2029": "\\u2029",
        }
        out = []
        for c in s:
            out.append(table.get(c, c))
        return "".join(out)


def generate_dump_cs(ctx: Il2CppContext, bin: Binary, meta: Metadata, version: float,
                     config: Optional[Dict] = None) -> str:
    gen = DumpCsGenerator(ctx, bin, meta, version)
    return gen.generate(config)


def scan_metadata_usage(ctx: Il2CppContext, bin: Binary, meta: Metadata, json_out: Dict):
    def add_type_info(idx, slot_rva):
        if 0 <= idx < len(ctx.types):
            t = ctx.types[idx]
            json_out["ScriptMetadata"].append({
                "Address": slot_rva,
                "Name": ctx.type_name(t) + "_TypeInfo",
                "Signature": "",
            })

    def add_type_var(idx, slot_rva):
        if 0 <= idx < len(ctx.types):
            t = ctx.types[idx]
            json_out["ScriptMetadata"].append({
                "Address": slot_rva,
                "Name": ctx.type_name(t) + "_var",
                "Signature": "",
            })

    def add_method_def(idx, slot_rva):
        if not (0 <= idx < len(meta.methods)):
            return
        md = meta.methods[idx]
        td = md.get("declaringType", -1)
        type_name = ctx.type_def_name(td) if 0 <= td < len(meta.type_defs) else "?"
        iname = ""
        for img in meta.images:
            ts, tc = img.get("typeStart", 0), img.get("typeCount", 0)
            if ts <= td < ts + tc:
                iname = meta.read_string(img.get("nameIndex", -1))
                break
        mptr = ctx.get_method_pointer(iname, md) if iname else 0
        entry = {"Address": slot_rva,
                 "Name": "Method$" + type_name + "." + ctx.method_name(md) + "()"}
        if mptr > 0:
            entry["MethodAddress"] = bin.get_rva(mptr)
        json_out["ScriptMetadataMethod"].append(entry)

    def add_field_info(idx, slot_rva):
        if not (0 <= idx < len(meta.fields_refs)):
            return
        fr = meta.fields_refs[idx]
        if 0 <= fr["typeIndex"] < len(ctx.types):
            t = ctx.types[fr["typeIndex"]]
            td_idx = ctx.get_type_def(t)
            if 0 <= td_idx < len(meta.type_defs):
                td = meta.type_defs[td_idx]
                fstart = td.get("fieldStart", 0)
                fi = fstart + fr.get("fieldIndex", 0)
                if 0 <= fi < len(meta.fields):
                    fname = meta.read_string(meta.fields[fi].get("nameIndex", -1))
                    json_out["ScriptMetadata"].append({
                        "Address": slot_rva,
                        "Name": "Field$" + ctx.type_name(t) + "." + fname,
                        "Signature": "",
                    })

    def add_string_literal(idx, slot_rva):
        if 0 <= idx < len(meta.string_literals):
            json_out["ScriptString"].append({
                "Address": slot_rva,
                "Value": meta.string_literals[idx],
            })

    def add_method_ref(idx, slot_rva):
        if 0 <= idx < len(ctx.method_specs):
            spec = ctx.method_specs[idx]
            gmp = ctx.method_spec_generic_pointers.get(idx, 0)
            entry = {"Address": slot_rva, "Name": "Method$<spec>.<...>()"}
            if gmp > 0:
                entry["MethodAddress"] = bin.get_rva(gmp)
            json_out["ScriptMetadataMethod"].append(entry)

    handlers = {1: add_type_info, 2: add_type_var, 3: add_method_def,
                4: add_field_info, 5: add_string_literal, 6: add_method_ref}

    for off, end in bin.data_scan_ranges():
        last = min(end, len(bin.data)) - bin.ptr
        pos = off
        while pos <= last:
            fmt = "Q" if bin.ptr == 8 else "I"
            v = struct.unpack_from("<" + fmt, bin.data, pos)[0]
            if v < 0xFFFFFFFF and (v & 1) == 1:
                usage = (v >> 29) & 0x7
                decoded = (v & 0x1FFFFFFE) >> 1
                if 1 <= usage <= 6 and v == ((usage << 29) | (decoded << 1)) + 1:
                    va = bin.map_off_to_va(pos)
                    slot_rva = bin.get_rva(va)
                    if slot_rva > 0:
                        handlers[usage](decoded, slot_rva)
            pos += bin.ptr


# --------------------------------------------------------------------------
# Game auto-discovery (APK / AAB / XAPK / extracted directory)
# --------------------------------------------------------------------------

BINARY_NAMES = ("libil2cpp.so", "GameAssembly.dll")
METADATA_NAMES = ("global-metadata.dat", "metadata.dat")


def discover_game(game_path: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Locate (binary_path, metadata_path, cleanup_dir) inside a game source.

    game_path may be:
      - a directory: walk it looking for a libil2cpp.so/GameAssembly.dll and a
        global-metadata.dat (preferring Unity's canonical layout)
      - a .apk/.aab/.xapk/.zip: open as a zip and extract the pair to a temp dir

    Returns (binary, metadata, tmpdir). tmpdir is non-None when the files were
    extracted and should be removed by the caller when finished.
    """
    if os.path.isdir(game_path):
        binary, metadata = _find_in_dir(game_path)
        return binary, metadata, None
    if zipfile.is_zipfile(game_path):
        return _find_in_zip(game_path)
    return None, None, None


def _find_in_dir(root: str) -> Tuple[Optional[str], Optional[str]]:
    binary = metadata = None
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in filenames:
            lfn = fn.lower()
            if metadata is None and lfn in METADATA_NAMES:
                metadata = os.path.join(dirpath, fn)
            elif binary is None and lfn in BINARY_NAMES:
                binary = os.path.join(dirpath, fn)
    if binary and metadata:
        return binary, metadata
    return None, None


def _find_in_zip(path: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    tmpdir = tempfile.mkdtemp(prefix="il2cpp_dump_")
    try:
        binary, metadata = _find_pair_in_zip(path, tmpdir, depth=0)
        if not (binary and metadata):
            return None, None, tmpdir
        return binary, metadata, tmpdir
    except (zipfile.BadZipFile, KeyError, OSError):
        return None, None, tmpdir


def _find_pair_in_zip(path: str, tmpdir: str, depth: int) -> Tuple[Optional[str], Optional[str]]:
    """Search a zip (APK/AAB/XAPK) for the binary + metadata pair.

    Recurses into nested .apk/.zip/.obb entries (XAPK wraps APKs) up to a
    small depth. The pair may be split across multiple nested APKs (e.g.
    binary in config.arm64_v8a.apk, metadata in the main APK), so candidates
    are gathered from all of them and combined.

    When several ABIs are present, arm64-v8a is preferred over armeabi-v7a
    (and 64-bit over 32-bit generally); a single candidate is used as-is.
    Extracts to tmpdir.
    """
    if depth > 3:
        return None, None
    binary_candidates: Dict[str, Tuple[int, bytes]] = {}  # entry -> (priority, data)
    metadata = None

    def grab(zpath):
        nonlocal metadata
        with zipfile.ZipFile(zpath) as zf:
            for entry in zf.namelist():
                lname = os.path.basename(entry).lower()
                if metadata is None and lname in METADATA_NAMES:
                    metadata = zf.read(entry)
                elif lname in BINARY_NAMES:
                    if entry not in binary_candidates:
                        binary_candidates[entry] = (_abi_priority(entry), zf.read(entry))

    grab(path)
    if not (binary_candidates and metadata):
        # recurse into nested apk/zip entries
        with zipfile.ZipFile(path) as zf:
            nested = [e for e in zf.namelist()
                      if e.lower().endswith((".apk", ".zip", ".aab", ".obb"))]
        for entry in nested:
            inner_path = os.path.join(tmpdir, "inner_%d_%s" % (depth, os.path.basename(entry)))
            with zipfile.ZipFile(path) as zf:
                try:
                    with open(inner_path, "wb") as f:
                        f.write(zf.read(entry))
                except KeyError:
                    continue
            try:
                grab(inner_path)
                if not (binary_candidates and metadata):
                    ib, im = _find_pair_in_zip(inner_path, tmpdir, depth + 1)
                    if ib and im:
                        return ib, im
            except (zipfile.BadZipFile, OSError):
                pass
            finally:
                if os.path.exists(inner_path):
                    os.remove(inner_path)
    if not (binary_candidates and metadata):
        return None, None
    # pick the highest-priority binary (prefer arm64-v8a / 64-bit)
    best_entry = min(binary_candidates, key=lambda e: binary_candidates[e][0])
    _, binary = binary_candidates[best_entry]
    # write the pair
    bpath = os.path.join(tmpdir, "libil2cpp.so")
    mpath = os.path.join(tmpdir, "global-metadata.dat")
    with open(bpath, "wb") as f:
        f.write(binary)
    with open(mpath, "wb") as f:
        f.write(metadata)
    return bpath, mpath


def _abi_priority(entry: str) -> int:
    """Lower = preferred. Uses the zip path's ABI directory; defaults to 64-bit
    preference when the path doesn't name an ABI."""
    e = entry.lower()
    if "arm64-v8a" in e or "x86_64" in e or "arm64" in e:
        return 0
    if "armeabi-v7a" in e or "armeabi" in e or "x86" in e:
        return 1
    return 0  # no ABI hint: assume 64-bit is preferred (single-ABI case)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="IL2CPP binary dumper (research/testing tool).")
    ap.add_argument("-g", "--game", metavar="PATH",
                    help="game APK/AAB/XAPK file or extracted game directory; "
                         "the binary + metadata pair is auto-discovered")
    ap.add_argument("-b", "--binary", help="libil2cpp.so / GameAssembly.dll "
                                           "(overrides -g discovery)")
    ap.add_argument("-m", "--metadata", help="global-metadata.dat "
                                             "(overrides -g discovery)")
    ap.add_argument("-o", "--output", default=".", help="output directory")
    ap.add_argument("--version", type=float, help="force il2cpp version override")
    ap.add_argument("--no-symbol", action="store_true",
                    help="skip symbol search (force scan-based lookup)")
    ap.add_argument("--xor-key", metavar="HEX",
                    help="repeating XOR key (hex) to decrypt protected metadata")
    ap.add_argument("--dump-cs", action="store_true",
                    help="also write a human-readable dump.cs")
    args = ap.parse_args()

    cleanup_dir = None
    if args.binary and args.metadata:
        binary_path, metadata_path = args.binary, args.metadata
    elif args.game:
        binary_path, metadata_path, cleanup_dir = discover_game(args.game)
        if not (binary_path and metadata_path):
            print("error: could not find %s + %s inside %r" % (
                "/".join(BINARY_NAMES), "/".join(METADATA_NAMES), args.game),
                file=sys.stderr)
            print("  hint: pass the pair explicitly with -b <binary> -m <metadata>",
                  file=sys.stderr)
            return 1
        print("[+] discovered: binary=%s metadata=%s" % (binary_path, metadata_path))
    else:
        ap.error("provide -g <game.apk|game_dir> or both -b <binary> and -m <metadata>")

    try:
        return _run(args, binary_path, metadata_path)
    finally:
        if cleanup_dir:
            import shutil
            shutil.rmtree(cleanup_dir, ignore_errors=True)


def _run(args, binary_path: str, metadata_path: str) -> int:
    from dump_metadata import Metadata, MetaError, auto_xor_key, xor_decrypt
    with open(metadata_path, "rb") as f:
        mraw = f.read()
    key = None
    if args.xor_key:
        key = bytes.fromhex(args.xor_key)
        mraw = xor_decrypt(mraw, key, 0)
    else:
        try:
            meta = Metadata(mraw)
        except MetaError:
            auto = auto_xor_key(mraw)
            if auto:
                key = auto
                mraw = xor_decrypt(mraw, key, 0)
                print("[+] auto-detected XOR key: %s" % key.hex())
            else:
                print("error: bad magic - file may be protected. "
                      "Provide --xor-key <hex>, or the key could not be "
                      "auto-recovered (keys longer than 4 bytes with unknown "
                      "tails require manual --xor-key).", file=sys.stderr)
                return 1
    meta = Metadata(mraw)
    version = args.version if args.version is not None else float(meta.version)

    try:
        bin = load_binary(binary_path)
    except ValueError as e:
        print("error: %s" % e, file=sys.stderr)
        return 1

    # locate registrations
    code_reg = meta_reg = 0
    found_by_scan = False
    if not args.no_symbol:
        code_reg, meta_reg = bin.symbol_search()
        if code_reg and meta_reg:
            print("[+] symbol search: g_CodeRegistration=0x%x g_MetadataRegistration=0x%x"
                  % (code_reg, meta_reg))
    if not (code_reg and meta_reg):
        print("[*] symbol search failed, running section scan...")
        sh = SectionHelper(bin, version, len(meta.methods), len(meta.type_defs), len(meta.images))
        last_pct = -5

        def _progress(frac):
            nonlocal last_pct
            pct = int(frac * 100)
            if pct >= last_pct + 5:
                last_pct = pct
                print("[*] scanning binary for registrations... %d%%" % pct, end="\r", flush=True)

        sh._progress = _progress
        code_reg = sh.find_code_registration()
        meta_reg = sh.find_metadata_registration()
        print(" " * 60, end="\r")
        if code_reg and meta_reg:
            found_by_scan = True
            print("[+] scan: CodeRegistration=0x%x MetadataRegistration=0x%x"
                  % (code_reg, meta_reg))
    if not (code_reg and meta_reg):
        print("error: could not locate registrations", file=sys.stderr)
        print("  the binary may be protected/stripped. Try:", file=sys.stderr)
        print("    - a memory dump of the running game (LIKEY etc.):", file=sys.stderr)
        print("        python3 dump_memory.py --package <game> --dump-binary", file=sys.stderr)
        print("    - forcing the version:  --version <n>", file=sys.stderr)
        print("    - explicit -b/-m if the pair was auto-discovered wrong", file=sys.stderr)
        return 1

    # Version-correction heuristics apply to the scan path only (matches
    # Il2CppDumper: PlusSearch -> AutoPlusInit, SymbolSearch -> Init directly).
    if found_by_scan:
        version, code_reg, meta_reg = auto_plus_init(bin, meta, version, code_reg, meta_reg)
    bin.version = version
    print("[i] using il2cpp version %.1f" % version)

    ctx = Il2CppContext(bin, meta, version)
    if not init(ctx, bin, version, code_reg, meta_reg):
        print("error: failed to decode registrations", file=sys.stderr)
        return 1
    print("[i] images: %d, types: %d, methods: %d, type-specs: %d" % (
        len(meta.images), len(ctx.types), len(meta.methods), len(ctx.method_specs)))

    json_out = build_script(ctx, bin, meta, version)
    import os
    os.makedirs(args.output, exist_ok=True)
    spath = os.path.join(args.output, "script.json")
    with open(spath, "w", encoding="utf-8") as f:
        json.dump(json_out, f, indent=1, ensure_ascii=False)
    lits = [{"value": s["Value"], "address": "0x%X" % s["Address"]}
            for s in json_out["ScriptString"]]
    with open(os.path.join(args.output, "stringliteral.json"), "w", encoding="utf-8") as f:
        json.dump(lits, f, indent=1, ensure_ascii=False)
    if args.dump_cs:
        cs = generate_dump_cs(ctx, bin, meta, version)
        with open(os.path.join(args.output, "dump.cs"), "w", encoding="utf-8") as f:
            f.write(cs)
        print("[+] wrote %s (%d bytes)" % (os.path.join(args.output, "dump.cs"), len(cs)))
    print("[+] wrote %s (methods=%d, strings=%d, metadata=%d, metaMethods=%d, addresses=%d)"
          % (spath, len(json_out["ScriptMethod"]), len(json_out["ScriptString"]),
             len(json_out["ScriptMetadata"]), len(json_out["ScriptMetadataMethod"]),
             len(json_out["Addresses"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
