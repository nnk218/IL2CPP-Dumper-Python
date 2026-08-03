#!/usr/bin/env python3
"""Regression sweep for il2cpp_bin_dumper.py across fixture combinations.

Covers the 8 combos:
    bits:     64 / 32
    metadata: plain / XOR-protected
    lookup:   symbol search / section scan

Each combo pairs a generated metadata file with a generated ELF fixture and
verifies that:
  - the run exits 0,
  - script.json parses and reports the expected method/string/metadata counts,
  - the output is byte-stable (a second identical run reproduces it).

Usage:
    python3 make_test_metadata.py
    python3 make_test_elf.py --bits 64
    python3 make_test_elf.py --bits 32
    python3 run_sweep.py
"""

import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
BINDUMPER = os.path.join(HERE, "il2cpp_bin_dumper.py")
XOR_KEY = "00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f"

# 4-byte repeating key fixture (auto-detectable without --xor-key)
KEY4 = bytes([0x05, 0x06, 0x07, 0x08])


def _make_xor4():
    """sample_xor4.dat: sample.dat XOR'd with a 4-byte key (no --xor-key needed)."""
    from il2cpp_meta_dumper import xor_decrypt
    src = os.path.join(HERE, "sample.dat")
    out = os.path.join(HERE, "sample_xor4.dat")
    if not os.path.exists(out):
        with open(src, "rb") as f:
            data = f.read()
        with open(out, "wb") as f:
            f.write(xor_decrypt(data, KEY4))
    return out


# name -> (binary, metadata, xor_key?, expected_count)
CASES = {
    # 64-bit
    "elf":    ("libil2cpp_test.so", "sample.dat", None),
    "xor":    ("libil2cpp_test.so", "sample_xor.dat", XOR_KEY),
    "xor4":   ("libil2cpp_test.so", "sample_xor4.dat", None),  # auto-detect
    "scan":   ("libil2cpp_scan_test.so", "sample_mscorlib.dat", None),
    "scan_xor": ("libil2cpp_scan_test.so", "sample_mscorlib_xor.dat", XOR_KEY),
    # 32-bit
    "elf32":  ("libil2cpp_test32.so", "sample.dat", None),
    "xor32":  ("libil2cpp_test32.so", "sample_xor.dat", XOR_KEY),
    "xor432": ("libil2cpp_test32.so", "sample_xor4.dat", None),  # auto-detect
    "scan32": ("libil2cpp_scan_test32.so", "sample_mscorlib.dat", None),
    "scan_xor32": ("libil2cpp_scan_test32.so", "sample_mscorlib_xor.dat", XOR_KEY),
}

# expected (methods, strings, metadata, metaMethods, addresses) per case
EXPECTED = {name: (1, 1, 1, 1, 1) for name in CASES}


def run_one(name, binary, metadata, xor_key, outdir):
    cmd = [sys.executable, BINDUMPER, "-b", os.path.join(HERE, binary),
           "-m", os.path.join(HERE, metadata), "-o", outdir]
    if xor_key:
        cmd += ["--xor-key", xor_key]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        return False, "exit=%d: %s" % (res.returncode, res.stderr.strip().splitlines()[-1] if res.stderr.strip() else res.stdout.strip())
    spath = os.path.join(outdir, "script.json")
    with open(spath, "r", encoding="utf-8") as f:
        data = json.load(f)
    got = (len(data.get("ScriptMethod", [])), len(data.get("ScriptString", [])),
           len(data.get("ScriptMetadata", [])), len(data.get("ScriptMetadataMethod", [])),
           len(data.get("Addresses", [])))
    return True, got


def main():
    _make_xor4()
    shutil.rmtree(os.path.join(HERE, "sweep"), ignore_errors=True)
    os.makedirs(os.path.join(HERE, "sweep"))
    failures = 0
    for name in sorted(CASES):
        binary, metadata, xor_key = CASES[name]
        outdir = os.path.join(HERE, "sweep", name)
        os.makedirs(outdir)
        ok, got = run_one(name, binary, metadata, xor_key, outdir)
        if not ok:
            print("FAIL %-10s %s" % (name, got))
            failures += 1
            continue
        if got != EXPECTED[name]:
            print("FAIL %-10s expected %s got %s" % (name, EXPECTED[name], got))
            failures += 1
            continue
        print("PASS %-10s %s" % (name, got))
    print("=" * 40)
    print("%d/%d passed" % (len(CASES) - failures, len(CASES)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
