# IL2CPP-Dumper-Python

A Python-based IL2CPP dumper for Unity games. It locates `Il2CppCodeRegistration` / `Il2CppMetadataRegistration` in a game binary, resolves methods/types/strings, and produces both machine-readable JSON and a human-readable `dump.cs`.

Written from scratch (with reference to Perfare/Il2CppDumper's PR-903), targeting real-world stripped Android `libil2cpp.so` + `global-metadata.dat` pairs, including **XOR-protected** and **LIKEY-custom-encrypted** games.

## Features

- **`il2cpp_bin_dumper.py`** — the main dumper:
  - Auto-discover `libil2cpp.so` + `global-metadata.dat` from an APK / AAB / XAPK (including nested inner-APKs) or an extracted game directory (`-g`)
  - ABI auto-detection: prefers **arm64-v8a** over armeabi-v7a when both are present
  - Symbol search + stripped-binary section scan (mscorlib reference walk + typeDefinitionsCount heuristic)
  - Applies ELF relocations in-memory (required for reloc-applied pointer chains)
  - v24–v39 metadata support (variable-width indexes, v38+ section layout, blob strings)
  - `--dump-cs` produces a human-readable `dump.cs` (classes, fields with offsets, properties, methods with RVA/Offset/VA, const/param default values, generic instantiations)
  - `--xor-key` and automatic XOR key detection for protected metadata
- **`root_memscan.py`** — bypasses custom metadata encryption (e.g. the `LIKEY` scheme) by scanning a rooted device's process memory over adb for the decrypted header (magic `0xFAB11BAF`) and dumping the decrypted `global-metadata.dat` plus an in-memory copy of `libil2cpp.so` with relocations applied. **No Frida required.**
- **`il2cpp_meta_dumper.py`** — standalone `global-metadata.dat` parser/renderer (text + JSON), with XOR and version overrides.
- **Test fixtures** — `make_test_metadata.py` + `make_test_elf.py` generate synthetic v31 metadata and ELF binaries; `run_sweep.py` runs the 8-combo regression sweep.

## Requirements

- Python 3.8+
- No third-party packages for the dumpers
- `adb` (Android platform-tools) + a rooted phone for `root_memscan.py`

## Usage

### Dump from an APK / XAPK (auto-discovery)

```bash
python3 il2cpp_bin_dumper.py -g game.apk -o out/
python3 il2cpp_bin_dumper.py -g game.xapk -o out/     # recurses into inner APKs
```

### Dump from an explicit pair

```bash
python3 il2cpp_bin_dumper.py -b libil2cpp.so -m global-metadata.dat -o out/
```

### Also produce human-readable dump.cs

```bash
python3 il2cpp_bin_dumper.py -g game.apk --dump-cs -o out/
```

### Protected metadata

```bash
# known XOR key
python3 il2cpp_bin_dumper.py -b libil2cpp.so -m global-metadata.dat --xor-key <hex> -o out/
# or auto-detect (works for 4-byte repeating keys)
python3 il2cpp_bin_dumper.py -b libil2cpp.so -m global-metadata.dat -o out/
```

### Custom-encrypted metadata (LIKEY etc.) — dump from a running game

```bash
python3 root_memscan.py --package com.example.game --dump-binary

# then dump the decrypted pair
python3 il2cpp_bin_dumper.py -b likey_dump/libil2cpp.memorydump.so \
    -m likey_dump/global-metadata.decrypted.<addr>.dat -o out/
```

### Standalone metadata inspection

```bash
python3 il2cpp_meta_dumper.py -i global-metadata.dat -o dump.txt
python3 il2cpp_meta_dumper.py -i global-metadata.dat --json --strings
```

### Tests

```bash
python3 make_test_metadata.py
python3 make_test_elf.py --bits 64
python3 make_test_elf.py --bits 32
python3 run_sweep.py        # 10/10 combos
```

## Outputs

- **`script.json`** — `ScriptMethod`, `ScriptString`, `ScriptMetadata`, `ScriptMetadataMethod`, `Addresses` (Il2CppDumper-compatible schema)
- **`stringliteral.json`** — string literals with addresses
- **`dump.cs`** — human-readable C# reconstruction (with `--dump-cs`)

## Notes

- Validated against Perfare/Il2CppDumper output on multiple real 64-bit Unity games (byte-identical classes/members when attributes are disabled).
- Real-game assets and dump outputs are excluded via `.gitignore`; only source + synthetic fixtures are committed.
