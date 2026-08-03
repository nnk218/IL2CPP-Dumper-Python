# IL2CPP-Dumper-Python

A Python toolkit for dumping Unity IL2CPP games: it extracts method/type/string information from a game's `libil2cpp.so` + `global-metadata.dat`, producing both machine-readable JSON and a human-readable C# `dump.cs`.

It handles real-world stripped Android binaries, XOR-protected metadata, and even games with custom encryption (e.g. the `LIKEY` scheme) by reading the decrypted data from a running game's memory.

---

## What this project does

Unity IL2CPP games compile C# code to native machine code (`libil2cpp.so`) and store class/method metadata in a companion file (`global-metadata.dat`). Dumping a game means combining these two files to reconstruct readable C#-like definitions:

- Which classes/methods exist and where they are in memory (addresses)
- Method signatures, fields, properties, string literals
- A human-readable `dump.cs` you can browse

This project automates that. It's written in pure Python (no third-party packages for the core dumpers).

---

## Requirements

| Tool | Needed for | How to get it |
|---|---|---|
| Python 3.8+ | Everything | `sudo pacman -S python` (Arch/CachyOS) |
| `adb` | Only `dump_memory.py` (running-game dumps) | `sudo pacman -S android-tools` |
| A rooted phone | Only `dump_memory.py` | e.g. Magisk, KernelSU, SuKisu |

The core dumpers (`dump_game.py`, `dump_metadata.py`) need **only Python** — no phone, no adb.

### Optional: install as commands (pip)

The project is pip-installable. Installing exposes `dump-game`, `dump-metadata`,
and `dump-memory` as shell commands:

```bash
pip install .
# then:
dump-game -g game.apk -o out/
dump-metadata -i global-metadata.dat -o dump.txt
dump-memory --package com.example.game --dump-binary
```

You can also run the scripts directly with `python3 dump_game.py ...` — both
styles are equivalent.

---

## Getting started (first 5 minutes)

### 1. Find your game files

A Unity IL2CPP Android game ships with:

```
libil2cpp.so          (native binary)
global-metadata.dat   (metadata - inside the APK at assets/bin/Data/Managed/Metadata/)
```

If you only have the APK/XAPK, the dumper can extract both automatically (see below).

### 2. Run the dumper

```bash
# From an APK or XAPK (auto-discovers both files):
python3 dump_game.py -g game.apk -o out/

# Or from already-extracted files:
python3 dump_game.py -b libil2cpp.so -m global-metadata.dat -o out/
```

### 3. Read the results

After it finishes, `out/` contains:

| File | What it is |
|---|---|
| `script.json` | All methods, strings, type infos and addresses (for tools/scripts) |
| `stringliteral.json` | String literals with their addresses |
| `dump.cs` | Human-readable C# classes/methods (add `--dump-cs` to generate) |

For a human-readable dump, run:

```bash
python3 dump_game.py -g game.apk --dump-cs -o out/
# -> produces out/dump.cs, a .cs file you can open in any text editor
```

---

## Detailed usage

### Dump from an APK / XAPK (recommended)

```bash
python3 dump_game.py -g game.apk -o out/
python3 dump_game.py -g game.xapk -o out/
```

The `-g` flag searches inside the archive for `libil2cpp.so` and `global-metadata.dat`. It handles:
- Plain APKs
- XAPKs (which wrap several APKs) — it recurses into the inner `.apk` files
- Multiple CPU architectures (ABIs) — prefers **arm64-v8a** (64-bit) over armeabi-v7a (32-bit)

### Dump from extracted files

```bash
python3 dump_game.py -b /path/to/libil2cpp.so -m /path/to/global-metadata.dat -o out/
```

### Protected metadata (XOR-encrypted)

Some games XOR-encrypt `global-metadata.dat`. If you see:

```
error: bad magic - file may be protected
```

either pass the XOR key:

```bash
python3 dump_game.py -b libil2cpp.so -m global-metadata.dat --xor-key <hex-key> -o out/
```

or let the dumper try to auto-detect it (works for 4-byte repeating keys):

```bash
python3 dump_game.py -b libil2cpp.so -m global-metadata.dat -o out/
```

### Custom-encrypted games (LIKEY, etc.)

If the metadata starts with a custom marker like `LIKEY`, static tools (including the original Il2CppDumper) fail. The fix is to read the **decrypted** copy from the running game's memory.

```bash
# 1. On the PC, phone connected (USB debugging + root), game open:
python3 dump_memory.py --package com.example.game --dump-binary

# 2. This writes:
#    likey_dump/global-metadata.decrypted.<addr>.dat  (the decrypted metadata)
#    likey_dump/libil2cpp.memorydump.so               (the lib, with relocations applied)

# 3. Dump normally:
python3 dump_game.py -b likey_dump/libil2cpp.memorydump.so \
    -m likey_dump/global-metadata.decrypted.<addr>.dat -o out/
```

> `dump_memory.py` needs `adb` + a rooted phone. It does **not** need Frida or any app installed on the phone.

### Standalone metadata inspection

```bash
# Text dump to screen:
python3 dump_metadata.py -i global-metadata.dat

# To a file, plus a JSON dump and string tables:
python3 dump_metadata.py -i global-metadata.dat -o dump.txt --json --strings
```

### Forcing a metadata version (advanced)

If auto-detection picks the wrong version:

```bash
python3 dump_game.py -b libil2cpp.so -m global-metadata.dat --version 39 -o out/
```

### Annotating a disassembler (IDA / Ghidra)

After dumping, you can apply names/comments to the disassembly so functions show
their C# names (`MonoBehaviour.IsInvoking` instead of `sub_6A41384`).

**IDA** — open `libil2cpp.so` in IDA, then `File > Script file...` and pick
`ida_annotate.py`. It prompts for your `script.json`.

**Ghidra** — import the binary, then `Window > Script Manager` → add this
repo's folder (green `+`) → run `ghidra_annotate.py`. It prompts for
`script.json`.

Both scripts:
- create functions at every address in `Addresses`
- rename every method to `Class$$method`
- label string literals `StringLiteral_N` with the value as a comment
- label type infos / metadata-method slots with names + comments

> The binary must be loaded with the same image base the dump used (for ELF
> that is normally the file's load base, so the raw addresses match).

---

## All command-line options

### dump_game.py

| Option | Description |
|---|---|
| `-g, --game PATH` | APK/AAB/XAPK file or extracted game directory (auto-discovery) |
| `-b, --binary` | Explicit `libil2cpp.so` / `GameAssembly.dll` (overrides `-g`) |
| `-m, --metadata` | Explicit `global-metadata.dat` (overrides `-g`) |
| `-o, --output` | Output directory (default: current directory) |
| `--version` | Force il2cpp version (e.g. `39`) |
| `--xor-key HEX` | XOR key to decrypt protected metadata |
| `--dump-cs` | Also write a human-readable `dump.cs` |
| `--no-symbol` | Skip symbol search (force the scan-based lookup) |

### dump_metadata.py

| Option | Description |
|---|---|
| `-i, --input` | Path to `global-metadata.dat` |
| `-o, --output` | Write text dump to a file (default: stdout) |
| `--version` | Force metadata version |
| `--xor-key HEX` | XOR key for protected metadata |
| `--xor-offset` | Start XOR decryption at this byte offset |
| `--json` | Also write a `.json` dump |
| `--strings` | Include string literal/string tables |

### dump_memory.py

| Option | Description |
|---|---|
| `--package` | Game package name, e.g. `com.example.game` |
| `--pid` | Process PID (alternative to `--package`) |
| `--adb` | Path to the adb binary (default: search PATH) |
| `--size` | Bytes to dump from the found metadata header |
| `--dump-binary` | Also dump `libil2cpp.so` from memory (relocations applied) |
| `--out` | Output directory (default: `likey_dump/`) |

---

## Running the tests

The repo includes a self-contained test suite (synthetic metadata + ELF fixtures, no game files needed):

```bash
python3 make_test_metadata.py
python3 make_test_elf.py --bits 64
python3 make_test_elf.py --bits 32
python3 run_sweep.py        # 10/10 combinations should PASS
```

---

## Troubleshooting

**"error: bad magic - file may be protected"**
→ The metadata is XOR-encrypted. Provide `--xor-key <hex>` (or let auto-detection try).

**"error: could not locate registrations"**
→ The binary is heavily stripped. If it's a `LIKEY`-style game, use `dump_memory.py` to get the in-memory lib + decrypted metadata. For other games, try `--no-symbol` or check that the `libil2cpp.so` and `global-metadata.dat` are from the *same* build.

**"error: could not find PID for <package>"**
→ The game must be running. Also check that `su` grants root to adb's shell (in your root manager's allowlist).

**`adb devices` shows "unauthorized"**
→ Accept the USB-debugging prompt on the phone, or re-authorize in developer options.

**The dump looks wrong / version mismatch**
→ Try `--version <n>` to force the metadata version.

**dump.cs is missing**
→ Add `--dump-cs` to the `dump_game.py` command.

---

## Project layout

```
dump_game.py            Main dumper: APK discovery, registration search, script.json + dump.cs
dump_metadata.py        Standalone global-metadata.dat parser/renderer
dump_memory.py          Rooted-device memory dumper (LIKEY / custom-encrypted games)
likey_dump.py           (legacy) Frida-based metadata scanner
ida_annotate.py         Apply names/comments to an IDA database from script.json
ghidra_annotate.py      Apply names/comments to a Ghidra program from script.json
make_test_elf.py        Synthetic ELF fixture generator (tests)
make_test_metadata.py   Synthetic metadata fixture generator (tests)
run_sweep.py            Regression test runner
```

## Notes

- Validated against Perfare/Il2CppDumper output on multiple real 64-bit Unity games (byte-identical classes/members with attributes off).
- Real-game assets and dump outputs are excluded from the repo via `.gitignore`; only source and synthetic fixtures are committed.
