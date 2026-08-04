# Usage Guide

This guide covers every script in the project. Install first — see
[INSTALL.md](INSTALL.md).

## Table of contents

- [The main dumper (`dumpers/dump_game.py`)](#the-main-dumper)
- [Standalone metadata parser (`dumpers/dump_metadata.py`)](#standalone-metadata-parser)
- [Rooted-device memory dumper (`dumpers/dump_memory.py`)](#rooted-device-memory-dumper)
- [Frida runtime dumper (`dumpers/frida_il2cpp_dump.py`)](#frida-runtime-dumper)
- [APK version probing (`tools/apk_probe.py`)](#apk-version-probing)
- [APKMirror scraper (`tools/apkm_scrape.py`)](#apkmirror-scraper)
- [IDA / Ghidra annotation](#ida--ghidra-annotation)
- [Reading the output](#reading-the-output)
- [Directory workflow](#directory-workflow)

---

## The main dumper

`python3 dumpers/dump_game.py` produces the complete dump set
(`script.json`, `stringliteral.json`, `Strings.txt`, `dump.cs`, `DummyDll/`).

### Run with no arguments

If you placed files in the standard folders, auto-discovery finds them:

```
DumpPayload/lib/libil2cpp.so  +  DumpPayload/metadata/global-metadata.dat   → used directly
DumpPayload/apk/<something>.apk                                            → pair discovered inside
```

```bash
python3 dumpers/dump_game.py
```

### Explicit inputs

```bash
# From an APK / APKM / XAPK (auto-extracts the pair inside)
python3 dumpers/dump_game.py -g game.apk

# From already-extracted files
python3 dumpers/dump_game.py -b libil2cpp.so -m global-metadata.dat

# From a pulled device (rooted phone)
python3 dumpers/dump_game.py --device --package com.example.game
```

### Common flags

| Flag | Effect |
|---|---|
| `-o DIR` | Write to a specific folder (default: `DumpResult/<timestamp>/`) |
| `--dump-attributes` | Render `[Attr(...)]` in `dump.cs` / `DummyDll` |
| `--dump-events` | Render events in `dump.cs` / `DummyDll` |
| `--no-dump-cs` / `--no-dummy-dll` | Skip that output (they're on by default) |
| `--dummy-dll-dir DIR` | Change DummyDll location |
| `--xor-key HEX` | Decrypt XOR-protected metadata with the given key |
| `--version N` | Force the il2cpp version (e.g. `--version 39`) |
| `--version-only` | Just print the metadata version and exit (quick check) |
| `--no-symbol` | Skip the symbol search, force the section scan |

### Protected metadata

If you see `error: bad magic - file may be protected`:

```bash
# known key
python3 dumpers/dump_game.py -b libil2cpp.so -m global-metadata.dat --xor-key <hex>

# or let it try to auto-detect a 4-byte repeating key (no flag)
python3 dumpers/dump_game.py -b libil2cpp.so -m global-metadata.dat
```

For custom-encrypted games (`LIKEY`, etc.) that resist static tools, use
`dump_memory.py` to pull the decrypted copy from a running game, then dump it
(see below).

---

## Standalone metadata parser

`python3 dumpers/dump_metadata.py` inspects just the `global-metadata.dat`
without a binary (useful for a quick look at the version or string tables).

```bash
# text dump to the terminal
python3 dumpers/dump_metadata.py -i global-metadata.dat

# to a file, plus a JSON dump and string tables
python3 dumpers/dump_metadata.py -i global-metadata.dat -o dump.txt --json --strings

# XOR-decrypted input
python3 dumpers/dump_metadata.py -i global-metadata.dat --xor-key <hex>
```

---

## Rooted-device memory dumper

`python3 dumpers/dump_memory.py` reads a running game's process memory over
`adb` (no Frida, no app installs on the phone). It scans for the *decrypted*
il2cpp metadata header and dumps it — this is how you get past `LIKEY` and
other custom protection.

Prereqs: rooted phone + USB debugging + game running.

```bash
# attach to a running game
python3 dumpers/dump_memory.py --package com.example.game --dump-binary

# or by PID
python3 dumpers/dump_memory.py --pid 12345 --dump-binary

# also scan file-backed ranges (some games keep the data there)
python3 dumpers/dump_memory.py --package com.example.game --dump-binary --scan-all
```

Output goes to `DumpResult/<timestamp>/`:

- `global-metadata.decrypted.<addr>.dat` — the decrypted metadata
- `libil2cpp.memorydump.so` — the in-memory lib (relocations applied)

Then dump normally:

```bash
python3 dumpers/dump_game.py -b DumpResult/<ts>/libil2cpp.memorydump.so \
    -m DumpResult/<ts>/global-metadata.decrypted.<addr>.dat
```

> Debuggable apps without root: `dump_memory.py` automatically falls back to
> `adb shell run-as <package>`.

### Against an emulator (no phone)

`python3 tools/emulator_dump.py` connects adb to a local emulator and then
delegates the exact same scan to `dump_memory.py` — no phone needed.

```bash
# Waydroid (Linux) — the default
python3 tools/emulator_dump.py --package com.example.game --dump-binary

# explicit container IP (if auto-detection misses)
python3 tools/emulator_dump.py --waydroid-ip 192.168.240.112 --package com.example.game --dump-binary

# other emulators (LDPlayer / MuMu / BlueStacks)
python3 tools/emulator_dump.py --emulator mumu --package com.example.game --dump-binary
```

All flags of `dump_memory.py` pass through (`--dump-binary`, `--scan-all`,
`--size`, `--out`).

---

## Frida runtime dumper

`python3 dumpers/frida_il2cpp_dump.py` attaches to a running game and walks the
live il2cpp data structures via the engine's own exported functions
("active call"). It works even when the metadata on disk is encrypted — no
static files or memory scanning needed.

```bash
python3 dumpers/frida_il2cpp_dump.py --package com.example.game
python3 dumpers/frida_il2cpp_dump.py --pid 12345
python3 dumpers/frida_il2cpp_dump.py --package com.example.game --fresh --dump-cs
```

Requires `pip install frida-tools`.

---

## APK version probing

`python3 tools/apk_probe.py` reads the il2cpp metadata version from an APK /
APKM / XAPK **without downloading the whole file** (HTTP Range requests fetch
only the ZIP tail + the compressed `global-metadata.dat`, then inflate it).

```bash
python3 tools/apk_probe.py https://example.com/game.apk     # remote URL
python3 tools/apk_probe.py game.apkm                         # local file
python3 tools/apk_probe.py url1 url2 url3                    # many at once
```

Prints the metadata version or why it failed. Version → Unity era:
`29` = Unity 2021, `31` = Unity 2022.1, `33` = Unity 2022.3, `35` = Unity
2023 / Unity 6, `39` = Unity 6.

---

## APKMirror scraper

`python3 tools/apkm_scrape.py` walks APKMirror's 4-hop download chain with a
cookie session, resolves the CDN URL, probes the version, and optionally
downloads + dumps.

```bash
# probe a release's version (no download)
python3 tools/apkm_scrape.py --release https://www.apkmirror.com/apk/.../release/

# search, resolve, download into ./hunt/ and dump
python3 tools/apkm_scrape.py "royal match" --download hunt/
```

APKMirror rate-limits bots; use `--delay <seconds>` if you get throttled.

---

## IDA / Ghidra annotation

After dumping, apply C# names/comments to the disassembly so functions show
their game names instead of `sub_...`.

**IDA** — open `libil2cpp.so` in IDA, then `File > Script file...` and pick
`tools/ida_annotate.py`. It prompts for your `script.json`.

**Ghidra** — import the binary, `Window > Script Manager`, add this repo's
folder (green `+`), run `tools/ghidra_annotate.py`. It prompts for
`script.json`.

Both scripts:
- create functions at every address in `Addresses`
- rename methods to `Class$$method`
- label string literals `StringLiteral_N` with the value as a comment
- label type infos / metadata-method slots

> The binary must be loaded with the same image base the dump used.

---

## Reading the output

Each run lands in a fresh `DumpResult/<timestamp>/` folder, so earlier results
are never overwritten. Inside:

| File | What it is |
|---|---|
| `script.json` | Machine-readable: all methods, strings, type infos, addresses |
| `stringliteral.json` | String literals with their addresses |
| `Strings.txt` | All metadata strings, one per line |
| `dump.cs` | Human-readable C# classes/methods |
| `DummyDll/` | Compilable per-assembly C# stubs (IDE intellisense) |

Example `script.json` stats:

```
methods=124465  strings=26455  metadata=21306  metaMethods=36632  addresses=136658
```

---

## Directory workflow

```
IL2CPP-Dumper-Python/
├── dumpers/        core dumpers (game, metadata, memory, frida, likey)
├── tools/          utilities (probe, scrape, ida/ghidra annotate)
├── tests/          synthetic fixtures + regression sweep
├── DumpPayload/    ← drop inputs here (auto-discovered)
│   ├── apk/  lib/  metadata/
└── DumpResult/     ← output (auto-created, one timestamped folder per run)
```
