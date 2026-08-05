# M4b: Port `dump_game.py` parse core to Kotlin

Status: PLANNED (2026-08-05). Decision: native Kotlin port, not Chaquopy — reuse the
existing `scanmem` acquisition layer, keep a single app toolchain, no CPython runtime.

## Goal

The Android app already lands `global-metadata.dat` + `libil2cpp.so` in
`Documents/Il2CppDumps/<pkg>/`. M4b adds a parser stage so the phone itself
produces `script.json`, `stringliteral.json`, `Strings.txt`, `dump.cs`, and
`DummyDll/*.cs` — mirroring `dump_game.py -g <folder>` with zero flags.

## Oracle & conformance strategy

The PC Python script is the **oracle**. Every port phase is gated by a JVM
conformance test (runs on PC via `./gradlew test`, no device needed):

- fixture pairs live in `app/src/test/resources/pairs/` (one dir per game:
  `global-metadata.dat` + `libil2cpp.so`, copied from the M4 device dumps)
- a small script regenerates golden outputs from the oracle
  (`dump_game.py -g <pair> -o gold/<pair> --dump-cs`)
- phase gates: see table below

## What the Python actually does (verified trace)

Acquisition/discovery in `dump_game.py` (APK/AAB/adb/zip, lines 2522-2919) is
**dropped** — the app owns acquisition. The port covers `_run`
(`dump_game.py:2923-3046`) and its callees:

```
metadata file -> Metadata(mraw)                 # dump_metadata.py table parse
binary file  -> load_binary() -> Elf64/Elf32    # headers + apply_relocations
                  |
   [1] symbol_search() -> g_CodeRegistration / g_MetadataRegistration
   [2] miss -> SectionHelper.find_code/metadata_registration()   # heuristics
                  |
   version-correct via auto_plus_init (scan path only)
                  v
   Il2CppContext + init()   # decode pointer arrays from both registrations
                  v
   build_script() -> ScriptMethod/ScriptString/ScriptMetadata/ScriptMetadataMethod/Addresses
   scan_metadata_usage()    # v27+: encode-token scan over data segs; v<27: usage lists
                  v
   script.json  stringliteral.json  Strings.txt
   dump.cs            (DumpCsGenerator ~900 lines)
   DummyDll/*.cs      (per-image .cs with needs-using resolution)
```

Notes:
- `dump_metadata.py` (1363 lines) is a version-gated little-endian table reader:
  header -> per-table offset/count -> element-size map -> row layouts
  (`type_def_layout`/`method_def_layout`/`image_layout`), v24-35, plus a v38
  branch with variable-width index sizes (`_fmt_read` kinds T/D/G/P, `-1`
  sentinels for 0xFF/0xFFFF/0xFFFFFFFF).
- `Elf64Binary.apply_relocations` (AArch64 ABS64/RELATIVE + x86-64 RELA/REL/
  JMPREL) is **critical**: the Mini Tales `libil2cpp.so` is a LIKEY memory dump
  (entry 0x0, relocations applied). Relocations MUST run before any VA read.
- `SectionHelper.find_reference` builds a `{value -> [VA...]}` reverse index
  over data sections; heaviest memory consumer on a 90 MB dump (~11 M entries).

## Kotlin module scaffold

```
app/src/main/java/dev/mbrx/il2cppdumper/parser/
  Metadata.kt        # <- dump_metadata.py: Metadata, layouts, table readers, read_string cache
  Elf.kt             # <- dump_game.py 155-600: Binary, Elf64, Elf32, relocations, symbol_search
  Specs.kt           # CODE_REG_SPEC / META_REG_SPEC / CODE_GEN_MODULE_SPEC (version-gated)
  SectionHelper.kt   # <- 599-750: reverse index + registration heuristics
  Context.kt         # <- 777-1168: Il2CppContext, init(), type-name rendering, Il2CppTypeInfo
  BuildScript.kt     # <- 1171-1236 + 2390-2520: build_script + scan_metadata_usage
  DumpCs.kt          # <- 1273-2330: compressed-uint, BlobValue, DumpCsGenerator, attrs
  DummyDll.kt        # <- 2322-2388
  JsonWriter.kt      # json.dump(indent=1, ensure_ascii=False) replica (byte-compatible)
  Parser.kt          # public entry: parse(binary, metadata, outDir, cfg, progress: (Float)->Unit)
app/src/test/java/dev/mbrx/il2cppdumper/parser/   # JVM conformance tests
app/src/test/resources/pairs/<game>/              # test fixtures (metadata + binary)
```

Model: typed data classes per row (TypeDefData, MethodDefData, ...) instead of
`List<Dict>`; 214k methods x ~10 ints ~ 10-20 MB, fine. Columnar `IntArray`s are
the fallback if profiling complains.

## Phased port (each gated by conformance)

| Phase | Port | Gate |
|---|---|---|
| 1 | Harness: `parser/` module + JVM test rig; fixture pairs; golden-file generator | `./gradlew test` runs on PC |
| 2 | `Metadata.kt`: header + version refinement (24.1/24.5/27.2/31...), element-size map, all tables, `read_string` | deep-equal vs oracle `render_text`; table counts |
| 3 | `Elf.kt`: headers, VA map, **relocations**, `symbol_search`, scan ranges | symbol_search hits on Undying Hero on-disk lib; relocation sanity on Mini Tales memory dump |
| 4 | `SectionHelper` + `Context` + `init` + `BuildScript` -> `script.json` | semantic deep-equal of `script.json` + known counts (214,588) |
| 5 | `DumpCs.kt` -> `dump.cs` | byte-identical `dump.cs` |
| 6 | `DummyDll.kt` | file count + sampled diffs |
| 7 | Wire into app: Documents pair -> `out/` + zip; progress callback (folds in the M5 progress item) | on-device run vs PC golden |

## Pitfalls

- Signed/unsigned fidelity: Python mixes `i/q` (signed) and `I/Q` — `-1`
  sentinels in `_fmt_read`, signed `v == method_count` compares. Match per-read.
- Relocations before any VA read on memory-dumped libs.
- Exact JSON formatting (`indent=1`, space-after-colon, `ensure_ascii=False`,
  insertion order) for byte-identical `script.json` -> dedicated `JsonWriter.kt`.
- `find_reference` memory: consider `LongLongHashMap` if the plain HashMap is too
  heavy on-device.
- Version sub-numbers must stay `Double` comparisons identical to Python
  (`24.2`, `27.1`, `27.2`, `29`, `31`, `35`).
- Endianness: all `<` (LE) via `ByteBuffer` LITTLE_ENDIAN.

## Explicitly dropped

PE/Windows binary support, APK/adb/zip discovery, XOR auto-detection (on-device
metadata is already decrypted), `Metadata.render_text`/`to_json`/`methods_for`
CLI helpers, v38 `type_index_to_name` (defer; keep version branches).
