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
| 2 | `Metadata.kt`: header + version refinement (24.1/24.5/27.2/31...), element-size map, all tables, `read_string` | **DONE** (android `f78572c`): `dump_metadata.py --fingerprint` -> `fingerprint.txt`; `MetadataConformanceTest` byte-diff |
| 3 | `Elf.kt`: headers, VA map, **relocations**, `symbol_search`, scan ranges | symbol_search hits on Undying Hero on-disk lib; relocation sanity on Mini Tales memory dump |
| 4 | `SectionHelper` + `Context` + `init` + `BuildScript` -> `script.json` | semantic deep-equal of `script.json` + known counts (214,588) |
| 5 | `DumpCs.kt` -> `dump.cs` | byte-identical `dump.cs` |
| 6 | `DummyDll.kt` | file count + sampled diffs |
| 7 | Wire into app: Documents pair -> `out/` + progress callback (folds in the M5 progress item) | on-device run vs PC golden |

## Status: COMPLETE (release v1.0.0)

All phases gated and verified **byte-identical to the oracle on-device** against 5
fixtures (4 x v31 + 1 x v39: minitales, undyinghero, com.pikpok.bbl.play,
com.multicastgames.devour, com.game.tiny.knightfall.idle.rpg). Full
`./gradlew test` green.

- **Package**: renamed `dev.mbrx.il2cppdumper` -> `com.nnk218.il2cppdumper`
  (release APK: `Il2cppDumperAndroid.releaseV1.apk`).
- **Floating window**: custom overlay (SYSTEM_ALERT_WINDOW) — minimize to a
  draggable bubble, expand to a resizable floating panel (drag by the title bar,
  resize from any corner), maximize to full screen, close with confirmation.
  Compose hosted in the overlay via a dedicated LifecycleOwner/ViewModelStore/
  ActivityResultRegistry owner.
- **Parser fixes found by the v39 fixture**: trailing-empty string in the v38+
  strings blob (`.split(b"\x00")` semantics), `getTypeDef` must not truncate the
  64-bit type index to Int, `typeDefValues` layout projection with `r.get(k,0)`
  defaults for the fingerprint, and the v38+ assemblies row offsets/signedness.
- **On-device hardening**: dump pair staged into app-private storage via root
  (Android 13 scoped storage), parse outputs published back to
  `Documents/Il2CppDumps/<pkg>/out`, `largeHeap`, streaming `dump.cs`,
  SectionHelper refIndex rebuilt as primitive sorted arrays.
- Fixtures are auto-discovered from `pairs/` (no hardcoded list); goldens are
  regenerated by `scripts/make_golden.sh` (oracle path now resolved relative to
  the repo, or passed as `$1`).


## Pitfalls

- Signed/unsigned fidelity: Python mixes `i/q` (signed) and `I/Q` — `-1`
  sentinels in `_fmt_read`, signed `v == method_count` compares. Match per-read.
- Relocations before any VA read on memory-dumped libs.
- Exact JSON formatting (`indent=1`, space-after-colon, `ensure_ascii=False`,
  insertion order) for byte-identical `script.json` -> dedicated `JsonWriter.kt`.
- `find_reference` memory: consider `LongLongHashMap` if the plain HashMap is too
  heavy on-device.
- Memory dumps lack the section-header table (it lives past the last PT_LOAD
  segment, so it is never mapped). The oracle now guards the shdr parse
  (`dump_game.py` Elf64/Elf32); symbol search degrades to the section scan. The
  Kotlin `Elf.kt` MUST do the same or it will crash on exactly these fixtures.
  Phase 2 hit a parallel bug: Kotlin method rows were strided by the *typeDef*
  size; the fingerprint gate caught it immediately.
- Version sub-numbers must stay `Double` comparisons identical to Python
  (`24.2`, `27.1`, `27.2`, `29`, `31`, `35`).
- Endianness: all `<` (LE) via `ByteBuffer` LITTLE_ENDIAN.

## Explicitly dropped

PE/Windows binary support, APK/adb/zip discovery, XOR auto-detection (on-device
metadata is already decrypted), `Metadata.render_text`/`to_json`/`methods_for`
CLI helpers, v38 `type_index_to_name` (defer; keep version branches).
