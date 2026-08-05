# Android App PoC — Design Document

Status: **Draft / on hold** · Last updated: 2026-08-04
Target: rooted Android 13 device (23043RP34G), SuKisu root, adb-connected.

---

## 1. Purpose

Validate that the existing `dump_memory.py` memory-scan logic can run **entirely
on-device** (no PC, no adb, no USB) inside a native Android app. The minimum
viable deliverable is:

> A rooted Android app that finds a running game, scans `/proc/<pid>/mem` for
> the decrypted il2cpp metadata header (`0xFAB11BAF`), and saves
> `global-metadata.decrypted.<addr>.dat` (+ optional `libil2cpp.memorydump.so`)
> to shared storage.

This is deliberately **not** a full dumper: parsing `dump.cs` / `script.json`
from the dumped files stays on the PC for now. The PoC only validates the
device-side acquisition that PC tooling struggles with.

## 2. Why this PoC

- The scan logic is already proven (`dump_memory.py`), but only ever ran via
  `adb shell` from a PC.
- A native app removes the PC dependency for acquisition, the single biggest UX
  win for this toolchain.
- Success criteria are crisp and testable on the connected device today.

## 3. Out of scope (later milestones)

- On-device parsing of the dumped pair → `dump.cs` / `script.json`
- In-app browsing / search of classes & methods
- GameGuardian-style UI polish
- Non-root paths (e.g. `run-as` for debuggable apps) — later
- Distribution (Play Store is out of scope; sideload only)

## 4. Architecture

```
┌──────────────────────────── Android app (Kotlin) ────────────────────────────┐
│  UI (Jetpack Compose)                                                        │
│   ├─ Root status banner                                                      │
│   ├─ Running-app list → pick a game                                          │
│   ├─ Scan progress + found VAs                                              │
│   └─ Export result (Share sheet / save to Documents)                         │
│                                                                              │
│  Root access layer                                                           │
│   ├─ Magisk/SuKisu `su` via `libsu` (topjohnwu)  ← daemon + callback         │
│   └─ executes privileged shell commands                                      │
│                                                                              │
│  Scan engine (native, C++ via NDK)  ← port of dump_memory.py scan logic      │
│   ├─ native helper binary (scanmem) staged to /data/local/tmp, run via su    │
│   ├─ enumerate /proc/<pid>/maps (parse read ranges)                          │
│   ├─ read each range via pread() on /proc/<pid>/mem                          │
│   ├─ scan for MAGIC (0xAF 1B B1 FA) + version validation                     │
│   └─ write global-metadata.decrypted.<addr>.dat                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Why NDK/C++ for the scan engine

- `pread()` on `/proc/<pid>/mem` in a tight loop is the hot path; C++ is fast
  and matches the byte-level control `dump_memory.py` has.
- The Python scan logic is small and ports 1:1 (MAGIC search + version check).
- **Key constraint (found in M3): the app process is NOT root** — `open()`
  on another app's `/proc/<pid>/mem` from the app uid fails under SELinux.
  Root only exists inside the `su` shell. So the scan engine is built as a
  **standalone ARM64 executable** (`app/src/main/cpp/scanmem.cpp`, built with
  the NDK toolchain, staged into `assets/`), copied to `/data/local/tmp` via
  `su` and executed with `su -c /data/local/tmp/scanmem <pid> <outdir>`.
  Root *invokes* it; C++ does the byte scan with root privileges.

### Why `libsu`

- `libsu` (Magisk's library) is the standard, maintained way to talk to `su`
  from an app — handles daemon management, `su -c`, streaming output, and the
  root-prompt callback cleanly. It also falls back to a non-root `sh` shell.

## 5. Root / device flow

1. App starts → request root via `libsu` (`su` availability check).
   - SuKisu shows its per-app allow prompt on first use.
2. User sees a banner: "Root granted (uid=0)" or instructions.
3. App lists running apps (package names + labels) via `ActivityManager`.
4. User picks a target game.
5. Scan engine resolves the game's PID, enumerates readable `/proc/<pid>/maps`
   ranges, scans each for the metadata magic.
6. On hit: validate version (u32@+4 in 1..99), write the dump to the app's
   external files dir, then expose it via a Share sheet / file picker.

## 6. Data & outputs

| Item | Where | Notes |
|---|---|---|
| `global-metadata.decrypted.<va>.dat` | app external files (internal) | bytes from header VA, up to 16 MB |
| `libil2cpp.memorydump.so` | app external files (internal) | reassembled from readable mappings (`scanmem --bin`) |
| Export (auto) | `/storage/emulated/0/Documents/Il2CppDumps/<package>/` | root `cp`, canonical names `global-metadata.dat` + `libil2cpp.so`; copied immediately after each scan/dump |
| Share sheet | optional | FileProvider `content://` URIs (`ACTION_SEND_MULTIPLE`) |
| Scan log | app log | ranges scanned, hits, errors |

**M3 hardening (2026-08-05):** final audit before M4:
- helper asset ships **uncompressed** (`androidResources { noCompress += "scanmem" }`) so
  `AssetFileDescriptor` works and a size-based staleness check re-stages the
  binary only when it actually changed (no per-scan re-extract).
- no hardcoded pids/packages/VAs anywhere; all user-visible text is in
  `strings.xml`; dead resources removed.

## 7. Project layout (new, alongside the Python repo)

```
android/                        # sibling repo/folder, NOT mixed into dumpers/
├── settings.gradle.kts
├── build.gradle.kts
├── app/
│   ├── build.gradle.kts        # compose + libsu + ndk
│   ├── src/main/
│   │   ├── AndroidManifest.xml
│   │   ├── java/.../MainActivity.kt, AppListScreen.kt, ScanViewModel.kt
│   │   └── cpp/scan.cpp        # the ported scan engine
└── README.md                   # build + install + test steps
```

Keeping it as a separate `android/` folder keeps the pure-Python repo clean and
the experimental/ area intact.

## 8. Milestones (gradual)

| # | Milestone | Deliverable | Success check |
|---|---|---|---|
| M0 | Skeleton | Gradle project, Compose app that boots on device | app installs & runs |
| M1 | Root | `libsu` root check + banner | shows uid=0 on the rooted device |
| M2 | App list | running-app list → select | pick the target game |
| M3 | Scan engine (native) | `scanmem` helper: metadata magic scan + `libil2cpp.so` memory dump | ✅ finds decrypted metadata + ELF-valid `libil2cpp.memorydump.so` on a real game |
| M4 | Export | save .dat + share sheet | ✅ file lands in Documents, parses on PC with dump_game.py |
| M5 | Polish | progress, errors, robustness | repeatable, robust |

**M3 result (2026-08-05):** validated on two games with opposite memory layouts:

- `com.superpixel.undyinghero` — decrypted metadata lives in a **file-backed**
  mapping (mmap of its own `files/il2cpp/Metadata/global-metadata.dat`, `r--s`);
  the anon-only filter misses it. Scan finds `HIT 0x7182982000 v31`; binary dump
  reassembles a valid ELF64 AArch64 `libil2cpp.memorydump.so` (≈68 MB, entry
  point `0x18B3C3C` intact).
- `com.loadcomplete.minitales` — the classic LIKEY case: decrypted metadata
  exists only in **anonymous** memory (`[anon:libc_malloc]`), on-disk
  `global-metadata.dat` stays encrypted. Scan finds `HIT 0x71d3e59740 v31` (also
  caught with `--anon`); binary dump is a valid ELF64 DYN (≈90 MB, entry 0x0 as
  expected for a LIKEY-modified lib).

`scanmem` defaults to **all readable ranges** (≈3.7 GB scanned in ≈2.4 s on
device) with `--anon` as an opt-in restriction, so both layouts are covered by
the default path.

**M4 result (2026-08-05):** full chain validated end-to-end on Mini Tales:
- export is **automatic and direct** — `scanmem` itself writes the just-scanned
  metadata and just-dumped library straight into
  `Documents/Il2CppDumps/<package>/` (auto-creating the folder) under canonical
  names `global-metadata.dat` + `libil2cpp.so` (folder always holds exactly one
  pair; no accumulation of per-ASLR copies, no intermediate `files/dumps/`
  staging copy);
- "Share" opens the system share sheet with FileProvider-granted `content://`
  URIs (chooser observed, no crash);
- the exported folder feeds the PC parser with zero flags:
  `dump_game.py -g Documents/Il2CppDumps/<pkg>/` → `script.json`
  (214 588 methods), `dump.cs` (848k lines), `stringliteral.json`,
  `DummyDll/`. Acquisition is fully device-side; the PC only runs the parser.
- robustness note: a game process can exit while backgrounded (Gamebase closes
  on focus loss); a stale pid surfaces as a clean per-operation error, nothing
  is exported until the dump actually succeeds.

Each milestone is independently shippable; we stop after any of them if the
approach isn't panning out (e.g. M3 fails on the device → rethink acquisition).

## 9. Risks & mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Root prompt rejected / su quirks on SuKisu | app can't scan | libsu callback UI + clear instructions; test early (M1) |
| Game process not readable under /proc (hidepid / per-app isolation) | no ranges to scan | test on a real game in M3 before building UI polish |
| Performance of byte scan in C++ | slow UX | scan in chunks with mmap-style reads; only readable ranges |
| Metadata split across regions | wrong/partial dump | reuse dump_memory.py's scan-all approach; validate header first |
| Distributing a memory-scanning app | policy | sideload only; keep in a separate repo |

## 10. Decision gate

After M3, evaluate:

- Did the scan find the decrypted metadata on a real game on the rooted device? **✅ Yes** (Undying Hero, v31).
- Is the acquisition fast/robust enough to justify continuing? **✅ Yes** (≈2.4 s for a full readable scan; helper stages itself via `su`).

Decision: **continue to M4/M5**, then reassess the **full on-device dumper** (parse + browse).

---

## Appendix A — minimal C scan snippet (sketch)

```c
// scan.cpp — sketch only, to be fleshed out in M3
#define MAGIC 0xFAB11BAF
static int check_header(const uint8_t *p) {
    uint32_t m; memcpy(&m, p, 4);
    if (m != MAGIC) return 0;
    uint32_t v; memcpy(&v, p + 4, 4);
    return (v >= 1 && v <= 99) ? 1 : 0;
}
// ... enumerate /proc/<pid>/maps, open /proc/<pid>/mem, pread() per range,
// scan 4-byte aligned offsets, collect hits, write dump file.
```
