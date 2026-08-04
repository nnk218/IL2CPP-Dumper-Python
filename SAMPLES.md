# Gathering test samples across il2cpp versions

This project is validated on metadata **v31** and **v39**. To harden it across the
full range Unity has shipped, we want at least one real pair per version below.

There is **no curated public repo** of ready-made `libil2cpp.so` +
`global-metadata.dat` pairs (game binaries are large and proprietary). The
practical way to gather samples is to download old APK versions of long-running
games from **APKMirror** / **APKPure**, which keep every released version.

## Unity version -> metadata version

Use this to pick which APK you need. `Metadata Version` is what
`dump_metadata.py` prints.

| Metadata version | Unity editor | Notes |
|---|---|---|
| 24.0 | 2018.2 | 32/64-bit pointer layouts |
| 24.1 | 2018.3 | |
| 24.2 | 2018.4 | |
| 24.3 | 2019.1 | |
| 24.4 | 2019.2 | |
| 24.5 | 2019.3 | |
| 27.0 | 2019.4 | long-term support, very common |
| 27.1 | 2020.1 | |
| 27.2 | 2020.2 / 2020.3 | |
| 29.0 | 2021.1 / 2021.2 | |
| 29.1 | 2021.3 | common |
| 31 | 2022.1 / 2022.2 | *we have Mini Tales v31* |
| 33 | 2022.3 | common |
| 35 | 2023.x / Unity 6 early | |
| 39 | Unity 6 | *we have two v39 games* |

## How to find a game for a specific version

1. On APKMirror, pick a **long-running** game (updated for years) so its old
   versions cover multiple Unity versions. Candidates that have been updated
   across the 2019–2024 range: idle/MMO games, e.g. **Rise of Kingdoms,
   Last War, Evony, AFK Arena** (verify — use their version history).
2. Open the game's page → "All versions" / "Download older versions".
3. Pick a version from the era of the Unity version you need (see table).
4. Download the APK, put it in `samples/`, then validate:

```bash
python3 dump_game.py -g samples/<game>.apk -o out/     # auto-extracts + dumps
# the log shows "using il2cpp version X.Y" — that's the metadata version
```

If the metadata is protected (`LIKEY`, etc.), use `dump_memory.py` on a running
device as documented in the README.

## Validating a new pair

A sample "passes" if `dump_game.py`:
1. finds both `libil2cpp.so` and `global-metadata.dat`,
2. locates `CodeRegistration` + `MetadataRegistration`,
3. writes a `script.json` with non-zero methods/strings/addresses.

```bash
python3 dump_game.py -b <lib> -m <metadata> -o out/
python3 dump_game.py -g samples/<game>.apk -o out/
```

## Tracking coverage

Keep a note of which versions are validated. Current status:

| Version | Status |
|---|---|
| 24.2 | validated (Subway Surfers 2.7.0) |
| 24.4/24.5 | validated (Subway Surfers 2.30.0) |
| 27 | validated (Subway Surfers 3.0.1) |
| 29 | validated (Merge Decor, Royal Match 19371, Royal Match 27161) |
| 31 | validated (Mini Tales, Royal Match 31863, Royal Match 32984) |
| 39 | validated (two games) |
| 33 | not yet |
| 35 | not yet |

When you add a new validated version, update this table and commit.
