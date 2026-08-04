# Experimental

Work-in-progress scripts that are **not yet part of the supported toolkit**.
They live here so they stay version-controlled without affecting the main
`dumpers/`, `tools/`, or `tests/` layout or the README docs.

## Current contents

### `emulator_dump.py` — on hold

Wrapper that connects adb to a local Android emulator (Waydroid first;
LDPlayer / MuMu / BlueStacks pre-wired) and delegates the memory-scan logic
to `dump_memory.py` unchanged.

Status: **on hold** — the core logic works (verified against a simulated adb
device), but it needs real-device validation before it can be promoted to
`tools/`. When resuming:

```bash
python3 experimental/emulator_dump.py --package com.example.game --dump-binary
```

Move it back to `tools/` and re-document it in `docs/USAGE.md` + `README.md`
once validated.
