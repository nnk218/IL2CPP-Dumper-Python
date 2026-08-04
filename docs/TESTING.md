# Testing

The repo includes a self-contained regression suite built from **synthetic
fixtures** (no real game files needed). It verifies the dumper across:

- **bits**: 64-bit and 32-bit ELF
- **metadata**: plain and XOR-protected
- **lookup path**: symbol search and section scan

## Run the tests

```bash
# 1. generate the synthetic metadata fixtures (into tests/fixtures/)
python3 tests/make_test_metadata.py

# 2. generate the synthetic ELF fixtures
python3 tests/make_test_elf.py --bits 64
python3 tests/make_test_elf.py --bits 32

# 3. run the full sweep
python3 tests/run_sweep.py
```

Expected final output:

```
========================================
10/10 passed
```

## What the sweep checks

For each of the 10 fixture combinations, `run_sweep.py` verifies that:

1. `dump_game.py` exits 0,
2. `script.json` parses and reports the expected method/string/metadata counts,
3. a second identical run reproduces byte-identical output (deterministic).

## CI

The repository runs the sweep automatically on every push / PR to `main`
via GitHub Actions (`.github/workflows/sweep.yml`), so regressions are caught
before they land.
