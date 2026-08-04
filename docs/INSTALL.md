# Installation Guide

This project is a pure-Python toolkit. The core dumpers need **only Python 3.8+**
with no third-party packages. Optional tools (`adb`, `frida`) are only needed for
the on-device / runtime scripts.

## 1. Prerequisites

| Tool | Version | Needed for | Optional? |
|---|---|---|---|
| Python | 3.8+ | Everything | required |
| `adb` (platform-tools) | any | `dumpers/dump_memory.py` (rooted-device memory dumps) | optional |
| `frida` + `frida-tools` | any | `dumpers/frida_il2cpp_dump.py`, `dumpers/likey_dump.py` (runtime dumps) | optional |
| IDA Pro | any | `tools/ida_annotate.py` (run inside IDA) | optional |
| Ghidra | any | `tools/ghidra_annotate.py` (run inside Ghidra) | optional |

### Install Python

- **Arch / CachyOS**: `sudo pacman -S python`
- **Debian / Ubuntu**: `sudo apt install python3`
- **macOS** (Homebrew): `brew install python`
- **Windows**: download from https://www.python.org/downloads/ (tick *"Add Python to PATH"*)

Verify:

```bash
python3 --version   # must be 3.8 or newer
```

## 2. Get the code

### Option A — clone from GitHub (recommended)

```bash
git clone https://github.com/nnk218/IL2CPP-Dumper-Python.git
cd IL2CPP-Dumper-Python
```

### Option B — download a release zip

Download the latest release from GitHub and extract it. (The repo layout is
identical either way.)

## 3. Optional: install as shell commands (pip)

Installing exposes `dump-game`, `dump-metadata`, and `dump-memory` as global
commands:

```bash
pip install .
```

> On some Linux distros (Arch, Debian 12+...) Python blocks system-wide pip
> installs (PEP 668). Use a virtual environment instead:
>
> ```bash
> python3 -m venv .venv
> source .venv/bin/activate     # Windows: .venv\Scripts\activate
> pip install .
> ```

Now you can run `dump-game ...` from anywhere. You can also keep running the
scripts directly with `python3 dumpers/dump_game.py ...` — both styles are
equivalent.

## 4. Optional: on-device tooling

Only needed if you plan to use `dump_memory.py` or the Frida dumpers.

### adb + a rooted phone (for `dump_memory.py`)

```bash
# Arch / CachyOS
sudo pacman -S android-tools

# Debian / Ubuntu
sudo apt install android-tools-adb

# macOS
brew install android-platform-tools
```

Then enable **USB debugging** on the phone and connect it. Root (Magisk /
KernelSU / SuKisu) is required for `dump_memory.py`.

### frida (for `frida_il2cpp_dump.py`)

```bash
pip install frida-tools
```

## 5. Prepare the input folders

The repo ships with a ready-made workflow layout (folders are kept in git,
their contents are git-ignored):

```
IL2CPP-Dumper-Python/
├── DumpPayload/          ← put your input files here
│   ├── apk/              ← .apk / .apkm / .xapk files
│   ├── lib/              ← libil2cpp.so
│   └── metadata/         ← global-metadata.dat
└── DumpResult/           ← dump output (created automatically)
```

Drop a game's files into `DumpPayload/` — see [USAGE.md](USAGE.md) for the
auto-discovery rules. You don't have to use these folders; any paths work with
the `-b` / `-m` / `-g` / `-o` flags.

## 6. Sanity check

```bash
# from the repo root
python3 tests/make_test_metadata.py
python3 tests/make_test_elf.py --bits 64
python3 tests/make_test_elf.py --bits 32
python3 tests/run_sweep.py        # expect: 10/10 passed
```

See [TESTING.md](TESTING.md) for details.

---

Next: [USAGE.md](USAGE.md) — how to dump a game and read the output.
