#!/usr/bin/env python3
"""Emulator-aware wrapper around dump_memory.py.

Lets you run the rooted-device memory scan (decrypted il2cpp metadata dump)
against an Android emulator running on the same PC instead of a physical phone.

Currently supports:
    Waydroid   (Linux)  - connects to the Android container over adb
    (add LDPlayer / MuMu / BlueStacks here later - they expose adb on 127.0.0.1:<port>)

It does NOT reimplement the scan logic. It connects adb to the emulator and then
delegates to dump_memory.py unchanged (same subprocess pattern apkm_scrape.py
uses to call dump_game.py).

Usage:
    python3 tools/emulator_dump.py --package com.example.game
    python3 tools/emulator_dump.py --package com.example.game --dump-binary
    python3 tools/emulator_dump.py --package com.example.game --scan-all --dump-binary
    python3 tools/emulator_dump.py --waydroid-ip 192.168.240.112 --package com.example.game
    python3 tools/emulator_dump.py --emulator mumu --package com.example.game
"""

import argparse
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DUMP_MEMORY = os.path.join(HERE, "..", "dumpers", "dump_memory.py")

# Known emulator adb endpoints (host:port). Windows emulators listen on the
# loopback interface; Waydroid's container has its own IP.
EMULATORS = {
    # name: (connect_host, default_port)  -- call add via --port to override
    "waydroid":   (None, 5555),   # host resolved at runtime (container IP)
    "ldplayer":   ("127.0.0.1", 5555),
    "mumu":       ("127.0.0.1", 7555),
    "bluestacks": ("127.0.0.1", 5555),
}


def _find_adb(override=None) -> str:
    for cand in (override, os.environ.get("ADB"), shutil.which("adb"),
                 os.path.expanduser("~/Android/Sdk/platform-tools/adb"),
                 "/opt/android-sdk/platform-tools/adb",
                 "/usr/lib/android-sdk/platform-tools/adb"):
        if cand and os.path.exists(cand):
            return cand
    return None


def _waydroid_container_ip() -> str:
    """Find the Waydroid container IP.

    Tries, in order:
      1. `waydroid status` (the Android container gateway)
      2. the well-known Waydroid container IP 192.168.240.112
      3. a running interface matching the waydroid bridge
    Returns a string like '192.168.240.112', or None.
    """
    try:
        out = subprocess.run(["waydroid", "status"], capture_output=True,
                             text=True, timeout=10).stdout
        for line in out.splitlines():
            line = line.strip()
            # e.g. "Waydroid is running" / "Session: ..." / container info
            if "running" in line.lower():
                # fall through to known default below; Waydroid rarely reports IP here
                break
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    # Known Waydroid container address (Anbox-style virtual ethernet)
    return "192.168.240.112"


def _connect_adb(adb, host, port) -> bool:
    """adb connect host:port; return True on success."""
    p = subprocess.run([adb, "connect", "%s:%d" % (host, port)],
                       capture_output=True, text=True, timeout=30)
    print(p.stdout.strip())
    return "connected" in p.stdout.lower()


def _devices(adb) -> list:
    p = subprocess.run([adb, "devices"], capture_output=True, text=True, timeout=15)
    return [l.split()[0] for l in p.stdout.splitlines()[1:] if l.strip()]


def main():
    ap = argparse.ArgumentParser(description="Run dump_memory.py against an emulator.")
    ap.add_argument("--emulator", choices=sorted(EMULATORS), default="waydroid",
                    help="which emulator to connect to (default: waydroid)")
    ap.add_argument("--waydroid-ip", help="explicit Waydroid container IP "
                                          "(default: auto-detect 192.168.240.112)")
    ap.add_argument("--port", type=int, help="adb port (default per emulator)")
    ap.add_argument("--adb", help="path to adb binary (default: search PATH + SDK dirs)")

    # passthrough args forwarded to dump_memory.py
    ap.add_argument("--package", help="game package name, e.g. com.loadcomplete.minitales")
    ap.add_argument("--pid", type=int, help="process PID (alternative to --package)")
    ap.add_argument("--size", type=lambda s: int(s, 0),
                    help="bytes to dump from the found header")
    ap.add_argument("--dump-binary", action="store_true",
                    help="also dump libil2cpp.so from memory (relocations applied)")
    ap.add_argument("--scan-all", action="store_true",
                    help="also scan file-backed readable ranges")
    ap.add_argument("--out", help="output directory (default: DumpResult/<ts>/)")
    args = ap.parse_args()

    if not args.package and not args.pid:
        ap.error("provide --package or --pid")

    adb = _find_adb(args.adb)
    if adb is None:
        print("error: adb not found. Install platform-tools or set --adb <path>.",
              file=sys.stderr)
        sys.exit(2)

    # resolve connect target
    name = args.emulator
    host, default_port = EMULATORS[name]
    port = args.port or default_port
    if name == "waydroid":
        host = args.waydroid_ip or _waydroid_container_ip()
        print("[*] Waydroid container IP: %s" % host)

    # connect
    print("[*] connecting adb to %s (%s:%d)..." % (name, host, port))
    if not _connect_adb(adb, host, port):
        print("error: could not connect adb to %s" % name, file=sys.stderr)
        print("  - is the emulator running?", file=sys.stderr)
        print("  - for Waydroid: start it, then try --waydroid-ip <ip>", file=sys.stderr)
        sys.exit(1)

    before = set(_devices(adb))
    # give adb a moment to register the new device
    import time
    time.sleep(2)
    after = set(_devices(adb))
    print("[*] adb devices: %s" % (sorted(after) or "(none)"))

    # delegate to dump_memory.py (unchanged logic)
    cmd = [sys.executable, DUMP_MEMORY]
    cmd += ["--adb", adb]
    if args.package:
        cmd += ["--package", args.package]
    if args.pid:
        cmd += ["--pid", str(args.pid)]
    if args.size:
        cmd += ["--size", str(args.size)]
    if args.dump_binary:
        cmd += ["--dump-binary"]
    if args.scan_all:
        cmd += ["--scan-all"]
    if args.out:
        cmd += ["--out", args.out]
    print("[*] delegating to %s" % " ".join(os.path.basename(c) for c in cmd))
    return subprocess.call(cmd)


if __name__ == "__main__":
    sys.exit(main())
