#!/usr/bin/env python3
"""Root-based on-device memory scanner (no Frida required).

Reads a rooted Android device's process memory via /proc/<pid>/mem over adb,
scans for the decrypted il2cpp metadata header (magic 0xFAB11BAF = bytes
AF 1B B1 FA), and dumps the surrounding buffer.

Why: LIKEY-protected games keep the *decrypted* global-metadata.dat only in
process memory. Tools like PADumper dump the file from the APK (still
encrypted). This script finds the in-memory plaintext.

Prereqs (no app installs on the phone):
  - rooted phone, USB debugging enabled
  - `adb` on the PC, device authorized (`adb devices` shows device)
  - root available via `su`

Usage:
    python3 dump_memory.py --package com.loadcomplete.minitales
    python3 dump_memory.py --pid 21231
    python3 dump_memory.py --package com.loadcomplete.minitales --size 0x1000000

The decrypted metadata is dumped to ./likey_dump/global-metadata.decrypted.<va>.dat
"""

import argparse
import os
import re
import shutil
import struct
import subprocess
import sys

MAGIC = b"\xAF\x1B\xB1\xFA"  # 0xFAB11BAF little-endian
DEFAULT_SIZE = 0x1000000      # 16 MB cap for a metadata dump

ADB = None


def _find_adb():
    """Locate adb: --adb flag > ADB env var > PATH > common SDK locations."""
    for cand in (ADB, os.environ.get("ADB"),
                 shutil.which("adb"),
                 os.path.expanduser("~/Android/Sdk/platform-tools/adb"),
                 os.path.expanduser("~/android-sdk/platform-tools/adb"),
                 "/opt/android-sdk/platform-tools/adb",
                 "/usr/lib/android-sdk/platform-tools/adb"):
        if cand and os.path.exists(cand):
            return cand
    return None


def run_adb(args, su=True):
    """Run an adb shell command; returns (returncode, stdout_bytes).
    Tries 'su -c' then 'su 0 -c' then 'su root -c' (device su variants)."""
    adb = _find_adb()
    if adb is None:
        print("error: adb not found on this PC.", file=sys.stderr)
        print("  Install platform-tools (https://developer.android.com/tools/adb)", file=sys.stderr)
        print("  or set ADB=/path/to/adb, or pass --adb /path/to/adb", file=sys.stderr)
        sys.exit(2)
    if not su:
        p = subprocess.run([adb, "shell", args], capture_output=True)
        return p.returncode, p.stdout
    for su_prefix in ("su -c", "su 0 -c", "su root -c"):
        p = subprocess.run([adb, "shell", su_prefix, args], capture_output=True)
        if p.returncode == 0 and p.stdout.strip():
            return p.returncode, p.stdout
    return p.returncode, p.stdout


def find_pid(package):
    """Locate the game's PID using several methods (device su variants differ)."""
    candidates = []
    # method 1: pidof via su
    rc, out = run_adb("pidof %s" % package)
    if out.strip():
        candidates.extend(out.split())
    # method 2: pgrep via su (both -f full match and plain)
    for pat in ("pgrep -f '%s'" % package, "pgrep -l %s" % package,
                "pgrep -x %s" % package):
        rc, out = run_adb(pat)
        if out.strip():
            for tok in out.split():
                try:
                    candidates.append(str(int(tok)))
                except ValueError:
                    pass
    # method 3: scan /proc for cmdline == package (works even if pidof/pgrep
    # aren't present in the su shell, or the process is multi-UID)
    rc, out = run_adb("for p in /proc/[0-9]*; do "
                      "tr -d '\\0' < $p/cmdline 2>/dev/null | grep -q '%s' && "
                      "echo ${p#/proc/}; done" % package)
    if out.strip():
        candidates.extend(out.split())

    seen = set()
    for c in candidates:
        if c not in seen:
            seen.add(c)
            try:
                return int(c)
            except ValueError:
                pass
    print("error: could not find PID for %s (is the game running?)" % package)
    print("  if the game is open, the device's su may differ; try:", file=sys.stderr)
    print("    adb shell su -c 'ps -A | grep %s'" % package, file=sys.stderr)
    sys.exit(1)


def get_maps(pid):
    rc, out = run_adb("cat /proc/%d/maps" % pid)
    if rc != 0 or not out:
        print("error: could not read /proc/%d/maps (need root)" % pid)
        sys.exit(1)
    ranges = []
    for line in out.decode("utf-8", "replace").splitlines():
        # e.g. "7190202000-719577f000 r--p 00000000 fd:00 1234 /path"
        m = re.match(r"^([0-9a-f]+)-([0-9a-f]+)\s+(\S{4})\s+\S+\s+\S+\s+\S+\s*(.*)$", line)
        if not m:
            continue
        start = int(m.group(1), 16)
        end = int(m.group(2), 16)
        perms = m.group(3)
        path = m.group(4).strip()
        ranges.append({"start": start, "end": end, "perms": perms, "path": path})
    return ranges


def read_exact(pid, start, size):
    """Read exactly `size` bytes starting at `start` (byte-granular), even when
    start is not page-aligned. Uses bs=1 so the offset is preserved."""
    adb = _find_adb()
    if size <= 0:
        return b""
    dd = ("dd if=/proc/%d/mem bs=1 skip=%d count=%d 2>/dev/null"
          % (pid, start, size))
    for su_prefix in ("su", "su 0", "su root"):
        p = subprocess.run([adb, "exec-out", su_prefix, "-c", dd], capture_output=True)
        if p.stdout:
            return p.stdout
    return p.stdout


def read_range(pid, start, end):
    """Stream a process memory range to the PC via adb exec-out + dd.
    Handles small reads (dd count is in bs units; a <4K read needs bs=1)."""
    adb = _find_adb()
    size = end - start
    if size <= 0:
        return b""
    if size < 4096:
        # small read: byte-granular so we don't lose the offset
        dd = ("dd if=/proc/%d/mem bs=1 skip=%d count=%d 2>/dev/null"
              % (pid, start, size))
    else:
        bs = 4096
        count = size // bs
        dd = ("dd if=/proc/%d/mem bs=%d skip=%d count=%d 2>/dev/null"
              % (pid, bs, start // bs, count))
    for su_prefix in ("su", "su 0", "su root"):
        p = subprocess.run([adb, "exec-out", su_prefix, "-c", dd], capture_output=True)
        if p.stdout:
            return p.stdout
    return p.stdout


def scan_for_magic(data, base_va):
    hits = []
    off = 0
    while True:
        off = data.find(MAGIC, off)
        if off == -1:
            break
        va = base_va + off
        # validate the header: version u32 at +4 must be 1..99
        if off + 8 <= len(data):
            ver = struct.unpack_from("<I", data, off + 4)[0]
            if 1 <= ver <= 99:
                hits.append((va, ver))
        off += 1
    return hits


def main():
    ap = argparse.ArgumentParser(description="Scan rooted device memory for "
                                            "decrypted il2cpp metadata (no Frida).")
    ap.add_argument("--package", help="game package name, e.g. com.loadcomplete.minitales")
    ap.add_argument("--pid", type=int, help="process PID (alternative to --package)")
    ap.add_argument("--adb", help="path to adb binary (default: search PATH + SDK dirs)")
    ap.add_argument("--size", type=lambda s: int(s, 0), default=DEFAULT_SIZE,
                    help="bytes to dump from the found header (default 0x1000000)")
    ap.add_argument("--dump-binary", action="store_true",
                    help="also dump libil2cpp.so from memory (relocations applied)")
    ap.add_argument("--out", default="likey_dump", help="output directory")
    args = ap.parse_args()

    global ADB
    ADB = args.adb

    if not args.package and not args.pid:
        ap.error("provide --package or --pid")
    if _find_adb() is None:
        print("error: adb not found. Install platform-tools or set --adb <path>.", file=sys.stderr)
        sys.exit(2)

    # confirm a device is connected before anything else
    adb = _find_adb()
    p = subprocess.run([adb, "devices"], capture_output=True, text=True)
    print(p.stdout.strip())
    lines = [l for l in p.stdout.splitlines()[1:]
             if l.strip() and "device" in l and "unauthorized" not in l
             and "offline" not in l and "no permissions" not in l]
    if not lines:
        print("error: no authorized adb device. Check USB debugging + accept the",
              "prompt on the phone (adb devices should list it as 'device').",
              file=sys.stderr)
        sys.exit(1)

    pid = args.pid if args.pid else find_pid(args.package)
    print("[*] scanning PID %d" % pid)

    # quick root check
    rc, out = run_adb("id")
    if rc != 0 or b"root" not in out:
        print("warning: su did not report root; scanning may fail")

    ranges = get_maps(pid)
    # keep readable ranges; prefer anonymous/heap, fall back to all 'r'
    anon = [r for r in ranges if "r" in r["perms"] and
            (not r["path"] or r["path"].startswith("["))]
    print("[*] %d readable anonymous ranges (%d total)" % (len(anon), len(ranges)))

    found = []
    for i, r in enumerate(anon):
        size = r["end"] - r["start"]
        if size <= 0 or size > 0x40000000:
            continue
        data = read_range(pid, r["start"], r["end"])
        if not data:
            continue
        hits = scan_for_magic(data, r["start"])
        for va, ver in hits:
            print("[+] header at VA 0x%x (version %d) in %s" % (va, ver, r["path"] or "<anon>"))
            found.append((va, ver))
        if i % 50 == 0:
            print("[*] scanned %d/%d ranges" % (i + 1, len(anon)), flush=True)

    if not found:
        print("[-] no decrypted metadata header found. Is the game fully loaded?")
        print("    Try running with the game past the title screen, or rerun.")
        sys.exit(1)

    os.makedirs(args.out, exist_ok=True)
    for va, ver in found:
        # dump args.size bytes starting exactly at the header VA so the magic
        # lands at offset 0 of the file
        blob = read_exact(pid, va, args.size)[:args.size]
        fn = os.path.join(args.out, "global-metadata.decrypted.%x.dat" % va)
        with open(fn, "wb") as f:
            f.write(blob)
        print("[+] wrote %s (%d bytes, version %d)" % (fn, len(blob), ver))
    if args.dump_binary:
        dump_binary(pid, ranges, args.out)
    print("[+] done. Feed the file to dump_game.py with -b/-m.")


def dump_binary(pid, maps, outdir):
    """Dump libil2cpp.so from memory into a contiguous file.

    Uses the actual mapped ranges from /proc/<pid>/maps: each mapping tells us
    its VA range AND its file offset, so we read memory at the (readable) VA
    and place it at the correct file offset. This recovers relocation-applied
    data that reloc-stripped APK copies lack, and works even when the loader
    mapped segments non-contiguously.
    """
    lib_ranges = [r for r in maps
                  if "libil2cpp.so" in r["path"] and "r" in r["perms"]]
    if not lib_ranges:
        print("[-] libil2cpp.so not mapped", file=sys.stderr)
        return None
    # maps line format: start-end perms offset dev inode path
    # we need the file offset -> parse the raw maps again
    adb = _find_adb()
    rc, out = run_adb("cat /proc/%d/maps" % pid)
    if rc != 0:
        print("[-] could not re-read maps", file=sys.stderr)
        return None
    entries = []
    for line in out.decode("utf-8", "replace").splitlines():
        if "libil2cpp.so" not in line:
            continue
        m = re.match(r"^([0-9a-f]+)-([0-9a-f]+)\s+(\S{4})\s+([0-9a-f]+)\s+\S+\s+\S+\s+(.*)$", line)
        if not m:
            continue
        start = int(m.group(1), 16)
        end = int(m.group(2), 16)
        perms = m.group(3)
        foff = int(m.group(4), 16)
        if "r" in perms:
            entries.append((start, end, foff))
    if not entries:
        print("[-] no readable libil2cpp.so mappings", file=sys.stderr)
        return None
    total = max(foff + (end - start) for _, end, foff in entries)
    buf = bytearray(total)
    print("[*] dumping %d libil2cpp.so mappings, file size ~0x%x" % (len(entries), total))
    for start, end, foff in sorted(entries, key=lambda e: e[0]):
        size = end - start
        mem = read_range(pid, start, end)
        if not mem:
            print("  - short read for VA 0x%x" % start, file=sys.stderr)
            continue
        buf[foff:foff + len(mem)] = mem[:size]
    # ensure it's still a valid ELF
    if buf[:4] != b"\x7fELF":
        print("[-] dumped buffer is not a valid ELF (first bytes: %r)" % bytes(buf[:4]), file=sys.stderr)
    outdir = outdir or "likey_dump"
    os.makedirs(outdir, exist_ok=True)
    fn = os.path.join(outdir, "libil2cpp.memorydump.so")
    with open(fn, "wb") as f:
        f.write(buf)
    print("[+] wrote %s (%d bytes)" % (fn, len(buf)))
    return fn


if __name__ == "__main__":
    main()
