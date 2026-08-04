#!/usr/bin/env python3
"""Frida script: locate & dump the DECRYPTED global-metadata.dat from a
running Unity/il2cpp game whose metadata is LIKEY-protected.

Why: PADumper dumps global-metadata.dat from the APK (disk), which is still
LIKEY-encrypted. The game decrypts it into a separate in-memory buffer at load
time. This script scans process memory for the decrypted header magic
(0xFAB11BAF = bytes AF 1B B1 FA) and dumps the surrounding buffer.

Usage:
    frida -U -f com.loadcomplete.minitales -l likey_dump.py   # fresh launch
    frida -U -p <PID> -l likey_dump.py                         # attach to running

Outputs are written to /data/local/tmp/likey_dump/ on the device.
"""

import frida
import sys

SCRIPT = r"""
'use strict';

var MAGIC_U32 = 0xFAB11BAF;
var OUTDIR = "/data/local/tmp/likey_dump";

function plausible(buf, off) {
    var ver = buf.readU32(off + 4);
    if (ver < 1 || ver > 99) return false;
    var first = buf.readU32(off + 8);
    if (first >= (1 << 28)) return false;
    return true;
}

function scanRange(base, size, out) {
    // scan every 4-byte aligned offset for the magic, then validate header
    var aligned = base.and(3);
    var start = aligned.toUInt32() === 0 ? 0 : (4 - aligned.toUInt32());
    for (var off = start; off + 12 < size; off += 4) {
        var p = base.add(off);
        if (p.readU32() === MAGIC_U32) {
            if (plausible(p, 0)) {
                out.push(p);
            }
        }
    }
}

function main() {
    send("attached; scanning process memory for decrypted metadata...");
    var ranges = Process.enumerateRanges('r--');
    var hits = [];
    ranges.forEach(function (r) {
        // skip the known-encrypted APK-backed file region is unnecessary;
        // just scan readable ranges. Guard against very large sizes.
        if (r.size > 0x40000000) return;
        try {
            scanRange(r.base, r.size, hits);
        } catch (e) { /* unreadable range */ }
    });
    send("found " + hits.length + " candidate magic buffers");
    var seen = {};
    hits.forEach(function (addr, i) {
        try {
            // estimate size: metadata files are ~10-30MB; look for a sane size
            // by scanning forward for the end (another copy) or cap at 32MB.
            var ver = addr.add(4).readU32();
            var len = Math.min(0x2000000, 32 * 1024 * 1024);
            var mem = addr.readByteArray(len);
            var fn = OUTDIR + "/global-metadata.decrypted." + addr.toString() + ".dat";
            var f = new File(fn, "wb");
            f.write(mem);
            f.close();
            send("wrote " + fn + " (version " + ver + ", " + len + " bytes)");
        } catch (e) {
            send("err " + addr + ": " + e);
        }
    });
    send("done");
}

setTimeout(main, 300);
"""


def main():
    if len(sys.argv) < 2:
        print("usage: python3 likey_dump.py <package|PID>")
        sys.exit(1)
    target = sys.argv[1]
    dev = frida.get_usb_device(timeout=15)
    if target.isdigit():
        session = dev.attach(int(target))
    else:
        pid = dev.spawn([target])
        session = dev.attach(pid)
        dev.resume(pid)
    script = session.create_script(SCRIPT)
    script.on("message", lambda msg, data: print(msg.get("payload", msg)))
    script.load()
    sys.stdin.read()


if __name__ == "__main__":
    main()
