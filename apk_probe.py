#!/usr/bin/env python3
"""Probe a remote APK/APKM/XAPK's il2cpp metadata version WITHOUT downloading
the whole file.

Uses HTTP Range requests to fetch only:
  1. the end-of-central-directory + central directory (~64KB),
  2. the local file header + compressed bytes of global-metadata.dat (~3-5MB),
then inflates it and reads the metadata version (u32 at offset 4).

This lets you hunt games by version quickly: check a dozen download URLs in a
minute and only download the ones that are v33/v35.

Usage:
    python3 apk_probe.py <url> [<url> ...]
    python3 apk_probe.py <file.apk|.apkm|.xapk>     # local file also works

Note: the metadata version is the il2cpp metadata version, NOT the Unity
editor version. Map via SAMPLES.md (29=Unity2021, 31=Unity2022.1, 33=Unity2022.3,
35=Unity2023/Unity6, 39=Unity6).
"""

import argparse
import io
import struct
import sys
import urllib.request
import zipfile
import os

EOCD_SIG = b"\x50\x4b\x05\x06"          # end of central directory
LOCAL_SIG = b"\x50\x4b\x03\x04"          # local file header
CENTRAL_SIG = b"\x50\x4b\x01\x02"        # central directory file header
MAGIC = 0xFAB11BAF

CHUNK = 65536  # initial fetch (EOCD + central dir)


def fetch_range(url, start, length):
    """Fetch bytes [start, start+length) via HTTP Range. Returns bytes."""
    req = urllib.request.Request(url)
    req.add_header("Range", "bytes=%d-%d" % (start, start + length - 1))
    req.add_header("User-Agent", "Mozilla/5.0")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read()
    except urllib.error.HTTPError as e:
        if e.code == 416:
            return b""
        raise


def get_size(url):
    """Get total file size from a HEAD request (or a 0-byte range)."""
    req = urllib.request.Request(url, method="HEAD")
    req.add_header("User-Agent", "Mozilla/5.0")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return int(resp.headers.get("Content-Length", 0))
    except Exception:
        pass
    # fallback: request first byte, read Content-Range
    try:
        data = fetch_range(url, 0, 1)
        return 0
    except Exception:
        return 0


def parse_eocd(tail):
    """Find EOCD in the tail bytes; return (cd_offset, cd_size, total_entries)."""
    idx = tail.rfind(EOCD_SIG)
    if idx == -1:
        return None
    # EOCD: sig(4) disk(2) cd_disk(2) disk_entries(2) total_entries(2) cd_size(4) cd_offset(4) comment_len(2)
    cd_size = struct.unpack_from("<I", tail, idx + 12)[0]
    cd_offset = struct.unpack_from("<I", tail, idx + 16)[0]
    return cd_offset, cd_size


def find_metadata_in_cd(cd_bytes):
    """Scan central directory for global-metadata.dat entry.
    Returns (local_header_offset, compressed_size, file_size, compress_type) or None."""
    pos = 0
    while pos + 46 <= len(cd_bytes):
        if cd_bytes[pos:pos + 4] != CENTRAL_SIG:
            break
        flags = struct.unpack_from("<H", cd_bytes, pos + 8)[0]
        method = struct.unpack_from("<H", cd_bytes, pos + 10)[0]
        csize, usize = struct.unpack_from("<II", cd_bytes, pos + 20)
        name_len, extra_len, comment_len = struct.unpack_from("<HHH", cd_bytes, pos + 28)
        lho = struct.unpack_from("<I", cd_bytes, pos + 42)[0]
        name = cd_bytes[pos + 46: pos + 46 + name_len].decode("utf-8", "replace")
        if name.endswith("global-metadata.dat"):
            return lho, csize, usize, method
        pos += 46 + name_len + extra_len + comment_len
    return None


def read_local_metadata(url, lho, csize, usize, method, size):
    """Fetch the local header + compressed data at lho and inflate to get bytes.
    Returns the raw bytes (enough to read the version)."""
    # local file header is at least 30 bytes; add name+extra lengths from header
    head = fetch_range(url, lho, 64)
    if len(head) < 30 or head[:4] != LOCAL_SIG:
        return None
    name_len, extra_len = struct.unpack_from("<HH", head, 26)
    data_start = lho + 30 + name_len + extra_len
    fetch_len = min(csize, 64 * 1024 * 1024)
    data = fetch_range(url, data_start, fetch_len)
    if not data:
        return None
    try:
        if method == 0:  # stored
            return data[:usize]
        if method == 8:  # deflate
            import zlib
            return zlib.decompress(data[:csize], -15)
    except Exception:
        return None
    return None


def _probe_url_recursive(url, size, depth=0):
    """Probe a remote zip (URL) for global-metadata.dat, recursing into nested
    .apk/.zip entries (APKM/XAPK wrap base.apk)."""
    if depth > 3:
        return None, "too deep"
    tail_start = max(0, size - CHUNK) if size else 0
    tail = fetch_range(url, tail_start, CHUNK)
    if not tail:
        return None, "could not fetch tail"
    eocd = parse_eocd(tail)
    if not eocd:
        return None, "could not parse EOCD"
    cd_offset, cd_size = eocd
    cd = fetch_range(url, cd_offset, cd_size)
    if not cd:
        return None, "could not fetch central directory"
    # 1) direct global-metadata.dat
    meta = find_metadata_in_cd(cd)
    if meta:
        lho, csize, usize, method = meta
        raw = read_local_metadata(url, lho, csize, usize, method, size)
        if not raw:
            return None, "could not read/inflate global-metadata.dat"
        v = version_from_metadata(raw)
        return v, "direct"
    # 2) nested apk/zip -> fetch + inflate it, recurse
    nested = find_nested_archive(cd)
    if not nested:
        return None, "no global-metadata.dat in archive"
    lho, csize, usize, method = nested
    raw = read_local_metadata(url, lho, csize, usize, method, size)
    if not raw:
        return None, "could not read nested archive"
    # raw is now an in-memory zip -> probe it as a "local" source
    return _probe_bytes(raw, depth + 1)


def find_nested_archive(cd):
    """Find a .apk/.zip/.aab entry in the central directory.
    Returns (lho, csize, usize, method) or None."""
    pos = 0
    while pos + 46 <= len(cd):
        if cd[pos:pos + 4] != CENTRAL_SIG:
            break
        method = struct.unpack_from("<H", cd, pos + 10)[0]
        csize, usize = struct.unpack_from("<II", cd, pos + 20)
        name_len, extra_len, comment_len = struct.unpack_from("<HHH", cd, pos + 28)
        lho = struct.unpack_from("<I", cd, pos + 42)[0]
        name = cd[pos + 46: pos + 46 + name_len].decode("utf-8", "replace")
        if name.lower().endswith((".apk", ".zip", ".aab")):
            return lho, csize, usize, method
        pos += 46 + name_len + extra_len + comment_len
    return None


def _probe_bytes(raw, depth=0):
    """Probe an in-memory zip (bytes) for global-metadata.dat, recursing into
    nested archives. raw must be a complete zip file."""
    if depth > 3:
        return None, "too deep"
    try:
        z = zipfile.ZipFile(io.BytesIO(raw))
        for info in z.infolist():
            if info.filename.endswith("global-metadata.dat"):
                v = version_from_metadata(z.read(info))
                return v, "nested"
        for info in z.infolist():
            if info.filename.lower().endswith((".apk", ".zip", ".aab")):
                return _probe_bytes(z.read(info), depth + 1)
    except Exception as e:
        return None, str(e)
    return None, "no global-metadata.dat"


def version_from_metadata(raw):
    if len(raw) < 8:
        return None
    magic = struct.unpack_from("<I", raw, 0)[0]
    if magic != MAGIC:
        return None
    return struct.unpack_from("<I", raw, 4)[0]


def probe_source(src):
    """src: a URL or a local file path. Returns (version_or_None, detail)."""
    is_url = src.startswith("http://") or src.startswith("https://")
    if is_url:
        size = get_size(src)
        if size <= 0:
            return None, "could not determine size (no Range support?)"
        v, detail = _probe_url_recursive(src, size)
        return v, "url"
    else:
        # local file
        try:
            with open(src, "rb") as f:
                raw = f.read()
            v, detail = _probe_bytes(raw)
            return v, detail
        except Exception as e:
            return None, str(e)


def main():
    ap = argparse.ArgumentParser(description="Probe il2cpp metadata version "
                                            "without full download.")
    ap.add_argument("targets", nargs="+", help="APK/APKM/XAPK URLs or local files")
    args = ap.parse_args()
    for t in args.targets:
        v, detail = probe_source(t)
        if v is not None:
            print("%-70s -> metadata version %d" % (os.path.basename(t)[:70], v))
        else:
            print("%-70s -> FAILED (%s)" % (os.path.basename(t)[:70], detail))


if __name__ == "__main__":
    main()
