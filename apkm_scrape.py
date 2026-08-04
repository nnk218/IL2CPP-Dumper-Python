#!/usr/bin/env python3
"""Scrape APKMirror for a game's download URLs and probe their il2cpp metadata
version, without downloading whole APKs.

APKMirror's download flow is a chain of 4 pages/requests:
  1.  release page  -> lists variants ("Download" buttons)
  2.  variant page  -> holds the real "Download APK" button linking to
                      /.../download/?key=<k1>
  3.  ?key=<k1>     -> "thank you / download starting" interstitial which holds
                      /wp-content/themes/APKMirror/download.php?id=<n>&key=<k2>
  4.  download.php  -> 302-redirects to the real CDN URL (downloadr2...)

The CDN URL supports HTTP Range requests, so we only fetch the zip tail +
central directory + the compressed global-metadata.dat blob (a few MB max)
and inflate it to read the metadata version.

This is essentially apk_probe.py plus a cookie-session scraper for the CDN
URL chain. Cookie handling + realistic headers + delays between hops keep us
under APKMirror's bot rate-limits (429).

Usage:
    python3 apkm_scrape.py "royal match"
    python3 apkm_scrape.py --release https://www.apkmirror.com/apk/.../release/
    python3 apkm_scrape.py --variant  https://www.apkmirror.com/apk/.../android-apk-download/
    python3 apkm_scrape.py --probe-only "https://downloadr2.apkmirror.com/.../file.apk"
"""

import argparse
import http.cookiejar
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

import apk_probe

UA = ("Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0 "
      "Floorp/11.24.0")
BASE = "https://www.apkmirror.com"
HOP_DELAY = float(4)          # seconds between page hops (avoid 429)
REQUEST_DELAY = float(0.5)    # extra delay between probe range requests

KEY_RE = re.compile(r"href=\"(/apk/[^\"\s]*download/\?key=[0-9a-f]+)\"")
PHP_RE = re.compile(
    r"href=\"(/wp-content/themes/APKMirror/download\.php\?id=\d+&key=[0-9a-f]+)\"")
VARIANT_RE = re.compile(
    r"href=\"(/apk/[^\"\s]*android-apk-download/)\"")
RELEASE_RE = re.compile(r"href=\"(/apk/[^\"\s]+?-release/)\"")

_ctx = ssl.create_default_context()


def make_opener():
    cj = http.cookiejar.CookieJar()
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cj),
        urllib.request.HTTPSHandler(context=_ctx),
    )


MAX_RETRIES = 6


def get(opener, url, ref=None, retries=MAX_RETRIES):
    """GET a page, returning the response object (redirects auto-followed).
    Retries with backoff on 429 / 5xx (APKMirror rate-limits bots hard)."""
    req = urllib.request.Request(url)
    req.add_header("User-Agent", UA)
    req.add_header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.9")
    req.add_header("Accept-Language", "en-US,en;q=0.9")
    if ref:
        req.add_header("Referer", ref)
    for attempt in range(retries):
        try:
            return opener.open(req, timeout=30)
        except urllib.error.HTTPError as e:
            if e.code in (429, 403, 500, 502, 503) and attempt < retries - 1:
                wait = HOP_DELAY * (2 ** attempt)
                sys.stderr.write("  rate-limited (%s), waiting %.0fs...\n" % (e.code, wait))
                time.sleep(wait)
                continue
            raise RuntimeError("HTTP %s at %s" % (e.code, url)) from e
    raise RuntimeError("gave up on %s" % url)


def variant_urls(release_url, opener):
    """Fetch a release page and return the list of variant page URLs."""
    html = get(opener, release_url).read().decode("utf-8", "replace")
    seen, out = set(), []
    for m in VARIANT_RE.finditer(html):
        u = BASE + m.group(1)
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def cdn_url(variant_url, opener):
    """Walk the 4-step download chain and return the final CDN URL."""
    time.sleep(HOP_DELAY)
    html = get(opener, variant_url).read().decode("utf-8", "replace")
    m = KEY_RE.search(html)
    if not m:
        raise RuntimeError("no download key found on variant page")
    inter = BASE + m.group(1)

    time.sleep(HOP_DELAY)
    page = get(opener, inter, variant_url).read().decode("utf-8", "replace")
    m = PHP_RE.search(page)
    if not m:
        raise RuntimeError("no download.php link on interstitial")
    dl = BASE + m.group(1)

    time.sleep(HOP_DELAY)
    r = get(opener, dl, inter)
    cdn = r.geturl()
    # download.php might hand back another HTML page instead of a redirect
    ct = r.headers.get("Content-Type", "")
    if "html" in ct and not cdn.endswith((".apk", ".apkm", ".xapk", ".zip")):
        raise RuntimeError("download.php did not redirect to a file (got %s)" % ct)
    return cdn


def probe_cdn(cdn):
    """Probe the CDN file with Range requests -> metadata version."""
    time.sleep(REQUEST_DELAY)
    size = apk_probe.get_size(cdn)
    if size <= 0:
        return None, "could not determine size"
    v, detail = apk_probe._probe_url_recursive(cdn, size)
    return v, detail


def download(cdn, dest_dir, chunk=1 << 20):
    """Download a CDN file to dest_dir with a progress bar. Returns the path."""
    os.makedirs(dest_dir, exist_ok=True)
    name = urllib.parse.unquote(cdn.rstrip("/").split("/")[-1].split("?")[0]) or "download.bin"
    local = os.path.join(dest_dir, name)
    size = apk_probe.get_size(cdn)
    got = 0
    req = urllib.request.Request(cdn)
    req.add_header("User-Agent", UA)
    try:
        with urllib.request.urlopen(req, timeout=60) as r, open(local, "wb") as f:
            while True:
                b = r.read(chunk)
                if not b:
                    break
                f.write(b)
                got += len(b)
                if size:
                    sys.stderr.write("\r  downloading... %d/%d MB (%.0f%%)"
                                     % (got >> 20, size >> 20, 100.0 * got / size))
                else:
                    sys.stderr.write("\r  downloading... %d MB" % (got >> 20))
                sys.stderr.flush()
    except Exception as e:
        sys.stderr.write("\n")
        raise RuntimeError("download failed: %s" % e)
    sys.stderr.write("\n")
    return local


def dump_local(game_path, dump_dir, dump_cs=False):
    """Run the main dumper on a local file. Returns the dump_game exit code."""
    import subprocess
    cmd = [sys.executable, "dump_game.py", "-g", game_path, "-o", dump_dir]
    if dump_cs:
        cmd.append("--dump-cs")
    print("[*] dumping %s -> %s" % (game_path, dump_dir))
    return subprocess.call(cmd)


def search_releases(query):
    """Search APKMirror; return (name, release_url) pairs."""
    q = urllib.parse.quote(query)
    opener = make_opener()
    html = get(opener, "%s/?s=%s" % (BASE, q)).read().decode("utf-8", "replace")
    out, seen = [], set()
    for m in RELEASE_RE.finditer(html):
        u = BASE + m.group(1)
        if u in seen:
            continue
        seen.add(u)
        name = m.group(1).rstrip("/").split("/")[-1].replace("-release", "")
        out.append((name, u))
    return out


def main():
    ap = argparse.ArgumentParser(description="Scrape APKMirror + probe metadata version")
    ap.add_argument("query", nargs="?", help="search query, release URL, variant URL, or CDN URL")
    ap.add_argument("--release", help="explicit release page URL")
    ap.add_argument("--variant", help="explicit variant page URL")
    ap.add_argument("--probe-only", help="probe CDN URL(s) directly")
    ap.add_argument("--all-variants", action="store_true",
                    help="probe every variant of a release (default: first)")
    ap.add_argument("--download", metavar="DIR",
                    help="after resolving the CDN URL, download the file into "
                         "DIR and run dump_game.py on it")
    ap.add_argument("--dump-cs", action="store_true",
                    help="with --download, also write dump.cs")
    ap.add_argument("--delay", type=float, default=4.0, help="delay between hops")
    args = ap.parse_args()

    global HOP_DELAY
    HOP_DELAY = args.delay

    if args.probe_only:
        for u in args.probe_only.split():
            v, detail = probe_cdn(u)
            print("%-70s v=%s (%s)" % (u[:70], v, detail))
        return

    if args.release:
        releases = [(args.release.rsplit("/", 2)[-2], args.release)]
    elif args.variant:
        releases = None
        variants = [args.variant]
    elif args.query:
        if args.query.startswith("http"):
            if "download/?key=" in args.query or "android-apk-download" in args.query:
                releases = None
                variants = [args.query]
            else:
                releases = [(args.query.rstrip("/").split("/")[-1].replace("-release", ""), args.query)]
        else:
            print("searching: %r" % args.query)
            releases = search_releases(args.query)
            for name, url in releases:
                print("  %-40s %s" % (name, url))
            if not releases:
                sys.exit("no results")
    else:
        ap.print_help()
        return

    opener = make_opener()
    if releases:
        for name, rurl in releases:
            print("\n== %s" % name)
            try:
                variants = variant_urls(rurl, opener)
            except Exception as e:
                print("  variants: FAILED (%s)" % e)
                continue
            print("  %d variant(s):" % len(variants))
            for vu in variants[:4]:
                print("   ", vu)
            chosen = variants[:1] if not args.all_variants else variants
            for vu in chosen:
                try:
                    cdn = cdn_url(vu, opener)
                    print("   CDN: %s" % cdn[:120])
                    v, detail = probe_cdn(cdn)
                    print("   metadata version: %s (%s)" % (v, detail))
                    if args.download and v is not None:
                        local = download(cdn, args.download)
                        print("   downloaded: %s" % local)
                        rc = dump_local(local, args.download, args.dump_cs)
                        print("   dump_game exit code: %d" % rc)
                except Exception as e:
                    print("   FAILED: %s" % e)
    else:
        for vu in variants:
            try:
                cdn = cdn_url(vu, opener)
                print("CDN: %s" % cdn[:120])
                v, detail = probe_cdn(cdn)
                print("metadata version: %s (%s)" % (v, detail))
                if args.download and v is not None:
                    local = download(cdn, args.download)
                    print("downloaded: %s" % local)
                    rc = dump_local(local, args.download, args.dump_cs)
                    print("dump_game exit code: %d" % rc)
            except Exception as e:
                print("FAILED: %s" % e)


if __name__ == "__main__":
    main()
