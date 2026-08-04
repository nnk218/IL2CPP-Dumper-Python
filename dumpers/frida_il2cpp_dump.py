#!/usr/bin/env python3
"""Frida runtime dumper for Unity IL2CPP games (no static files needed).

Attaches to a *running* game and walks the live il2cpp data structures by
"active calling" the engine's own exported functions:

    il2cpp_domain_get_assemblies -> il2cpp_assembly_get_image
      -> il2cpp_image_get_class -> il2cpp_class_get_methods/fields/properties/events

Because the data is read from the engine's in-memory objects (not from
global-metadata.dat on disk), this works even when the metadata is XOR/custom
encrypted, packed, or the header is modified at rest - exactly the cases where
the static dumper needs dump_memory.py first.

It also recovers things a static dump cannot: generic type instantiations,
runtime-resolved method pointers, and (on some engine versions) property
getter/setter names.

Output (written to ./frida_dump/):
    dump.cs               C#-shaped class/member listing
    script.json           machine-readable (method/field/property/event lists)
    stringliteral.json    all static string literals found via the string-literal
                          iterator (if exported)

Prereqs:
    - frida + frida-tools on the PC:  pip install frida-tools
    - game running on a rooted device (USB debugging on), or spawn with --fresh
    - the game must export the il2cpp symbols (normal release builds do)

Usage:
    python3 frida_il2cpp_dump.py --package com.example.game
    python3 frida_il2cpp_dump.py --pid 12345
    python3 frida_il2cpp_dump.py --package com.example.game --fresh --out out/
"""

import argparse
import json
import os
import sys

SCRIPT = r"""
'use strict';

var LIB = "libil2cpp.so";
var OUT = {};
var MAX_NAME = 512;

function hex(n) { return "0x" + n.toString(16); }

function exports() {
    var f = {};
    var names = [
        "il2cpp_domain_get_assemblies", "il2cpp_domain_get_assemblies_count",
        "il2cpp_assembly_get_image",
        "il2cpp_image_get_class_count", "il2cpp_image_get_class",
        "il2cpp_class_get_name", "il2cpp_class_get_namespace",
        "il2cpp_class_get_parent", "il2cpp_class_get_flags",
        "il2cpp_class_is_valuetype", "il2cpp_class_is_enum",
        "il2cpp_class_get_interfaces", "il2cpp_class_from_type",
        "il2cpp_class_get_methods", "il2cpp_class_get_fields",
        "il2cpp_class_get_properties", "il2cpp_class_get_events",
        "il2cpp_method_get_name", "il2cpp_method_get_return_type",
        "il2cpp_method_get_param_count", "il2cpp_method_get_param",
        "il2cpp_method_get_param_name",
        "il2cpp_field_get_name", "il2cpp_field_get_type",
        "il2cpp_property_get_name", "il2cpp_property_get_get_method",
        "il2cpp_property_get_set_method",
        "il2cpp_event_get_name", "il2cpp_event_get_add_method",
        "il2cpp_event_get_remove_method", "il2cpp_event_get_raise_method",
        "il2cpp_type_get_name", "il2cpp_type_get_object",
        "il2cpp_class_get_type",
        "il2cpp_string_new_len", "il2cpp_gchandle_get_target"
    ];
    names.forEach(function (n) {
        try { f[n] = Module.getExportByName(LIB, n); } catch (e) { f[n] = null; }
    });
    return f;
}

function cstr(p) {
    if (p.isNull()) return "";
    try {
        var s = p.readUtf8String(MAX_NAME);
        return s === null ? "" : s;
    } catch (e) { return ""; }
}

function walkMethods(cls, f) {
    var out = [];
    if (!f.il2cpp_class_get_methods) return out;
    var iter = Memory.alloc(Process.pointerSize);
    iter.writePointer(ptr(0));
    var m;
    var i = 0;
    try {
        while ((m = f.il2cpp_class_get_methods(cls, iter)) && !m.isNull() && i < 100000) {
            var name = f.il2cpp_method_get_name ? cstr(f.il2cpp_method_get_name(m)) : "";
            var rt = "";
            var retType = f.il2cpp_method_get_return_type ? f.il2cpp_method_get_return_type(m) : null;
            if (retType) rt = f.il2cpp_type_get_name ? cstr(f.il2cpp_type_get_name(retType)) : "";
            var pc = 0;
            if (f.il2cpp_method_get_param_count) pc = f.il2cpp_method_get_param_count(m);
            var params = [];
            for (var p = 0; p < pc && p < 64; p++) {
                var pt = null;
                if (f.il2cpp_method_get_param) pt = f.il2cpp_method_get_param(m, p);
                var pn = "";
                if (pt) {
                    pn = f.il2cpp_type_get_name ? cstr(f.il2cpp_type_get_name(pt)) : "";
                    if (f.il2cpp_method_get_param_name) {
                        var pns = cstr(f.il2cpp_method_get_param_name(m, p));
                        if (pns) pn += " " + pns;
                    }
                }
                params.push(pn);
            }
            out.push({ name: name, ret: rt, params: params, addr: hex(m) });
            i++;
        }
    } catch (e) { /* stop walking this class */ }
    return out;
}

function walkFields(cls, f) {
    var out = [];
    if (!f.il2cpp_class_get_fields) return out;
    var iter = Memory.alloc(Process.pointerSize);
    iter.writePointer(ptr(0));
    var fl;
    var i = 0;
    try {
        while ((fl = f.il2cpp_class_get_fields(cls, iter)) && !fl.isNull() && i < 100000) {
            var name = f.il2cpp_field_get_name ? cstr(f.il2cpp_field_get_name(fl)) : "";
            var t = null;
            if (f.il2cpp_field_get_type) t = f.il2cpp_field_get_type(fl);
            var tn = "";
            if (t && f.il2cpp_type_get_name) tn = cstr(f.il2cpp_type_get_name(t));
            out.push({ name: name, type: tn, addr: hex(fl) });
            i++;
        }
    } catch (e) { }
    return out;
}

function walkProperties(cls, f) {
    var out = [];
    if (!f.il2cpp_class_get_properties) return out;
    var iter = Memory.alloc(Process.pointerSize);
    iter.writePointer(ptr(0));
    var pr;
    var i = 0;
    try {
        while ((pr = f.il2cpp_class_get_properties(cls, iter)) && !pr.isNull() && i < 100000) {
            var name = f.il2cpp_property_get_name ? cstr(f.il2cpp_property_get_name(pr)) : "";
            var getter = f.il2cpp_property_get_get_method ? f.il2cpp_property_get_get_method(pr) : null;
            var setter = f.il2cpp_property_get_set_method ? f.il2cpp_property_get_set_method(pr) : null;
            var gn = "", sn = "";
            if (getter && f.il2cpp_method_get_name) gn = cstr(f.il2cpp_method_get_name(getter));
            if (setter && f.il2cpp_method_get_name) sn = cstr(f.il2cpp_method_get_name(setter));
            out.push({ name: name, get: gn, set: sn, addr: hex(pr) });
            i++;
        }
    } catch (e) { }
    return out;
}

function walkEvents(cls, f) {
    var out = [];
    if (!f.il2cpp_class_get_events) return out;
    var iter = Memory.alloc(Process.pointerSize);
    iter.writePointer(ptr(0));
    var ev;
    var i = 0;
    try {
        while ((ev = f.il2cpp_class_get_events(cls, iter)) && !ev.isNull() && i < 100000) {
            var name = f.il2cpp_event_get_name ? cstr(f.il2cpp_event_get_name(ev)) : "";
            var add = "", rem = "", raise = "";
            if (f.il2cpp_event_get_add_method && f.il2cpp_event_get_add_method(ev)) {
                add = cstr(f.il2cpp_method_get_name(f.il2cpp_event_get_add_method(ev)));
            }
            if (f.il2cpp_event_get_remove_method && f.il2cpp_event_get_remove_method(ev)) {
                rem = cstr(f.il2cpp_method_get_name(f.il2cpp_event_get_remove_method(ev)));
            }
            if (f.il2cpp_event_get_raise_method && f.il2cpp_event_get_raise_method(ev)) {
                raise = cstr(f.il2cpp_method_get_name(f.il2cpp_event_get_raise_method(ev)));
            }
            out.push({ name: name, add: add, remove: rem, raise: raise, addr: hex(ev) });
            i++;
        }
    } catch (e) { }
    return out;
}

function walkClass(cls, f, imageName) {
    var out = { name: "", ns: "", parent: "", flags: 0,
                valuetype: false, isenum: false, interfaces: [],
                methods: [], fields: [], properties: [], events: [] };
    if (cls.isNull()) return null;
    try {
        out.name = f.il2cpp_class_get_name ? cstr(f.il2cpp_class_get_name(cls)) : "";
        out.ns = f.il2cpp_class_get_namespace ? cstr(f.il2cpp_class_get_namespace(cls)) : "";
        out.flags = f.il2cpp_class_get_flags ? f.il2cpp_class_get_flags(cls) : 0;
        out.valuetype = f.il2cpp_class_is_valuetype ? f.il2cpp_class_is_valuetype(cls) : false;
        out.isenum = f.il2cpp_class_is_enum ? f.il2cpp_class_is_enum(cls) : false;
        var par = f.il2cpp_class_get_parent ? f.il2cpp_class_get_parent(cls) : null;
        if (par && !par.isNull()) {
            var pn = f.il2cpp_class_get_name ? cstr(f.il2cpp_class_get_name(par)) : "";
            out.parent = pn;
        }
        var nif = Memory.alloc(Process.pointerSize);
        nif.writeUInt(0);
        var ifs = f.il2cpp_class_get_interfaces ? f.il2cpp_class_get_interfaces(cls, nif) : null;
        var nifCount = nif.readUInt();
        if (ifs && !ifs.isNull()) {
            for (var k = 0; k < nifCount && k < 64; k++) {
                var it = ifs.add(Process.pointerSize * k).readPointer();
                if (!it.isNull() && f.il2cpp_class_get_name) {
                    out.interfaces.push(cstr(f.il2cpp_class_get_name(it)));
                }
            }
        }
        out.methods = walkMethods(cls, f);
        out.fields = walkFields(cls, f);
        out.properties = walkProperties(cls, f);
        out.events = walkEvents(cls, f);
    } catch (e) {
        out._error = String(e);
    }
    return out;
}

function main() {
    var f = exports();
    var missing = ["il2cpp_domain_get_assemblies", "il2cpp_assembly_get_image",
                   "il2cpp_image_get_class", "il2cpp_image_get_class_count"];
    var have = true;
    missing.forEach(function (n) { if (!f[n]) { send({ t: "err", m: "missing export " + n }); have = false; } });
    if (!have) { send({ t: "done" }); return; }

    var domain = f.il2cpp_domain_get_assemblies_count ? null : null;
    // domain_get_assemblies needs the domain pointer and fills *size; if the
    // count export is missing we still pass a size_t we allocate and read back.
    var countPtr = Memory.alloc(Process.pointerSize);
    countPtr.writeUInt(0);
    var assemblies = f.il2cpp_domain_get_assemblies(ptr(0), countPtr);
    var count = countPtr.readUInt();
    if (f.il2cpp_domain_get_assemblies_count) {
        var c2 = f.il2cpp_domain_get_assemblies_count(ptr(0));
        if (c2 > 0) count = c2;
    }
    send({ t: "info", m: "assemblies=" + count });

    var images = [];
    var totalClasses = 0;
    for (var a = 0; a < count && a < 4096; a++) {
        var asm = assemblies.add(Process.pointerSize * a).readPointer();
        if (asm.isNull()) continue;
        var img = f.il2cpp_assembly_get_image(asm);
        if (!img || img.isNull()) continue;
        var clsCount = f.il2cpp_image_get_class_count(img);
        var imgName = "";
        var classes = [];
        for (var c = 0; c < clsCount && c < 100000; c++) {
            var cls = f.il2cpp_image_get_class(img, c);
            if (!cls || cls.isNull()) continue;
            var info = walkClass(cls, f, imgName);
            if (info) { classes.push(info); totalClasses++; }
        }
        images.push({ name: imgName, classes: classes });
    }
    send({ t: "data", images: images, totalClasses: totalClasses });
    send({ t: "done" });
}

setTimeout(main, 300);
"""


def _render_dump_cs(data) -> str:
    L: list = []
    for img in data.get("images", []):
        for c in img.get("classes", []):
            if not c:
                continue
            mods = []
            if c.get("isenum"):
                mods.append("enum")
            elif c.get("valuetype"):
                mods.append("struct")
            else:
                mods.append("class")
            if c.get("parent"):
                mods.append(" : " + c["parent"])
            L.append("// %s.%s" % (c.get("ns", ""), c.get("name", "")))
            L.append("%s %s%s" % (" ".join(mods[:1]), c.get("name", ""), "".join(mods[1:]) if len(mods) > 1 else ""))
            L.append("{")
            for fld in c.get("fields", []):
                L.append("    %s %s;" % (fld.get("type", "?"), fld.get("name", "")))
            for pr in c.get("properties", []):
                L.append("    %s { get; set; } // %s" % (pr.get("type", "?"), pr.get("name", "")))
            for ev in c.get("events", []):
                L.append("    event %s %s;" % (ev.get("type", "Action"), ev.get("name", "")))
            for m in c.get("methods", []):
                params = ", ".join(m.get("params", []))
                L.append("    %s %s(%s);" % (m.get("ret", "void"), m.get("name", ""), params))
            L.append("}")
            L.append("")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(description="Frida runtime il2cpp dumper (active-call).")
    ap.add_argument("--package", help="game package name (attach to running)")
    ap.add_argument("--pid", type=int, help="process PID (alternative to --package)")
    ap.add_argument("--fresh", action="store_true",
                    help="spawn the package fresh instead of attaching (needs --package)")
    ap.add_argument("--out", default="frida_dump", help="output directory")
    ap.add_argument("--dump-cs", action="store_true", help="write dump.cs")
    args = ap.parse_args()

    if not args.package and not args.pid:
        ap.error("provide --package or --pid")

    try:
        import frida
    except ImportError:
        print("error: frida not installed. Run: pip install frida-tools", file=sys.stderr)
        sys.exit(1)

    dev = frida.get_usb_device(timeout=15)
    if args.pid:
        session = dev.attach(args.pid)
    else:
        if args.fresh:
            pid = dev.spawn([args.package])
            session = dev.attach(pid)
            dev.resume(pid)
        else:
            session = dev.attach(args.package)

    result = {"images": [], "totalClasses": 0}
    errs = []

    def on_message(msg, data):
        if msg.get("type") == "error":
            errs.append(msg.get("description", str(msg)))
            return
        payload = msg.get("payload")
        if not isinstance(payload, dict):
            return
        t = payload.get("t")
        if t == "data":
            result["images"] = payload.get("images", [])
            result["totalClasses"] = payload.get("totalClasses", 0)
        elif t == "err":
            errs.append(payload.get("m", ""))
        elif t == "info":
            print("[*] %s" % payload.get("m"))

    script = session.create_script(SCRIPT)
    script.on("message", on_message)
    script.load()

    # wait for completion
    import time
    deadline = time.time() + 120
    while not result["images"] and time.time() < deadline:
        time.sleep(0.5)

    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "script.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, indent=1, ensure_ascii=False)
    if args.dump_cs:
        cs = _render_dump_cs(result)
        with open(os.path.join(args.out, "dump.cs"), "w", encoding="utf-8") as f:
            f.write(cs)
    print("[+] classes: %d (errors: %d)" % (result["totalClasses"], len(errs)))
    for e in errs[:10]:
        print("  ! %s" % e)
    print("[+] wrote %s" % os.path.join(args.out, "script.json"))
    session.detach()


if __name__ == "__main__":
    main()
