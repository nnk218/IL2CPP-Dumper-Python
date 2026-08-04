# -*- coding: utf-8 -*-
"""Apply names/comments from the dumper's script.json to a Ghidra program.

Load this script inside Ghidra's Script Manager (Window > Script Manager,
then run): after
  1. Dumping the game with dump_game.py (produces script.json)
  2. Importing libil2cpp.so / GameAssembly.dll into Ghidra (Analyze after
     import is fine) so the image base matches the dump.

What it does:
  - creates functions at every method/address in "Addresses"
  - renames every ScriptMethod to "Class$$method"
  - labels string literals "StringLiteral_N" with the string as a comment
  - labels type infos / method infos with names + comments
  - labels metadata-method slots and records their method address

Usage in Ghidra:
  Window > Script Manager > (green plus) add this script's folder, then run
  il2cpp_annotate.py from the list.
"""

import json

processFields = [
    "ScriptMethod",
    "ScriptString",
    "ScriptMetadata",
    "ScriptMetadataMethod",
    "Addresses",
]

functionManager = currentProgram.getFunctionManager()
baseAddress = currentProgram.getImageBase()
USER_DEFINED = ghidra.program.model.symbol.SourceType.USER_DEFINED


def get_addr(addr):
    return baseAddress.add(addr)


def set_name(addr, name):
    name = name.replace(' ', '-')
    createLabel(addr, name, True, USER_DEFINED)


def make_function(start):
    func = getFunctionAt(start)
    if func is None:
        createFunction(start, None)


f = askFile("script.json from IL2CPP-Dumper-Python", "Open")
data = json.loads(open(f.absolutePath, 'rb').read().decode('utf-8'))

if "ScriptMethod" in data:
    scriptMethods = data["ScriptMethod"]
    monitor.initialize(len(scriptMethods))
    monitor.setMessage("Methods")
    for scriptMethod in scriptMethods:
        addr = get_addr(scriptMethod["Address"])
        name = scriptMethod["Name"].encode("utf-8")
        set_name(addr, name)
        monitor.incrementProgress(1)

if "ScriptString" in data:
    index = 1
    scriptStrings = data["ScriptString"]
    monitor.initialize(len(scriptStrings))
    monitor.setMessage("Strings")
    for scriptString in scriptStrings:
        addr = get_addr(scriptString["Address"])
        value = scriptString["Value"].encode("utf-8")
        name = "StringLiteral_" + str(index)
        createLabel(addr, name, True, USER_DEFINED)
        setEOLComment(addr, value)
        index += 1
        monitor.incrementProgress(1)

if "ScriptMetadata" in data:
    scriptMetadatas = data["ScriptMetadata"]
    monitor.initialize(len(scriptMetadatas))
    monitor.setMessage("Metadata")
    for scriptMetadata in scriptMetadatas:
        addr = get_addr(scriptMetadata["Address"])
        name = scriptMetadata["Name"].encode("utf-8")
        set_name(addr, name)
        setEOLComment(addr, name)
        monitor.incrementProgress(1)

if "ScriptMetadataMethod" in data:
    scriptMetadataMethods = data["ScriptMetadataMethod"]
    monitor.initialize(len(scriptMetadataMethods))
    monitor.setMessage("Metadata Methods")
    for scriptMetadataMethod in scriptMetadataMethods:
        addr = get_addr(scriptMetadataMethod["Address"])
        name = scriptMetadataMethod["Name"].encode("utf-8")
        set_name(addr, name)
        setEOLComment(addr, name)
        if "MethodAddress" in scriptMetadataMethod:
            methodAddr = get_addr(scriptMetadataMethod["MethodAddress"])
            setEOLComment(addr, "0x%X" % methodAddr.offset)
        monitor.incrementProgress(1)

if "Addresses" in data:
    addresses = data["Addresses"]
    monitor.initialize(len(addresses))
    monitor.setMessage("Addresses")
    for index in range(len(addresses) - 1):
        start = get_addr(addresses[index])
        make_function(start)
        monitor.incrementProgress(1)

print('Script finished!')
