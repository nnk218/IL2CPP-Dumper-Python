# -*- coding: utf-8 -*-
"""Apply names/comments from the dumper's script.json to an IDA database.

Load this script inside IDA (File > Script file...) after:
  1. Dumping the game with dump_game.py (produces script.json)
  2. Loading libil2cpp.so / GameAssembly.dll into IDA with its load base
     matching the dump (for ELF this is usually the image base 0).

What it does:
  - creates functions at every method/address in "Addresses"
  - renames every ScriptMethod to "Class$$method"
  - labels string literals "StringLiteral_N" with the string as a comment
  - labels type infos / method infos with names + comments
  - labels metadata-method slots and records their method address

Usage in IDA:
  ida_py3 / ida (Python 3 / 2) -> File > Script file... -> ida_annotate.py
  It prompts for the script.json path.
"""

import json

processFields = [
    "ScriptMethod",
    "ScriptString",
    "ScriptMetadata",
    "ScriptMetadataMethod",
    "Addresses",
]

imageBase = idaapi.get_imagebase()


def get_addr(addr):
    return imageBase + addr


def set_name(addr, name):
    ret = idc.set_name(addr, name, SN_NOWARN | SN_NOCHECK)
    if ret == 0:
        new_name = name + '_' + str(addr)
        ret = idc.set_name(addr, new_name, SN_NOWARN | SN_NOCHECK)


def make_function(start, end):
    next_func = idc.get_next_func(start)
    if next_func < end:
        end = next_func
    if idc.get_func_attr(start, FUNCATTR_START) == start:
        ida_funcs.del_func(start)
    ida_funcs.add_func(start, end)


path = idaapi.ask_file(False, '*.json', 'script.json from IL2CPP-Dumper-Python')
data = json.loads(open(path, 'rb').read().decode('utf-8'))

if "Addresses" in data:
    addresses = data["Addresses"]
    for index in range(len(addresses) - 1):
        start = get_addr(addresses[index])
        end = get_addr(addresses[index + 1])
        make_function(start, end)

if "ScriptMethod" in data:
    for scriptMethod in data["ScriptMethod"]:
        addr = get_addr(scriptMethod["Address"])
        name = scriptMethod["Name"]
        set_name(addr, name)

if "ScriptString" in data:
    index = 1
    for scriptString in data["ScriptString"]:
        addr = get_addr(scriptString["Address"])
        value = scriptString["Value"]
        name = "StringLiteral_" + str(index)
        idc.set_name(addr, name, SN_NOWARN)
        idc.set_cmt(addr, value, 1)
        index += 1

if "ScriptMetadata" in data:
    for scriptMetadata in data["ScriptMetadata"]:
        addr = get_addr(scriptMetadata["Address"])
        name = scriptMetadata["Name"]
        set_name(addr, name)
        idc.set_cmt(addr, name, 1)

if "ScriptMetadataMethod" in data:
    for scriptMetadataMethod in data["ScriptMetadataMethod"]:
        addr = get_addr(scriptMetadataMethod["Address"])
        name = scriptMetadataMethod["Name"]
        set_name(addr, name)
        idc.set_cmt(addr, name, 1)
        if "MethodAddress" in scriptMetadataMethod:
            methodAddr = get_addr(scriptMetadataMethod["MethodAddress"])
            idc.set_cmt(addr, '{0:X}'.format(methodAddr), 0)

print('Script finished!')
