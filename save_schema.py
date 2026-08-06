"""save_schema.py -- standalone POP0.schema loader for the .PoPSavedGame save-format project.

Reads POP0.schema directly via forge/schema_parser.py and exposes the couple of pieces of derived
data pop_save.py actually needs: primitive field widths and one real, validated schema correction.
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(_HERE, 'forge'))
import schema_parser as P

# ---- primitive widths by typeIndex (mid byte of the field trailer) ----
# Includes kind=0x11 (id/ref-style scalar, 4 bytes), confirmed against real save-file ground
# truth (PopGameplaySettings.LastPopEnvironmentAreaPortalID).
PRIM_WIDTH = {
    0x00: 1,    # bool / u8
    0x01: 1,    # char/u8
    0x02: 4,
    0x03: 1,    # s8
    0x04: 2,    # s16
    0x05: 2,    # u16
    0x06: 4,    # u32
    0x07: 4,    # u32
    0x09: 8,    # u64
    0x0a: 4,    # float
    0x0b: 8,    # Vector2 (2 floats)
    0x0c: 12,   # Vector3 (3 floats)
    0x0d: 16,   # Vector4 (4 floats)
    0x0e: 16,   # Quaternion / IColor (4 floats)
    0x10: 64,   # Matrix (16 floats)
    0x11: 4,    # id/ref-style scalar -- save-format-specific finding, see module docstring
    0x19: 4,    # enum
    0x1f: 8,    # 2x u32
}

SERIALIZE_BIT = 0x2000000       # a field is part of the normal .forge object-graph serialization
SAVE_PERSIST_BIT = 0x8000000    # a field is written to the .PoPSavedGame save file (see
                                 # pop_save.save_persisted_census's docstring for how this was found)

_SCHEMA = None


def load_schema():
    """Returns (T, names). T[typehash] = {'parent': typehash, 'fields': [(flags, name_hash,
    field_typehash, trailer), ...]}. names[hash] = the real string, for any hash (class or field)
    present in POP0.schema's own name table."""
    global _SCHEMA
    if _SCHEMA is not None:
        return _SCHEMA
    d, filesize, types, extra, names, endp = P.parse()
    T = {}
    for t in types:
        T[t['A']] = {'parent': t['B'], 'fields': [(fl, nh, th, tr) for (fl, nh, th, tr) in t['fields']]}

    # POPPlayer fix: the schema says Brightness/BrightnessDefault are 4-byte fields, but they're
    # really 1 byte each - with the schema's own kind, the field walk overshoots by exactly 6
    # bytes, and dropping these two to 1 byte fixes it. Matters here since POPPlayer has other
    # save-persisted fields too (Tutorials, Subtitles, ...).
    POPPlayer = 0x6944b2de
    if POPPlayer in T:
        fields = T[POPPlayer]['fields']
        for i, (fl, nh, fth, tr) in enumerate(fields):
            if nh in (0x962bd533, 0xd9a1ab7d):
                fields[i] = (fl, nh, fth, 0x00000)

    _SCHEMA = (T, names)
    return _SCHEMA


if __name__ == '__main__':
    T, names = load_schema()
    print('loaded %d types, %d names' % (len(T), len(names)))
