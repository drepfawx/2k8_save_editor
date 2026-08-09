"""forge_file.py -- reader for Prince of Persia 2008 (Scimitar/Anvil) .forge archives.

The forge container + index format is identical on PC and Xbox360 (little-endian, version 26).

Header:  "scimitar"(8) | 0x00 | u32 version=26 @9 | s64 indexOffset @0xD (always 0x416)
Index @0x416: u32 entryCount, fixed header, then at +0x70 an array of
              {u64 uid, u64 fileOffset} entries (offset 0 = empty/trailing slot).
Each resource @fileOffset starts with ASCII "FILEDATA" + null-padded name; the
serialized object begins ~+0x187.
"""
import struct, os

MAGIC = b"scimitar"
ENTRY_TABLE_REL = 0x70   # entry array offset relative to indexOffset
DATA_REL = 0x187         # serialized object start relative to a resource's FILEDATA offset


class Entry:
    __slots__ = ("idx", "uid", "offset", "name", "size", "header_reloff", "table_index")

    def __init__(self, idx, uid, offset, name, size, header_reloff=None, table_index=None):
        self.idx, self.uid, self.offset, self.name, self.size = idx, uid, offset, name, size
        # Only one of these two is ever set. header_reloff is for the two header-embedded
        # streams (GlobalMetaFile/DLCWorld) -- their offset field lives at
        # index_off+4+header_reloff, outside the normal {uid,offset} table. table_index is for
        # a real table entry, whose offset field lives at index_off+0x70+table_index*16+8.
        # Don't use `idx` as a table slot number -- it's off by 2 (the two header streams get
        # numbered first) and would clobber slots 0-1.
        self.header_reloff = header_reloff
        self.table_index = table_index

    def __repr__(self):
        return f"Entry(#{self.idx} {self.name!r} off={self.offset:#x} size={self.size} uid={self.uid:#018x})"


class ForgeFile:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()
        d = self.data
        assert d[:8] == MAGIC, f"{path}: not a forge (magic={d[:8]!r})"
        self.version = struct.unpack_from("<I", d, 9)[0]
        self.index_off = struct.unpack_from("<q", d, 0xD)[0]
        self.count = struct.unpack_from("<I", d, self.index_off)[0]
        self._parse_entries()

    def _read_name(self, off):
        if off == 0 or off + 8 > len(self.data):
            return None
        if self.data[off:off+8] != b"FILEDATA":
            return None
        seg = self.data[off+8:off+8+0x180]
        return seg.split(b"\x00")[0].decode("latin1", "replace")

    # Every forge also carries two fixed datastreams in the header itself, right before the
    # uid/offset table -- plain u32 file offsets at relative bytes 84 and 100. They're not part
    # of the table and have no uid; the first is always "GlobalMetaFile" (same boilerplate in
    # every forge), the second varies ("DLCWorld", "POP0WORLD", or unused).
    HEADER_STREAM_RELOFFSETS = (84, 100)

    def _parse_entries(self):
        d = self.data
        base = self.index_off + ENTRY_TABLE_REL
        header_base = self.index_off + 4
        header_raw = []
        for reloff in self.HEADER_STREAM_RELOFFSETS:
            if header_base + reloff + 4 > len(d):
                continue
            off = struct.unpack_from("<I", d, header_base + reloff)[0]
            if off and self._read_name(off) is not None:
                header_raw.append((0, off, reloff))
        table_raw = []
        for k in range(self.count):
            uid, off = struct.unpack_from("<QQ", d, base + k*16)
            table_raw.append((uid, off, k))
        # Header streams first, then the table. `idx` is just a position in this combined list,
        # not a table slot -- use header_reloff/table_index on the Entry to find the real offset.
        raw = header_raw + table_raw
        # size = distance to next *data* boundary (sorted offsets) or EOF
        offs = sorted({o for _, o, _ in raw if o} | {len(d)})
        nextof = {}
        for i, o in enumerate(offs[:-1]):
            nextof[o] = offs[i+1]
        self.entries = []
        for k, (uid, off, extra) in enumerate(raw):
            name = self._read_name(off) if off else None
            size = (nextof.get(off, len(d)) - off) if off else 0
            if k < len(header_raw):
                self.entries.append(Entry(k, uid, off, name, size, header_reloff=extra))
            else:
                self.entries.append(Entry(k, uid, off, name, size, table_index=extra))

    def named(self):
        return [e for e in self.entries if e.name]

    def by_name(self):
        return {e.name: e for e in self.entries if e.name}

    def read_resource(self, e):
        """Raw bytes of a resource (FILEDATA header + payload), incl. trailing padding."""
        return self.data[e.offset:e.offset + e.size]


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python forge_file.py <forge_path>")
    else:
        fo = ForgeFile(sys.argv[1])
        named = fo.named()
        print(f"{os.path.basename(sys.argv[1])}: ver={fo.version} count={fo.count} named={len(named)}")
        for e in named[:10]:
            print(f"  {e}")
