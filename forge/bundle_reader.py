"""bundle_reader.py -- reader for the FILEDATA bundle format used inside forge archives.

On-disk bundle layout (all multi-byte fields in the file's endianness):
  0x000  "FILEDATA" (8)
  0x008  name + header, null-padded, up to 0x187
  0x187  scalar header, 49 bytes:  u32 f30 | u32 payloadSize | u64 f31 | u64 f32 | u32 f33 |
                                   u32 f19c | u32 f34 | u32 f1a4 | u32 f35 | u8 f36 | u32 f1b4
  0x1b8  section 1 = LZSS-compressed RESOURCE TABLE
  ....   section 2 = LZSS-compressed BODY (the serialized nodes)

Each compressed section:
  u64 magic 0x1004fa9957fbaa33 | u16 ver | u8 comptype | u32 0x80008000 |
  u16 blockCount | blockCount*(u16 uSize,u16 cSize) | blockCount*(u32 checksum + cSize bytes)
Resource table (decompressed): u16 count | count*(u32 nameHash, u32 resourceSize).
Sum of resourceSizes == decompressed body length (resources tile the body sequentially).
"""
import struct, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from forge_file import ForgeFile
from lzss import lzss_block

SECTION_MAGIC = 0x1004fa9957fbaa33

class BundleError(Exception):
    pass

def _f(be):
    return '>' if be else '<'

def decompress_section(raw, off, be):
    """Parse+decompress one compressed section at `off`. Returns (data, end_off, ver, comptype)."""
    f = _f(be)
    if off + 17 > len(raw):
        raise BundleError("section truncated at %#x" % off)
    magic = struct.unpack_from(f + 'Q', raw, off)[0]
    if magic != SECTION_MAGIC:
        raise BundleError("bad section magic %#018x at %#x (endianness wrong?)" % (magic, off))
    ver  = struct.unpack_from(f + 'H', raw, off + 8)[0]
    comp = raw[off + 10]
    const= struct.unpack_from(f + 'I', raw, off + 11)[0]
    cnt  = struct.unpack_from(f + 'H', raw, off + 15)[0]
    if not (0 < cnt <= 60000):
        raise BundleError("bogus block count %d at %#x" % (cnt, off + 15))
    p = off + 17
    blocks = []
    for k in range(cnt):
        us, cs = struct.unpack_from(f + 'HH', raw, p + k * 4)
        if not (0 < us <= 0x8000 and 0 < cs <= us):
            raise BundleError("bogus block[%d] us=%#x cs=%#x at %#x" % (k, us, cs, p + k * 4))
        blocks.append((us, cs))
    cur = p + cnt * 4
    out = bytearray()
    for us, cs in blocks:
        cur += 4                                   # skip u32 checksum
        if cs == us:
            out += raw[cur:cur + cs]
        else:
            d, _ = lzss_block(raw, cur)
            if len(d) != us:
                raise BundleError("block decode %d != us %d" % (len(d), us))
            out += d
        cur += cs
    return bytes(out), cur, ver, comp

def parse_bundle(raw, be):
    """Parse a FILEDATA bundle. Raises BundleError where a real
    read would desync/hang. Returns a dict describing the bundle."""
    f = _f(be)
    if raw[0:8] != b"FILEDATA":
        raise BundleError("no FILEDATA magic")
    name = raw[8:8 + 0x100].split(b"\x00")[0].decode("latin1", "replace")
    # scalar header @0x187 (49 bytes)
    sh = struct.unpack_from(f + 'IIQQIIIIIBI', raw, 0x187)
    payload_size = sh[1]
    # section 1: resource table (magic must be at 0x1b8 for a well-formed bundle)
    o1 = 0x1b8
    tbl, o1_end, v1, c1 = decompress_section(raw, o1, be)
    n = struct.unpack_from(f + 'H', tbl, 0)[0]
    if 2 + n * 8 > len(tbl):
        raise BundleError("resource table count %d overflows %d bytes" % (n, len(tbl)))
    entries = [struct.unpack_from(f + 'II', tbl, 2 + k * 8) for k in range(n)]
    # section 2: body (immediately follows section 1)
    body, o2_end, v2, c2 = decompress_section(raw, o1_end, be)
    size_sum = sum(sz for _, sz in entries)
    return dict(name=name, scalar=sh, payload_size=payload_size, comptype=c1,
                res_count=n, entries=entries, body=body,
                sec1_range=(o1, o1_end), sec2_range=(o1_end, o2_end),
                size_sum=size_sum, body_len=len(body),
                size_matches=(size_sum == len(body)))

def diagnose(path, be, name):
    """Ad-hoc CLI diagnostic: parse one named bundle from a .forge file and print its shape.
    Usage: python bundle_reader.py <forge_path> <BE|LE> <bundle_name>"""
    fo = ForgeFile(path)
    e = next(x for x in fo.named() if x.name == name)
    raw = fo.data[e.offset:e.offset + e.size]
    tag = "BE" if be else "LE"
    print("=== %s  [%s]  slot=%d ===" % (name, tag, e.size))
    try:
        b = parse_bundle(raw, be)
        print("  name=%s  resources=%d  body=%d  size_sum=%d  match=%s"
              % (b['name'], b['res_count'], b['body_len'], b['size_sum'], b['size_matches']))
        print("  sec1=%s sec2=%s comptype=%d  payloadSize(hdr)=%d"
              % (b['sec1_range'], b['sec2_range'], b['comptype'], b['payload_size']))
        print("  first entries:", [(hex(h), s) for h, s in b['entries'][:4]])
        print("  PARSE OK")
    except BundleError as ex:
        print("  *** DESYNC / FREEZE POINT: %s" % ex)

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Usage: python bundle_reader.py <forge_path> <BE|LE> <bundle_name>")
    else:
        diagnose(sys.argv[1], sys.argv[2].upper() == 'BE', sys.argv[3])
