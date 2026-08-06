"""resource_names.py -- resource metadata listing for a parsed forge bundle."""
import struct


def list_resources(parsed, be):
    """Resource metadata rows from a parsed bundle (see bundle_reader.parse_bundle) -- cheap:
    header peeks only, no full field-level decode."""
    f = '>' if be else '<'
    body = parsed['body']
    out = []
    off = 0
    for k, (h, sz) in enumerate(parsed['entries']):
        r = dict(i=k, body_off=off, hash=h, size=sz, typehash=None, name='', kind='')
        if sz >= 12 and off + 12 <= len(body):
            th = struct.unpack_from(f + 'I', body, off)[0]
            nl = struct.unpack_from(f + 'I', body, off + 8)[0] & 0xffff
            r['typehash'] = th
            if 0 < nl < 200 and off + 12 + nl <= len(body):
                nm = body[off + 12:off + 12 + nl]
                if all(32 <= c < 127 for c in nm):
                    r['name'] = nm.decode()
        out.append(r)
        off += sz
    return out
