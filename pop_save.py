"""pop_save.py -- .PoPSavedGame format reader.

Header layout reverse engineered from PrinceOfPersia_Launchera.exe's writer/loader (Ghidra).
File structure:

  [0x0000-0x203F) fixed header (8255 bytes) -- magic, version, sizes, timestamp, 4 embedded
                  UTF-16 string slots (title/level name/forge name/reserved).
  [0x203F, +blob2_size)  blob2 -- small checkpoint-summary record (hash-style checkpoint ID +
                  level name again), read by the save browser without touching blob1.
  [..., +blob1_size)     blob1 -- the real payload: a compressed section using the same
                  SECTION_MAGIC framing as forge bundles, but wrapped in a save-specific 10-byte
                  header (4-byte outer size, 2 unknown bytes, 4-byte inner size) before the usual
                  magic+ver+comp+const+cnt prefix. The LZSS blocks aren't back-to-back like forge
                  sections -- each one is followed by a 4-byte checksum that has to be skipped
                  before the next block starts.
  [..., +trailer_size)   trailer -- a PNG screenshot (save-slot thumbnail).

Decompressed blob1's root object is `SaveGameObject` (typehash 0x89dda5b). Its field layout right
after [typehash][size] doesn't follow the generic Converter.parse_node() managed-object
convention, so full field-level decode isn't complete -- this module exposes the decompressed
bytes and root typehash so callers can show what's known and fall back to raw hex otherwise; see
save_explorer.py.
"""
import os
import re
import struct
import sys
import zlib
from datetime import datetime, timedelta

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(_HERE, 'forge'))
from lzss import lzss_block

MAGIC = 0x484D4752  # "RGMH"
HEADER_SIZE = 0x203F


class SaveFormatError(Exception):
    pass


def parse_header(data):
    """Parse the fixed 0x203F-byte header. Returns a dict of every field this project has
    ground-truthed (see module docstring). Raises SaveFormatError if the magic doesn't match."""
    if len(data) < HEADER_SIZE:
        raise SaveFormatError("file too short for header: %d bytes" % len(data))
    magic = struct.unpack_from('<I', data, 0)[0]
    if magic != MAGIC:
        raise SaveFormatError("bad magic %#010x (expected %#010x)" % (magic, MAGIC))

    def wstr(off):
        buf = data[off:off + 0x800]
        end = len(buf)
        for i in range(0, len(buf) - 1, 2):
            if buf[i] == 0 and buf[i + 1] == 0:
                end = i
                break
        return buf[:end].decode('utf-16-le', 'replace')

    version = struct.unpack_from('<I', data, 0x04)[0]
    meta_off = struct.unpack_from('<I', data, 0x08)[0]           # always 0x2028
    end_field = struct.unpack_from('<I', data, 0x0C)[0]          # header_size + blob1_size
    trailer_size = struct.unpack_from('<I', data, 0x14)[0]
    const1 = struct.unpack_from('<Q', data, 0x18)[0]
    const2 = struct.unpack_from('<Q', data, 0x20)[0]

    title = wstr(0x28)
    level_name = wstr(0x828)
    forge_name = wstr(0x1028)
    reserved_str = wstr(0x1828)

    section_marker = struct.unpack_from('<I', data, 0x2028)[0]
    checksum = struct.unpack_from('<I', data, 0x202C)[0]
    blob1_size = struct.unpack_from('<I', data, 0x2030)[0]
    year = struct.unpack_from('<H', data, 0x2034)[0]
    month = data[0x2036]
    day = data[0x2037]
    hour = data[0x2038]
    minute = data[0x2039]
    second = data[0x203A]
    blob2_size = struct.unpack_from('<I', data, 0x203B)[0]

    try:
        # header stores UTC, not local time
        timestamp_utc = datetime(year, month, day, hour, minute, second)
    except ValueError:
        timestamp_utc = None

    return dict(
        magic=magic, version=version, meta_off=meta_off, end_field=end_field,
        trailer_size=trailer_size, const1=const1, const2=const2,
        title=title, level_name=level_name, forge_name=forge_name, reserved_str=reserved_str,
        section_marker=section_marker, checksum=checksum, blob1_size=blob1_size,
        year=year, month=month, day=day, hour=hour, minute=minute, second=second,
        timestamp_utc=timestamp_utc, blob2_size=blob2_size,
    )


def parse_blob2(data, off, size):
    """The small checkpoint-summary record: an ASCII checkpoint-ID string (hash + level-code
    suffix, e.g. '35C990AE.CA') followed by the level display name again in UTF-16."""
    blob2 = data[off:off + size]
    marker = struct.unpack_from('<I', blob2, 0)[0] if len(blob2) >= 4 else None
    code = None
    if len(blob2) > 4:
        end = blob2.find(b'\x00', 4)
        if end < 0:
            end = len(blob2)
        code = blob2[4:end].decode('ascii', 'replace')
    level_name = None
    # scan the rest for a UTF-16 string (first non-zero u16-aligned run after the code)
    i = 4 + (len(code) if code else 0)
    i += (-i) % 2
    while i < len(blob2) - 1 and blob2[i] == 0 and blob2[i + 1] == 0:
        i += 2
    if i < len(blob2) - 1:
        end = i
        while end < len(blob2) - 1 and not (blob2[end] == 0 and blob2[end + 1] == 0):
            end += 2
        level_name = blob2[i:end].decode('utf-16-le', 'replace')
    return dict(marker=marker, checkpoint_code=code, level_name=level_name, raw=blob2)


BLOB1_FIRST_BLOCK_HEADER = 25   # where the first block's header starts
BLOB1_BLOCK_HEADER_SIZE = 13    # [u8 flag][u32 compressed][u32 uncompressed][u32 checksum]


def decompress_blob1(data, off, size):
    """Decompress blob1 into the raw serialized SaveGameObject bytes.

    Layout (little-endian):
      blob1[0:10)  4-byte outer size, 2 unused bytes, 4-byte size (unreliable, ignore)
      blob1[10:18) SECTION_MAGIC (same as forge sections)
      blob1[18:26) ver/comptype/const
      blob1[25:..) blocks: [u8 flag][u32 compressed size][u32 uncompressed size][u32 checksum,
                   unverified], then that many compressed bytes. Next block follows immediately.

    A previous version skipped only 4 of the 13 header bytes, so lzss_block decoded the size
    fields as literal data and every block after the first came out 8 bytes too long. The stream
    resynced right after each boundary, so it mostly still worked -- the tell was a handful of
    records that looked like a MissionItem with an oversized header, all near a 32768 boundary.
    """
    blob1 = data[off:off + size]
    if len(blob1) < BLOB1_FIRST_BLOCK_HEADER + BLOB1_BLOCK_HEADER_SIZE:
        raise SaveFormatError("blob1 too short: %d bytes" % len(blob1))
    out = bytearray()
    p = BLOB1_FIRST_BLOCK_HEADER
    blocks = 0
    while p + BLOB1_BLOCK_HEADER_SIZE <= len(blob1):
        flag = blob1[p]
        csize, usize = struct.unpack_from('<II', blob1, p + 1)
        # (the checksum is the u32 at p+9 and isn't verified)
        start = p + BLOB1_BLOCK_HEADER_SIZE
        if csize == 0 or usize == 0 or start + csize > len(blob1):
            break
        if flag == 0 or csize == usize:
            chunk = blob1[start:start + csize]      # stored block, not compressed
        else:
            chunk, _ = lzss_block(blob1, start)
        if len(chunk) < usize:
            raise SaveFormatError("blob1 block %d short: %d < %d" % (blocks, len(chunk), usize))
        out += chunk[:usize]
        p = start + csize
        blocks += 1
        if blocks > 1000:
            raise SaveFormatError("blob1 decompression didn't terminate (>1000 blocks)")
    return bytes(out)


# Checkpoint-code suffix (the part after the dot in blob2's checkpoint ID, e.g. "35C990AE.CA")
# -> human level name. Not a CRC32 hash -- these are literal short mnemonics matching the game's
# own MissionLU_<CODE>#_<Area>_Act# bundle-naming convention (DataPC_POP0WORLD.forge lists them
# directly, e.g. "MissionLU_HC3_Castle_LAIR_Act2").
LEVEL_CODES = {
    'CA': 'Canyon', 'DE': 'Desert', 'TL': 'Temple',
    'HC1': 'Spire of Dreams', 'HC2': 'Royal Gardens',
    'HC3': 'The Palace Rooms', 'HC4': 'Coronation Hall', 'HC5': 'Royal Spire',
    'HC6': 'The Cavern',
    'LR1': 'Tower of Ormazd', 'LR2': 'Tower of Ahriman', 'LR3': "Warrior's Fortress",
    'LR4': "Queen's Tower", 'LR5': 'City of Light', 'LR6': 'City Gate',
    'OB1': 'Machinery Ground', 'OB2': "Heaven's Stair", 'OB3': 'The Observatory',
    'OB4': 'Construction Yard', 'OB5': 'Reservoir', 'OB6': 'The Cauldron',
    'RC1': 'The Windmills', 'RC2': "Martyrs' Tower", 'RC3': "Hunter's Lair",
    'RC4': 'Marshalling Ground', 'RC5': 'The Sun Temple', 'RC6': "King's Gate",
}


def resolve_checkpoint_code(checkpoint_code):
    """Split a blob2 checkpoint code like '35C990AE.CA' into (hash, level_name). Returns
    (None, 'Autosave') for the literal 'AUTOSAV...' slot codes; (hash, None) for an unrecognized
    or unconfirmed suffix."""
    if checkpoint_code is None:
        return None, None
    if checkpoint_code.upper().startswith('AUTOSAV'):
        return None, 'Autosave'
    if '.' not in checkpoint_code:
        return checkpoint_code, None
    h, suffix = checkpoint_code.split('.', 1)
    return h, LEVEL_CODES.get(suffix)


ROOT_TYPEHASH = 0x89DDA5B  # SaveGameObject


def scan_property_paths(decompressed):
    """Scan the whole buffer for the PropertyPath entry signature
    (`[u32 marker=2][u32 class typehash][u16 flag=0xffff][u32 field name hash]`, 14 bytes) and
    return every (class_name, field_name) pair found, with occurrence counts.

    Marker must be exactly 2 -- broadening it matches CompositeSaveGameObject children's own
    [typehash][uid] headers when uid is small. The class->field gap is 6 bytes, not 4.
    """
    pairs = {}
    n = len(decompressed)
    for i in range(0, n - 14):
        if struct.unpack_from('<I', decompressed, i)[0] != 2:
            continue
        cls = struct.unpack_from('<I', decompressed, i + 4)[0]
        fld = struct.unpack_from('<I', decompressed, i + 10)[0]
        cls_name = names_lookup(cls)
        fld_name = names_lookup(fld)
        if not cls_name.startswith('0x') and not fld_name.startswith('0x'):
            key = (cls_name, fld_name)
            pairs[key] = pairs.get(key, 0) + 1
    return pairs


def walk_property_declarations(decompressed, start, end=None):
    """Walk a contiguous run of 17-byte PropertyPath declaration entries starting at `start`:
    `[u32 marker=2][u32 class typehash][u16 per-instance index][u32 field-name hash][u16
    tail=0xffff]`. Stops at the first entry that doesn't match this exact shape. Returns a list of
    dicts (class_name, index, field_name). These are pure declarations, no values -- the value
    storage that follows is only understood for a couple of field kinds so far (see
    decode_property_value / CONFIRMED_VALUE_OFFSETS)."""
    out = []
    p = start
    limit = end if end is not None else len(decompressed)
    while p + 17 <= limit:
        marker = struct.unpack_from('<I', decompressed, p)[0]
        if marker != 2:
            break
        cls = struct.unpack_from('<I', decompressed, p + 4)[0]
        idx = struct.unpack_from('<H', decompressed, p + 8)[0]
        fld = struct.unpack_from('<I', decompressed, p + 10)[0]
        tail = struct.unpack_from('<H', decompressed, p + 14)[0]
        if tail != 0xffff:
            break
        out.append(dict(offset=p, class_name=names_lookup(cls), index=idx, field_name=names_lookup(fld)))
        p += 17
    return out


# 24-byte type-manifest entries: [3 zero bytes][u32 type hash][2 zero bytes][kind][14 zero bytes].
# Describes a field's TYPE, not its value -- two "confirmed offsets" elsewhere in this file got
# retracted after treating this byte as data (it's the schema's kind code: 25=Enum, 7=u32, and it
# never varies). Still useful for locating where a record's real value blob starts.
def scan_type_manifest_entries(decompressed):
    """Every 24-byte type-manifest entry in the buffer. Returns [(offset, hash, name, kind), ...].
    Position-independent (the hash is the identity, not the declaration order), and validated
    against the schema's own name table -- an entry is only accepted if its hash resolves to a real
    name, which keeps this from matching coincidental zero-padded regions elsewhere in the file.

    The 4th tuple element is a schema KIND code (see save_schema.PRIM_WIDTH), not a value."""
    out = []
    n = len(decompressed)
    for i in range(0, n - 24):
        if decompressed[i] or decompressed[i + 1] or decompressed[i + 2]:
            continue
        if decompressed[i + 7] or decompressed[i + 8]:
            continue
        if decompressed[i + 10:i + 24] != b'\x00' * 14:
            continue
        h = struct.unpack_from('<I', decompressed, i + 3)[0]
        name = names_lookup(h)
        # Accept any hash the schema can name -- entries point at either a bare type name
        # ("MissionItemState") or a "Class::Field" debug name, and both are real.
        if not name.startswith('0x'):
            out.append((i, h, name, decompressed[i + 9]))
    return out


def enumerate_savegameobjects(decompressed):
    """List every SaveGameObject-typed record at a 4-byte-aligned offset.

    blob1 is an array of ~225 SaveGameObject instances, one per stateful world object. `end` is
    just "where the next entry starts", not a decoded size field.

    Misses any record at a non-4-aligned offset (e.g. PopGamePlayManager) -- a general unaligned
    rescan also picks up CompositeSaveGameObject's internal 91-byte sub-blocks and floods the
    result with junk, so use find_unaligned_records() for specific classes instead.

    `uid` is the 4 bytes after the typehash, genuine per-instance identity (unlike the shared,
    byte-identical template tail of a normal 364-byte entry).
    """
    offs = [i for i in range(0, len(decompressed) - 4, 4)
            if struct.unpack_from('<I', decompressed, i)[0] == ROOT_TYPEHASH]
    out = []
    for i, off in enumerate(offs):
        end = offs[i + 1] if i + 1 < len(offs) else len(decompressed)
        uid = struct.unpack_from('<I', decompressed, off + 4)[0] if off + 8 <= len(decompressed) else None
        out.append(dict(offset=off, end=end, size=end - off, uid=uid,
                         kind='normal' if end - off == 364 else 'outlier'))
    return out


# MissionItem records are exactly 91 bytes, stored back to back in runs of arbitrary length.
#
# 91 isn't a multiple of 4, so every 364 bytes (LCM(91,4)) a 4-aligned scan lands on another
# MissionItem -- which used to get misread as one CompositeSaveGameObject with 4 children. It
# wasn't: those "children" are unrelated neighbors that happen to span the alignment period (hence
# groups mixing e.g. HC3_LAIR with PowerTutorial_Dash). Confirmed by most such "groups" having
# another MissionItem 91 bytes before them, i.e. they start mid-run.
MISSION_ITEM_SIZE = 91
_MISSION_ITEM_FIELD_HASHES = [zlib.crc32(x) & 0xffffffff
                              for x in (b'MIState', b'WasEverCompleted', b'WasEverPlayed')]

# A MissionItem is always the standard 25-byte header. Records that looked like a larger-header
# variant turned out to be the decompressor's fault, not a real shape -- see decompress_blob1.
_MISSION_ITEM_HEADER = 25


def is_mission_item(decompressed, offset):
    """True if a MissionItem record starts here. Checks the typehash, the declared field count, all
    three name-table hashes at their 11-byte stride, and the value blob's own length prefix -- five
    independent things, so it doesn't fire on lookalike bytes."""
    if offset < 0 or offset + MISSION_ITEM_SIZE > len(decompressed):
        return False
    if struct.unpack_from('<I', decompressed, offset)[0] != ROOT_TYPEHASH:
        return False
    if struct.unpack_from('<I', decompressed, offset + 16)[0] != 3:
        return False
    if any(struct.unpack_from('<I', decompressed, offset + 25 + 11 * i)[0] != h
           for i, h in enumerate(_MISSION_ITEM_FIELD_HASHES)):
        return False
    return struct.unpack_from('<I', decompressed, offset + 81)[0] == 6


def find_mission_items(decompressed):
    """Every MissionItem record in the buffer, in file order, regardless of alignment. Returns
    dicts of (offset, size, uid, state, was_ever_completed, was_ever_played)."""
    out = []
    p = 0
    n = len(decompressed)
    while p < n - MISSION_ITEM_SIZE:
        if not is_mission_item(decompressed, p):
            p += 1
            continue
        while is_mission_item(decompressed, p):
            values = p + 85                # blob starts right after its u32 length prefix
            out.append(dict(offset=p, size=MISSION_ITEM_SIZE,
                            uid=struct.unpack_from('<I', decompressed, p + 4)[0],
                            state=decompressed[values],
                            state_offset=values,
                            was_ever_completed=decompressed[values + 4],
                            was_ever_played=decompressed[values + 5]))
            p += MISSION_ITEM_SIZE
    return out


# Per-region progress trackers: light seeds collected per area (the in-game map numbers), as
# opposed to PopGameplaySettings.SparkleCount which is the running total.
#
# Same alignment trap as MissionItem -- most sit unaligned right after a MissionItem run, so
# they're found by signature rather than the aligned scanner.
_SECTION_GAME_DATA_FIELDS = [b'NbTimeVisited', b'NbSparklesCollected',
                             b'FertileGroundStatus', b'NbFightsDone']
_SECTION_GAME_DATA_HASHES = [zlib.crc32(x) & 0xffffffff for x in _SECTION_GAME_DATA_FIELDS]


def is_section_game_data(decompressed, offset):
    """True if a SectionGameData record starts here (typehash, field count of 4, and all four
    name-table hashes at their 11-byte stride)."""
    if offset < 0 or offset + 110 > len(decompressed):
        return False
    if struct.unpack_from('<I', decompressed, offset)[0] != ROOT_TYPEHASH:
        return False
    if struct.unpack_from('<I', decompressed, offset + 16)[0] != 4:
        return False
    return [struct.unpack_from('<I', decompressed, offset + 25 + 11 * i)[0]
            for i in range(4)] == _SECTION_GAME_DATA_HASHES


# The length prefix sits at a fixed +100 in the overwhelming majority of records. Don't anchor to
# the record's end instead -- length isn't constant (some records carry extra trailing bytes),
# which would silently shift the blob.
SECTION_GAME_DATA_BLOB_PREFIX_OFFSET = 100

# Max light seeds per region: 45 (25 for the 4 LAIR regions) -- confirmed by a 100%-collected save
# summing to exactly SparkleCount's 1000. Above 45 means the record was never written by the game.
MAX_SPARKLES_PER_REGION = 45


# The 24 seed-bearing regions: 4 areas x 6 regions, named AREA + digit 1-6 ("HC1_LeftTower").
# Two-digit names ("HC25_RockyCliff") are corridors and never hold seeds -- confirmed against a
# 100%-collected save. Position 3 in each area is the boss lair (25 seeds instead of 45).
SEED_REGION_AREAS = ('HC', 'LR', 'OB', 'RC')
_SEED_REGION_RE = re.compile(r'^(HC|LR|OB|RC)([1-6])_')


def seed_region_rank(region_name):
    """Fixed display position 0-23 for a seed-bearing region, or None if it isn't one. Deliberately
    independent of how many seeds are currently collected, so the list stays in the same order from
    a fresh save to a finished one."""
    m = _SEED_REGION_RE.match(region_name)
    if not m:
        return None
    return SEED_REGION_AREAS.index(m.group(1)) * 6 + int(m.group(2)) - 1


def _section_game_data_blob(decompressed, record_offset, limit):
    """Start of a SectionGameData record's 16-byte value blob, or None."""
    off = record_offset + SECTION_GAME_DATA_BLOB_PREFIX_OFFSET
    if (off + 4 + SECTION_GAME_DATA_BLOB_LEN <= len(decompressed)
            and struct.unpack_from('<I', decompressed, off)[0] == SECTION_GAME_DATA_BLOB_LEN):
        return off + 4
    return _find_length_prefixed_blob(decompressed, record_offset + 69,
                                       SECTION_GAME_DATA_BLOB_LEN, min(record_offset + 220, limit))


def find_section_game_data(decompressed):
    """Every region tracker in the buffer, regardless of alignment. Returns dicts of (offset, uid,
    blob_offset, NbTimeVisited, NbSparklesCollected, FertileGroundStatus, NbFightsDone).

    Each record carries `initialized`. A region the player never loaded still gets a record, but
    the game never fills its value blob in, so it reads as whatever was in memory -- millions of
    light seeds, a visit count that's really a float bit pattern. Those are flagged rather than
    dropped (the record genuinely exists, and hiding it would be its own kind of lie) and callers
    should leave them out of any total.

    FertileGroundStatus is the other gate: it's a 3-member enum, so a record whose blob was located
    wrongly gets dropped instead of reported with junk numbers."""
    out = []
    n = len(decompressed)
    p = 0
    while p < n - 110:
        if not is_section_game_data(decompressed, p):
            p += 1
            continue
        name_table_end = p + 25 + 4 * 11
        start = _section_game_data_blob(decompressed, p, n)
        if start is not None:
            visits, sparkles, fertile, fights = struct.unpack_from('<4I', decompressed, start)
            if fertile <= 2:
                out.append(dict(offset=p, uid=struct.unpack_from('<I', decompressed, p + 4)[0],
                                blob_offset=start, NbTimeVisited=visits,
                                NbSparklesCollected=sparkles, FertileGroundStatus=fertile,
                                NbFightsDone=fights,
                                initialized=sparkles <= MAX_SPARKLES_PER_REGION))
        p += MISSION_ITEM_SIZE
    return out


# CompositeSaveGameObject -- the real one, not the 364-byte alignment artifact (see
# find_mission_items). Its one schema field, SavedObjects, is an array of per-component saved
# state: lever angles, pool rotations, fight/illusion flags, transforms.
#
#   header  0..31   [typehash][uid][2 class tags][own property count = 0][gap][u32 child count @+28]
#   child           [uid][2 tags][property count = 1][5-byte gap]
#                   [11-byte name record][5 bytes][u16 kind][u32 blob length][blob]
#                   -- child size = 43 + blob length
#
# Grammar checked against the corpus: most composites end exactly on the next one; only a small
# fraction fail to parse -- all of them children with a property count of 0 rather than 1: no
# name record, no kind/blob, just the 21-byte header plus 3 trailing zero bytes (24 bytes total,
# always 00 00 00, never resolves to an instance name). Handling that second shape takes the
# unparsed fraction from ~1.5% to zero across the whole corpus -- every composite in every save
# now parses.
COMPOSITE_TYPEHASH = 0x2198212e
_COMPOSITE_HEADER = 32
_COMPOSITE_CHILD_FIXED = 43
_COMPOSITE_EMPTY_CHILD_SIZE = 24


def parse_composite(decompressed, offset):
    """Parse one CompositeSaveGameObject at `offset`. Returns dict(offset, uid, length, children)
    where each child is dict(uid, name, kind, value_offset, value_len) for a real property, or
    dict(uid, name=None, empty=True) for a 0-property child. None if the bytes don't fit the
    grammar."""
    n = len(decompressed)
    if offset + _COMPOSITE_HEADER > n:
        return None
    if struct.unpack_from('<I', decompressed, offset)[0] != COMPOSITE_TYPEHASH:
        return None
    count = struct.unpack_from('<I', decompressed, offset + 28)[0]
    if not (0 <= count <= 64):
        return None
    p = offset + _COMPOSITE_HEADER
    children = []
    for _ in range(count):
        if p + 21 > n:
            return None
        nprops = struct.unpack_from('<I', decompressed, p + 12)[0]
        uid = struct.unpack_from('<I', decompressed, p)[0]
        if nprops == 0:
            if p + _COMPOSITE_EMPTY_CHILD_SIZE > n:
                return None
            children.append(dict(uid=uid, name=None, empty=True))
            p += _COMPOSITE_EMPTY_CHILD_SIZE
        elif nprops == 1:
            if p + _COMPOSITE_CHILD_FIXED > n:
                return None
            name_hash = struct.unpack_from('<I', decompressed, p + 21)[0]
            kind = struct.unpack_from('<H', decompressed, p + 37)[0]
            blob_len = struct.unpack_from('<I', decompressed, p + 39)[0]
            if blob_len > 4096 or p + _COMPOSITE_CHILD_FIXED + blob_len > n:
                return None
            children.append(dict(uid=uid, name=names_lookup(name_hash), name_hash=name_hash,
                                 kind=kind, value_offset=p + _COMPOSITE_CHILD_FIXED,
                                 value_len=blob_len))
            p += _COMPOSITE_CHILD_FIXED + blob_len
        else:
            return None
    return dict(offset=offset, uid=struct.unpack_from('<I', decompressed, offset + 4)[0],
                length=p - offset, children=children)


def find_composites(decompressed):
    """Every CompositeSaveGameObject that parses cleanly, in file order."""
    out = []
    needle = struct.pack('<I', COMPOSITE_TYPEHASH)
    i = decompressed.find(needle)
    while i != -1:
        rec = parse_composite(decompressed, i)
        if rec is not None:
            out.append(rec)
            i = decompressed.find(needle, i + max(rec['length'], 4))
        else:
            i = decompressed.find(needle, i + 4)
    return out


# Struct formats for the scalar kinds these children actually use. Multi-number kinds (Vector4,
# quaternion, transform) are left out on purpose -- callers show those as components.
COMPOSITE_SCALAR_FMT = {0: 'B', 3: 'b', 5: '<H', 6: '<I', 7: '<I', 10: '<f', 0x19: '<I'}


def composite_child_value(decompressed, child):
    """Decoded value for a child whose kind is a plain scalar, else None (including empty
    (0-property) children, which have no value at all)."""
    if child.get('empty'):
        return None
    fmt = COMPOSITE_SCALAR_FMT.get(child['kind'])
    if fmt is None or struct.calcsize(fmt) != child['value_len']:
        return None
    return struct.unpack_from(fmt, decompressed, child['value_offset'])[0]


# Graph records hold rule-system state. Only Variables (an array) is save-persisted:
#
#   0..24     standard header; count = 1 + number of declarations
#   25..37    RulesLibraryBook reference
#   38..      one 17-byte PropertyPath declaration per variable, in order
#   tail      one float per declaration, same order -- the LAST 4*N bytes of the record
#
# The values were assumed "external" for a long time; they aren't -- they sit at the end of the
# same record, found by anchoring to the end rather than scanning forward. Confirmed sane in 107
# of 108 records (real Durations in seconds, RuntimeValue == OriginalValue on untouched variables).
GRAPH_DECLARATIONS_OFFSET = 38

# Graph subclass per record, keyed by uid (not derivable from the record itself -- the header's
# class tags are shared between subclasses, e.g. VoiceGraph/AnimationGraph are identical). Each of
# these six uids appears exactly once per save with a stable variable count, cross-checked against
# ACViewer's class names.
GRAPH_CLASS_BY_UID = {
    0x0d4bc26a: 'VoiceGraph',
    0x14a38039: 'TutorialGraph',
    0x6fab4001: 'FXGraph',
    0xc4210004: 'AnimationGraph',
    0xc58f04b4: 'CameraGraph',
    0xda22e3a4: 'PopAudioGraph',
    0x20bbc006: 'AchievementSet',
}


def graph_class(uid):
    """Graph subclass name for a record uid, or 'Graph' if it's one we haven't identified."""
    return GRAPH_CLASS_BY_UID.get(uid & 0xffffffff, 'Graph')


def parse_graph(decompressed, offset, end=None):
    """Parse a Graph record at `offset`. Returns dict(offset, uid, declarations, values, length)
    or None. `end` is the record end; when omitted it's taken as the next record header."""
    n = len(decompressed)
    if offset + GRAPH_DECLARATIONS_OFFSET > n:
        return None
    if struct.unpack_from('<I', decompressed, offset)[0] != ROOT_TYPEHASH:
        return None
    # decls CAN legitimately be empty -- a Graph with no rule variables at all still declares
    # RulesLibraryBook (which is what got this offset here in the first place, via find_graphs),
    # it just has nothing after it. One such record (uid 0x20bbc006) appears once per save; without
    # this it fell through to the generic array as an unclassified "(unrecognized shape)".
    decls = walk_property_declarations(decompressed, offset + GRAPH_DECLARATIONS_OFFSET)
    if end is None:
        end = n
        for th in (ROOT_TYPEHASH, COMPOSITE_TYPEHASH):
            j = decompressed.find(struct.pack('<I', th),
                                   offset + GRAPH_DECLARATIONS_OFFSET + 17 * len(decls))
            if j != -1:
                end = min(end, j)
    start = end - 4 * len(decls)
    if start < offset + GRAPH_DECLARATIONS_OFFSET + 17 * len(decls):
        return None
    values = []
    for k, d in enumerate(decls):
        values.append(dict(index=d['index'], field_name=d['field_name'],
                           class_name=d['class_name'], offset=start + 4 * k,
                           value=struct.unpack_from('<f', decompressed, start + 4 * k)[0]))
    # Variables is a polymorphic array (ObjectPtr<IGraphVariable>) -- each element is its own
    # object, typed by the fields it declares (Duration -> DelayTimer, RuntimeValue+OriginalValue
    # -> GraphVariable). Grouping by declaration index rebuilds the array, matching ACViewer.
    grouped = {}
    for v in values:
        grouped.setdefault(v['index'], []).append(v)
    variables = []
    for idx in sorted(grouped):
        fields = grouped[idx]
        names_here = {f['field_name'] for f in fields}
        if names_here == {'Duration'}:
            klass = 'DelayTimer'
        elif names_here == {'RuntimeValue', 'OriginalValue'}:
            klass = 'GraphVariable'
        else:
            klass = 'IGraphVariable'
        variables.append(dict(index=idx, klass=klass, fields=fields))
    uid = struct.unpack_from('<I', decompressed, offset + 4)[0]
    return dict(offset=offset, uid=uid, klass=graph_class(uid), declarations=decls, values=values,
                variables=variables, length=end - offset)


def find_graphs(decompressed):
    """Every Graph record, found by its RulesLibraryBook property (unaligned ones included)."""
    out = []
    needle = struct.pack('<I', zlib.crc32(b'RulesLibraryBook') & 0xffffffff)
    i = decompressed.find(needle)
    while i != -1:
        rec = parse_graph(decompressed, i - 25)
        if i >= 25 and rec is not None:
            out.append(rec)
        i = decompressed.find(needle, i + 1)
    return out


def _find_next_record(decompressed, start, limit=4096):
    """First ROOT_TYPEHASH/COMPOSITE_TYPEHASH occurrence at or after `start`, any alignment."""
    end = min(start + limit, len(decompressed))
    for cand in range(start, end):
        if struct.unpack_from('<I', decompressed, cand)[0] in (ROOT_TYPEHASH, COMPOSITE_TYPEHASH):
            return cand
    return None


# TrapsManager.Traps / PowersManager.Powers: a per-element struct array. Declared with the same
# 17-byte PropertyPath entries as Graph.Variables (one run of 3 per element: type/Enabled/
# ManualActivation), but the record header is a non-standard 21 bytes (typehash + 3 fields + count
# + 1-byte gap, not the usual 25-byte property-table header) and there's no length-prefixed value
# blob -- the values are just packed at the record's tail, in declaration order, each field its own
# native width. Located by working backward from the next record's start.
ARRAY_CONTAINER_FIELDS = {
    'Traps': ('TrapType', 'Enabled', 'ManualActivation'),
    'Powers': ('MagicPlateComponentType', 'Enabled', 'ManualActivation'),
}
ARRAY_ELEMENT_WIDTH = {'TrapType': 4, 'MagicPlateComponentType': 4, 'Enabled': 1, 'ManualActivation': 1}


def find_array_containers(decompressed, field_name):
    """Every TrapsManager/PowersManager instance for `field_name` ('Traps' or 'Powers'). Returns
    dicts(offset, uid, elements) -- elements is a list of {field_name: value} dicts, one per
    declared array index."""
    fields = ARRAY_CONTAINER_FIELDS[field_name]
    needle = struct.pack('<I', zlib.crc32(field_name.encode()) & 0xffffffff)
    out = []
    i = decompressed.find(needle)
    while i != -1:
        p = i - 4
        if (p >= 0 and struct.unpack_from('<I', decompressed, p)[0] == 2
                and struct.unpack_from('<H', decompressed, p + 8)[0] == 0):
            rec_off = p - 21
            if rec_off >= 0 and struct.unpack_from('<I', decompressed, rec_off)[0] == ROOT_TYPEHASH:
                decls = walk_property_declarations(decompressed, p)
                vend = p + 17 * len(decls)
                total_w = sum(ARRAY_ELEMENT_WIDTH[d['field_name']] for d in decls)
                nxt = _find_next_record(decompressed, vend)
                if nxt is not None and nxt - vend >= total_w and len(decls) % len(fields) == 0:
                    off = nxt - total_w
                    elements, elem = [], {}
                    for d in decls:
                        w = ARRAY_ELEMENT_WIDTH[d['field_name']]
                        elem[d['field_name']] = (decompressed[off] if w == 1
                                                  else struct.unpack_from('<I', decompressed, off)[0])
                        off += w
                        if len(elem) == len(fields):
                            elements.append(elem)
                            elem = {}
                    uid = struct.unpack_from('<I', decompressed, rec_off + 4)[0]
                    out.append(dict(offset=rec_off, uid=uid, elements=elements, value_offset=nxt - total_w))
        i = decompressed.find(needle, i + 1)
    return out


# PortalDynamicLoaderSaveState.ObjectToSave/ActiveFlag: fixed-capacity (always 50), zero-padded
# u32 arrays following the record's normal property table. The first array is preceded by a
# constant 19-byte type-descriptor block (the field's schema trailer, embedded twice); the second
# array has no descriptor of its own -- just [u32 capacity][capacity x u32] immediately.
_FIXED_ARRAY_PREAMBLE = bytes.fromhex('00000000009e030000000000009e0310000000')
FIXED_ARRAY_CAPACITY = 50


def find_fixed_capacity_arrays(decompressed):
    """Every PortalDynamicLoaderSaveState instance. Returns dicts(offset, uid, object_to_save,
    active_flag, object_to_save_offset, active_flag_offset) -- both value lists are fixed at 50
    entries; a zero entry means "nothing in that slot"."""
    needle = struct.pack('<I', zlib.crc32(b'ObjectToSave') & 0xffffffff)
    out = []
    n = len(decompressed)
    i = decompressed.find(needle)
    while i != -1:
        rec_off = None
        for b in range(0, 400):
            if i - b >= 0 and struct.unpack_from('<I', decompressed, i - b)[0] == ROOT_TYPEHASH:
                rec_off = i - b
                break
        if rec_off is not None:
            t = read_property_table(decompressed, rec_off)
            if t and [p['name'] for p in t['properties']] == ['ObjectToSave', 'ActiveFlag']:
                vstart = t['name_table_end']
                cap = FIXED_ARRAY_CAPACITY
                if (vstart + 19 + 4 + cap * 4 + 4 + cap * 4 <= n
                        and decompressed[vstart:vstart + 19] == _FIXED_ARRAY_PREAMBLE
                        and struct.unpack_from('<I', decompressed, vstart + 19)[0] == cap):
                    list1 = vstart + 23
                    list2_cap_off = list1 + 4 * cap
                    if struct.unpack_from('<I', decompressed, list2_cap_off)[0] == cap:
                        list2 = list2_cap_off + 4
                        obj_ids = [struct.unpack_from('<I', decompressed, list1 + 4 * k)[0] for k in range(cap)]
                        flags = [struct.unpack_from('<I', decompressed, list2 + 4 * k)[0] for k in range(cap)]
                        uid = struct.unpack_from('<I', decompressed, rec_off + 4)[0]
                        out.append(dict(offset=rec_off, uid=uid, object_to_save=obj_ids, active_flag=flags,
                                        object_to_save_offset=list1, active_flag_offset=list2))
        i = decompressed.find(needle, i + 1)
    return out


# CorruptionZone and IGraphRule share an identical 48-byte, one-property shape:
#
#   0..24   header (property count = 1)
#   25..35  name record
#   36..42  padding + u16 kind
#   43      u32 blob length = 1
#   47      the value, at the record boundary
#
# Most sit unaligned (following a MissionItem run), so found by signature rather than the old
# last-byte-of-record rule, which only worked for records the aligned scan could see.
SINGLE_FIELD_RECORD_SIZE = 48
SINGLE_FIELD_VALUE_OFFSET = 47


def find_single_field_records(decompressed, field_name):
    """Every 48-byte one-property record for `field_name`, regardless of alignment. Returns dicts
    of (offset, uid, value_offset, value)."""
    needle = struct.pack('<I', zlib.crc32(field_name.encode()) & 0xffffffff)
    out = []
    n = len(decompressed)
    i = decompressed.find(needle)
    while i != -1:
        p = i - 25
        if (p >= 0 and p + SINGLE_FIELD_RECORD_SIZE <= n
                and struct.unpack_from('<I', decompressed, p)[0] == ROOT_TYPEHASH
                and struct.unpack_from('<I', decompressed, p + 16)[0] == 1
                and struct.unpack_from('<I', decompressed, p + 43)[0] == 1):
            out.append(dict(offset=p, uid=struct.unpack_from('<I', decompressed, p + 4)[0],
                            value_offset=p + SINGLE_FIELD_VALUE_OFFSET,
                            value=decompressed[p + SINGLE_FIELD_VALUE_OFFSET]))
        i = decompressed.find(needle, i + 1)
    return out


def find_unaligned_records(decompressed):
    """Find census-class records enumerate_savegameobjects() misses due to non-4-aligned offsets.
    For each class with enough declared fields, anchors on the first few field-name hashes at
    their 11-byte stride and requires all of them to line up.

    Only returns unaligned records (aligned ones are already found by enumerate_savegameobjects),
    and excludes anything inside a 364-byte composite-artifact span. Returns dicts of (offset,
    klass, uid) -- point discoveries, not a complete/orderable record list."""
    composite_spans = [(o['offset'], o['end']) for o in enumerate_savegameobjects(decompressed)
                        if o['kind'] == 'normal']

    def _inside_composite(off):
        return any(lo <= off < hi for lo, hi in composite_spans)

    # A 2-hash anchor isn't strong enough -- small classes like MissionItem produce false
    # positives from field-name hashes recurring elsewhere. Require enough fields for a 4-hash
    # anchor.
    MIN_FIELDS = 6
    ANCHOR_LEN = 4

    census = save_persisted_census()
    found = []
    seen_offsets = set()
    for cls, fields in census.items():
        if len(fields) < MIN_FIELDS:
            continue
        anchor_hashes = [zlib.crc32(fields[k][0].encode()) & 0xffffffff
                          for k in range(min(ANCHOR_LEN, len(fields)))]
        b0 = struct.pack('<I', anchor_hashes[0])
        i = decompressed.find(b0)
        while i >= 0:
            ok = all(decompressed[i + 11 * k:i + 11 * k + 4] == struct.pack('<I', h)
                     for k, h in enumerate(anchor_hashes))
            if ok:
                rec_off = i - 25   # back up to the record header (see read_property_table)
                if (rec_off >= 0 and rec_off % 4 != 0 and rec_off not in seen_offsets
                        and not _inside_composite(rec_off)
                        and struct.unpack_from('<I', decompressed, rec_off)[0] == ROOT_TYPEHASH):
                    seen_offsets.add(rec_off)
                    uid1 = struct.unpack_from('<I', decompressed, rec_off + 4)[0]
                    found.append(dict(offset=rec_off, uid=uid1, klass=cls))
            i = decompressed.find(b0, i + 1)
    return found


# The POP0.schema field-flag bit 0x08000000 marks every save-persisted field, for every class in
# the game -- gives a complete, static, whole-game census with no live-memory reads needed. Cached
# at first use since load_schema()/the census walk are a bit of work.
_CENSUS = None


def save_persisted_census():
    """Returns {class_name: [(field_name, kind, width_or_None), ...]} for every class in
    POP0.schema that has at least one field flagged save-persisted (fl & save_schema.SAVE_PERSIST_BIT)."""
    global _CENSUS
    if _CENSUS is not None:
        return _CENSUS
    import save_schema as SS
    T, names = SS.load_schema()
    census = {}
    for th, info in T.items():
        hits = []
        for fl, nh, fth, tr in info['fields']:
            if fl & SS.SAVE_PERSIST_BIT:
                kind = (tr >> 16) & 0x1f
                hits.append((names.get(nh, '%#010x' % nh), kind, SS.PRIM_WIDTH.get(kind)))
        if hits:
            census[names.get(th, '%#010x' % th)] = hits
    _CENSUS = census
    return census


_FULL_SCHEMA_CENSUS = None


def full_schema_census():
    """Same shape as save_persisted_census() but every declared field, not just SAVE_PERSIST ones.
    Fallback in guess_record_class() for records whose only resolvable property is
    SERIALIZE_BIT-only (e.g. Graph.RulesLibraryBook) -- real instances that deserve a class label
    instead of '(no class match)'."""
    global _FULL_SCHEMA_CENSUS
    if _FULL_SCHEMA_CENSUS is not None:
        return _FULL_SCHEMA_CENSUS
    import save_schema as SS
    T, names = SS.load_schema()
    census = {}
    for th, info in T.items():
        hits = []
        for fl, nh, fth, tr in info['fields']:
            kind = (tr >> 16) & 0x1f
            hits.append((names.get(nh, '%#010x' % nh), kind, SS.PRIM_WIDTH.get(kind)))
        if hits:
            census[names.get(th, '%#010x' % th)] = hits
    _FULL_SCHEMA_CENSUS = census
    return census


def _best_census_match(want, census):
    """Shared scoring core for guess_record_class(): the census class whose own field-name set
    overlaps `want` the most, ties broken by fewest extra/missing fields. Returns (class_name,
    score) or (None, 0)."""
    best_cls, best_score = None, 0
    for cls, fields in census.items():
        have = set(nm for nm, kind, w in fields)
        overlap = len(want & have)
        if overlap == 0:
            continue
        # score: overlap count, penalized a little for size mismatch (extra/missing fields)
        score = overlap - 0.1 * abs(len(have) - len(want))
        if score > best_score or (score == best_score and best_cls is None):
            best_cls, best_score = cls, score
    return (best_cls, best_score) if best_cls else (None, 0)


def guess_record_class(property_names):
    """Given a list of resolved property names found in one property-table record (see
    read_property_table), try to identify which census class this record is an instance of: the
    census class whose own persisted-field-name set is the best match (most names in common,
    ties broken by fewest extra/missing). Returns (class_name, score) or (None, 0) if nothing
    matches. Best-effort label for the UI, not a structural guarantee.

    Tries save_persisted_census() first (authoritative). Falls back to full_schema_census() only
    if that finds nothing -- see its docstring for why some real records need this."""
    want = set(property_names)
    if not want:
        return None, 0
    cls, score = _best_census_match(want, save_persisted_census())
    if cls:
        return cls, score
    return _best_census_match(want, full_schema_census())


def read_property_table(decompressed, record_offset, record_size=None):
    """Decode a "named property table" SaveGameObject entry -- not opaque per-object state, a
    real property registry with human-readable names.

    Layout: [typehash(4)][size(4)][uid1(4)][uid2(4)][count(4)][5-byte gap][count x 11-byte name
    records][value region]. Each name record's first 4 bytes are a `zlib.crc32(name)` hash
    resolvable via the schema's own `names` table.

    The trailing value region's exact per-property-type layout isn't fully cracked in general (see
    CONFIRMED_VALUE_OFFSETS for the specific fields that are). Returns None if this doesn't look
    like a property-table record (implausible count, or the first name doesn't land where
    expected) so callers can fall back to `read_slots()`/raw hex.
    """
    HEADER = 25
    NAME_REC = 11
    if record_size == 364:
        # CompositeSaveGameObject.SavedObjects shape (4 nested 91-byte children, see read_slots()).
        # Reading it as one flat table would splice four separate records together.
        #
        # The MIState/WasEverCompleted/WasEverPlayed hashes visible in here were once written off as
        # coincidence; they aren't. Each child is a genuine MissionItem record -- same field count,
        # same name table, same 6-byte value blob -- confirmed on 35741 of 35744 children across the
        # corpus. The guard is still right, just not for the reason first assumed.
        return None
    if record_offset + HEADER > len(decompressed):
        return None
    th = struct.unpack_from('<I', decompressed, record_offset)[0]
    if th != ROOT_TYPEHASH:
        return None
    count = struct.unpack_from('<I', decompressed, record_offset + 16)[0]
    if not (0 < count <= 300):
        return None
    p = record_offset + HEADER
    if p + count * NAME_REC > len(decompressed):
        return None
    props = []
    for i in range(count):
        h = struct.unpack_from('<I', decompressed, p)[0]
        name = names_lookup(h)
        if name.startswith('0x') and not _looks_like_real_hash(h):
            # Some records embed a nested sub-structure partway through their declared `count`
            # instead of a flat run of name records -- reading past that point as if it were still
            # flat produces garbage "hashes" (an incrementing index byte + constant suffix, not
            # real CRC32 output). Stop here rather than return junk entries.
            break
        props.append(dict(hash=h, name=name))
        p += NAME_REC
    return dict(count=len(props), properties=props, name_table_end=p)


def _looks_like_real_hash(h):
    """A real CRC32 output should look like uniformly-random bytes. Structural read-desync
    artifacts (see read_property_table) tend to have long runs of 0x00/0xff instead."""
    b = h.to_bytes(4, 'little')
    degenerate = sum(1 for x in b if x in (0x00, 0xff))
    return degenerate <= 1


def names_lookup(h):
    import save_schema as SS
    _, names = SS.load_schema()
    return names.get(h, '%#010x' % h)


# property_hash -> (relative byte offset from record start, struct format). Found by diffing two
# saves at the same spot and matching records by UID. Keep this list short and high-confidence --
# only add an offset once you've seen a value change in a way that actually makes sense.
CONFIRMED_VALUE_OFFSETS = {
    # record[0]'s 5 simple properties, packed as 4-byte slots from 473 (record[0]-specific, not a
    # general rule). CurrentPopGameStage: story-progression enum (3=HealingFertileGrounds matches
    # ENUM_NAMES). NumberCompletedFight/SparkleCount: counters. LastPopEnvironmentAreaPortalID:
    # per-portal identity hash. LastPopEnvironmentAreaPortalBlendingRatio: float, 0->1 on blend.
    zlib.crc32(b'CurrentPopGameStage') & 0xffffffff: (473, '<I'),
    zlib.crc32(b'NumberCompletedFight') & 0xffffffff: (477, '<I'),
    zlib.crc32(b'SparkleCount') & 0xffffffff: (481, '<I'),
    zlib.crc32(b'LastPopEnvironmentAreaPortalID') & 0xffffffff: (485, '<I'),
    zlib.crc32(b'LastPopEnvironmentAreaPortalBlendingRatio') & 0xffffffff: (489, '<f'),

    # Ability/stamina tracker: 19 ability-lock bools then 8 StaminaBonus* ints, one length-prefixed
    # blob at the end of the record (u32 length @537, bools 541..559, ints 560..591). Byte 540 is
    # a pad (always 0); 559 is the real last bool, which is what fixes the run at 541 -- confirmed
    # via a diff that caught DeflectLocked flipping right when it's first unlocked.
    #
    # An earlier StaminaBonus* placement at 479..535 was retracted (every save read a literal type
    # tag there). The real values climb in multiples of 15 over a playthrough and reset to 0 on a
    # new one for Hunter/Concubine/MourningKing; Warrior/MonsterX/Guard are 0 throughout this corpus.
    zlib.crc32(b'StateOffensiveLocked') & 0xffffffff: (541, 'B'),
    zlib.crc32(b'StateDefensiveLocked') & 0xffffffff: (542, 'B'),
    zlib.crc32(b'StateGooLocked') & 0xffffffff: (543, 'B'),
    zlib.crc32(b'StateHealthRegenLocked') & 0xffffffff: (544, 'B'),
    zlib.crc32(b'StateDisruptLocked') & 0xffffffff: (545, 'B'),
    zlib.crc32(b'StateGooSpitLocked') & 0xffffffff: (546, 'B'),
    zlib.crc32(b'StatePainLocked') & 0xffffffff: (547, 'B'),
    zlib.crc32(b'ComplexAttackWeaponLocked') & 0xffffffff: (548, 'B'),
    zlib.crc32(b'ComplexAttackGooLocked') & 0xffffffff: (549, 'B'),
    zlib.crc32(b'ComplexAttackAcrobaticLocked') & 0xffffffff: (550, 'B'),
    zlib.crc32(b'ComplexAttackGrabLocked') & 0xffffffff: (551, 'B'),
    zlib.crc32(b'DeflectLocked') & 0xffffffff: (552, 'B'),
    zlib.crc32(b'ModifierPushBackLocked') & 0xffffffff: (553, 'B'),
    zlib.crc32(b'ModifierBlockBreakerLocked') & 0xffffffff: (554, 'B'),
    zlib.crc32(b'ModifierKnockDownLocked') & 0xffffffff: (555, 'B'),
    zlib.crc32(b'SpecialAbilityHunterLocked') & 0xffffffff: (556, 'B'),
    zlib.crc32(b'SpecialAbilityWarriorLocked') & 0xffffffff: (557, 'B'),
    zlib.crc32(b'SpecialAbilityConcubineLocked') & 0xffffffff: (558, 'B'),
    zlib.crc32(b'SpecialAbilityAlchemistLocked') & 0xffffffff: (559, 'B'),
    zlib.crc32(b'StaminaBonusHunter') & 0xffffffff: (560, '<I'),
    zlib.crc32(b'StaminaBonusWarrior') & 0xffffffff: (564, '<I'),
    zlib.crc32(b'StaminaBonusConcubine') & 0xffffffff: (568, '<I'),
    zlib.crc32(b'StaminaBonusAlchemist') & 0xffffffff: (572, '<I'),
    zlib.crc32(b'StaminaBonusMourningKing') & 0xffffffff: (576, '<I'),
    zlib.crc32(b'StaminaBonusMourningKingCorrupted') & 0xffffffff: (580, '<I'),
    zlib.crc32(b'StaminaBonusMonsterX') & 0xffffffff: (584, '<I'),
    zlib.crc32(b'StaminaBonusGuard') & 0xffffffff: (588, '<I'),

    # MissionItem's 3 fields sit in a length-prefixed blob at the end of the 91-byte record: u32=6
    # @+81 (matching MIState's 4 bytes + two 1-byte bools), then the values at +85..+90.
    #
    # MIState reads 0/2/3 (the real enum). Both bools are 0 in every record in the corpus --
    # including where MIState is Completed, where WasEverCompleted "should" be 1 -- so the game
    # likely rederives them from MIState on load rather than persisting them.
    zlib.crc32(b'MIState') & 0xffffffff: (85, 'B'),
    zlib.crc32(b'WasEverCompleted') & 0xffffffff: (89, 'B'),
    zlib.crc32(b'WasEverPlayed') & 0xffffffff: (90, 'B'),

    # PopGamePlayManager: per-checkpoint world state. Value blob starts at +465, fields run in
    # declared order from there. Anchored by spotting PrinceMatrix/LoverMatrix (two 4x4 affine
    # transforms back to back, recognizable by row 3 ending in 1.0) landing at +481 in every record.
    #
    # Validated by values that couldn't survive a wrong offset: CameraOrientation is a unit
    # quaternion, CameraFOV is 44 degrees, CameraPos sits a few units behind the Prince.
    #
    # Chain stops at BondState -- ActiveODDTags (a variable-length array) follows, so everything
    # after it has no fixed offset. CurrentTrapSynchroZone isn't in the record at all.
    zlib.crc32(b'TargetSectionID') & 0xffffffff: (465, '<I'),
    zlib.crc32(b'SpecialGamePlayContext') & 0xffffffff: (477, '<I'),
    zlib.crc32(b'SavedDivisionID') & 0xffffffff: (609, '<I'),
    zlib.crc32(b'SavedCorruptionZoneID') & 0xffffffff: (613, '<I'),
    zlib.crc32(b'CameraFOV') & 0xffffffff: (649, '<f'),
    zlib.crc32(b'CurrentFightCount') & 0xffffffff: (653, '<I'),
    zlib.crc32(b'CurrentAct') & 0xffffffff: (657, '<I'),
    zlib.crc32(b'BondState') & 0xffffffff: (661, '<I'),

    # PopSoundReverbManager: 51-byte record, one field. u32=4 @+43, value @+47. Cleanest example
    # of the length-prefix shape in the file.
    zlib.crc32(b'CurrentPortalSoundReverbSetObjectID') & 0xffffffff: (47, '<I'),
}


# Fields holding several numbers rather than one, so they can't go in CONFIRMED_VALUE_OFFSETS.
# Each entry lists (label, offset relative to the field, struct format). For the two 4x4
# transforms only the translation row (X/Y/Z position) is listed, not the rotation basis.
MULTI_COMPONENT_OFFSETS = {
    zlib.crc32(b'MousePosition') & 0xffffffff: (469, [('X', 0, '<f'), ('Y', 4, '<f')]),
    zlib.crc32(b'PrinceMatrix') & 0xffffffff: (481, [('X', 48, '<f'), ('Y', 52, '<f'), ('Z', 56, '<f')]),
    zlib.crc32(b'LoverMatrix') & 0xffffffff: (545, [('X', 48, '<f'), ('Y', 52, '<f'), ('Z', 56, '<f')]),
    zlib.crc32(b'CameraPos') & 0xffffffff: (617, [('X', 0, '<f'), ('Y', 4, '<f'), ('Z', 8, '<f')]),
    zlib.crc32(b'CameraOrientation') & 0xffffffff: (633, [('X', 0, '<f'), ('Y', 4, '<f'),
                                                          ('Z', 8, '<f'), ('W', 12, '<f')]),
}


# ActiveODDTags is a variable-length array ([u32 count][count x u32] @+665), so the 9 fields after
# it shift by 4 bytes per entry -- derived from the count rather than a fixed offset (scanning for
# the next record's typehash doesn't work; it also matches bytes inside the array/matrix data).
#
# Validated by every downstream bool reading strictly 0/1 and SaveElikaCapturedPos decoding as
# either all-zero or a well-formed transform -- a wrong offset couldn't produce that.
#
# ODD is the contextual Prince/Elika dialogue system: ODDConversation/ODDDialogLine/ODDEvent all
# tie together, and ODDEvent/ODDComponent both declare a field literally named ODDTag. Tag values
# are hashes with no matching name in the forge registry or schema, so the row shows a count.
ACTIVE_ODD_TAGS_COUNT_OFFSET = 665
_POP_GPM_TAIL_LEN = 75


def popgameplaymanager_tail_start(decompressed, record_offset):
    """Absolute offset of the fields that follow PopGamePlayManager's ActiveODDTags array, or None
    if the count doesn't look sane. Callers must already know this record is a PopGamePlayManager
    (the field-name hashes below are unique to it)."""
    off = record_offset + ACTIVE_ODD_TAGS_COUNT_OFFSET
    if off + 4 > len(decompressed):
        return None
    count = struct.unpack_from('<I', decompressed, off)[0]
    if not (0 <= count <= 4096):
        return None
    start = off + 4 + 4 * count
    if start + _POP_GPM_TAIL_LEN > len(decompressed):
        return None
    return start


# Offsets within that tail.
POP_GPM_TAIL_OFFSETS = {
    zlib.crc32(b'SavePrinceDeathHeight') & 0xffffffff: (0, 'B'),
    zlib.crc32(b'SavePrinceDeathHeightValue') & 0xffffffff: (1, '<f'),
    zlib.crc32(b'SaveElikaFollowUpActive') & 0xffffffff: (5, 'B'),
    zlib.crc32(b'SaveElikaActionCoopJump') & 0xffffffff: (6, 'B'),
    zlib.crc32(b'SaveElikaActionMagicPlate') & 0xffffffff: (7, 'B'),
    zlib.crc32(b'SaveElikaActionCompass') & 0xffffffff: (8, 'B'),
    zlib.crc32(b'SaveElikaUnderPersistantScenaricControl') & 0xffffffff: (9, 'B'),
    zlib.crc32(b'SaveElikaIsCaptured') & 0xffffffff: (10, 'B'),
}

_SAVE_ELIKA_CAPTURED_POS = zlib.crc32(b'SaveElikaCapturedPos') & 0xffffffff
_ACTIVE_ODD_TAGS = zlib.crc32(b'ActiveODDTags') & 0xffffffff


def resolve_multi_component(decompressed, record_offset, prop_hash):
    """Component rows for a multi-number field (see MULTI_COMPONENT_OFFSETS), as
    [(label, absolute_offset, fmt, value), ...], or None if this field isn't one of them."""
    entry = MULTI_COMPONENT_OFFSETS.get(prop_hash)
    if entry is not None:
        base, comps = entry
        base += record_offset
    elif prop_hash == _SAVE_ELIKA_CAPTURED_POS:
        # Same translation-row treatment as the other transforms, but its position depends on the
        # array length rather than being fixed.
        tail = popgameplaymanager_tail_start(decompressed, record_offset)
        if tail is None:
            return None
        base = tail + 11
        comps = [('X', 48, '<f'), ('Y', 52, '<f'), ('Z', 56, '<f')]
    else:
        return None
    out = []
    for label, rel, fmt in comps:
        off = base + rel
        if off + struct.calcsize(fmt) > len(decompressed):
            return None
        out.append((label, off, fmt, struct.unpack_from(fmt, decompressed, off)[0]))
    return out


def active_odd_tags(decompressed, record_offset, prop_hash):
    """(count, [u32 entries]) for PopGamePlayManager's ActiveODDTags array, or None."""
    if prop_hash != _ACTIVE_ODD_TAGS:
        return None
    off = record_offset + ACTIVE_ODD_TAGS_COUNT_OFFSET
    if off + 4 > len(decompressed):
        return None
    count = struct.unpack_from('<I', decompressed, off)[0]
    if not (0 <= count <= 4096) or off + 4 + 4 * count > len(decompressed):
        return None
    return count, [struct.unpack_from('<I', decompressed, off + 4 + 4 * i)[0] for i in range(count)]


# AchievementsTrackingData is a nested struct (record[0]'s 6th property), so its 14 sub-fields
# never appear in ptab['properties'] and skip CONFIRMED_VALUE_OFFSETS. Its declared widths sum to
# exactly 51 bytes, packed right after the first 5 fields (493+51=544), no need to decode the
# nested format itself. Offsets below are absolute from record[0]'s start.
ACHIEVEMENTS_TRACKING_DATA_FIELDS = [
    ('TotalCoopJumps', 493, '<I'),
    ('TotalPrinceDeflects', 497, '<I'),
    ('TotalPrinceBlocks', 501, '<I'),
    ('TotalDodgeWarriorAttackCount', 505, '<b'),
    ('DefeatedConcubineNoGrab', 506, '<B'),
    ('DefeatedAlchemistNoAcro', 507, '<B'),
    ('AllCombosUsedAtLeastOnce', 508, '<Q'),
    ('SaveMeCount', 516, '<I'),
    ('TotalPlayingTimeInSec', 520, '<f'),
    ('TotalHealingCompleted', 524, '<I'),
    ('SpeedkillCountAchievement', 528, '<I'),
    ('DialogueWithElikaCount', 532, '<I'),
    ('CompassCount', 536, '<I'),
    ('TotalEnemiesThrown', 540, '<I'),
]


def decode_achievements_tracking_data(decompressed, record_offset):
    """Returns [(name, abs_offset, fmt, value), ...] for AchievementsTrackingData's 14 real
    sub-fields, or None if record_offset+544 doesn't fit (defensive -- every save in the known
    corpus has record[0] at >= 544 bytes, but don't assume that holds forever)."""
    if record_offset + 544 > len(decompressed):
        return None
    out = []
    for name, rel_off, fmt in ACHIEVEMENTS_TRACKING_DATA_FIELDS:
        off = record_offset + rel_off
        val = struct.unpack_from(fmt, decompressed, off)[0]
        out.append((name, off, fmt, val))
    return out


# SectionGameData's 4 values are always the last 16 bytes of the record, packed in declaration
# order -- the gap before them isn't constant (some records carry 8 extra bytes), so this can't be
# a fixed offset from the start. Confirmed by NbTimeVisited only increasing and FertileGroundStatus
# staying in its real enum range across same-uid pairs.
#
# guess_record_class also matches bigger, unrelated records as "SectionGameData" (they share these
# 4 names among many others); SECTION_GAME_DATA_MAX_SIZE keeps this decode from firing on those.
SECTION_GAME_DATA_MAX_SIZE = 150

SECTION_GAME_DATA_TAIL_OFFSETS = {
    zlib.crc32(b'NbTimeVisited') & 0xffffffff: (-16, '<I'),
    zlib.crc32(b'NbSparklesCollected') & 0xffffffff: (-12, '<I'),
    zlib.crc32(b'FertileGroundStatus') & 0xffffffff: (-8, '<I'),
    zlib.crc32(b'NbFightsDone') & 0xffffffff: (-4, '<I'),
}

# CorruptionZone.CorruptionLevel: same last-byte trick, confirmed toggling 0/1 on same-uid records.
CORRUPTION_ZONE_MAX_SIZE = 60
CORRUPTION_ZONE_TAIL_OFFSETS = {
    zlib.crc32(b'CorruptionLevel') & 0xffffffff: (-1, 'b'),
}

# IGraphRule.RuntimeEnabled: same shape, last byte of a 48-byte record. Different instances show
# both 0 and 1, never anything else.
IGRAPH_RULE_MAX_SIZE = 60
IGRAPH_RULE_TAIL_OFFSETS = {
    zlib.crc32(b'RuntimeEnabled') & 0xffffffff: (-1, 'B'),
}

_ROOT_TYPEHASH_BYTES = struct.pack('<I', ROOT_TYPEHASH)


def true_record_end(decompressed, record_offset):
    """Where a record really ends: the next SaveGameObject typehash at ANY alignment, or the end of
    the buffer. enumerate_savegameobjects() only scans 4-aligned offsets, so its `size` overshoots
    badly whenever the following record happens to start unaligned (which is common)."""
    nxt = decompressed.find(_ROOT_TYPEHASH_BYTES, record_offset + 25)
    return len(decompressed) if nxt == -1 else nxt


# (tail_offsets_table, max_size) pairs, checked in order by resolve_property_value_slot -- add new
# "value lives near the end of the record" shapes here instead of writing another branch by hand.
_TAIL_OFFSET_TABLES = (
    (SECTION_GAME_DATA_TAIL_OFFSETS, SECTION_GAME_DATA_MAX_SIZE),
    (CORRUPTION_ZONE_TAIL_OFFSETS, CORRUPTION_ZONE_MAX_SIZE),
    (IGRAPH_RULE_TAIL_OFFSETS, IGRAPH_RULE_MAX_SIZE),
)

# Fallback for SectionGameData records too long for the "last 16 bytes" rule (hundreds of bytes,
# other fields tacked on): find the value blob by its u32=16 length prefix instead. Only safe for
# a blob length distinctive enough not to match noise -- 16 qualifies, 1 (CorruptionZone/
# IGraphRule) doesn't, so those keep the tail rule only.
SECTION_GAME_DATA_BLOB_LEN = 16
SECTION_GAME_DATA_BLOB_FIELDS = {
    zlib.crc32(b'NbTimeVisited') & 0xffffffff: (0, '<I'),
    zlib.crc32(b'NbSparklesCollected') & 0xffffffff: (4, '<I'),
    zlib.crc32(b'FertileGroundStatus') & 0xffffffff: (8, '<I'),
    zlib.crc32(b'NbFightsDone') & 0xffffffff: (12, '<I'),
}


def _find_length_prefixed_blob(decompressed, search_from, blob_len, limit):
    """Start of a value blob introduced by a u32 == blob_len, or None. Scans forward from
    `search_from` (pass the end of the name table -- searching the header would match noise)."""
    p = search_from
    while p + 4 + blob_len <= limit:
        if struct.unpack_from('<I', decompressed, p)[0] == blob_len:
            return p + 4
        p += 1
    return None


def resolve_property_value_slot(decompressed, record_offset, prop_hash, record_size=None,
                                 name_table_end=None):
    """Where decode_property_value's confirmed-offset lookup would read from, without actually
    reading it -- (absolute_byte_offset, struct_format) or None. Split out from
    decode_property_value so save_explorer.py's edit-value feature can write to the exact same
    spot a decode would have read it from, without duplicating the offset-resolution logic."""
    entry = CONFIRMED_VALUE_OFFSETS.get(prop_hash)
    if entry is not None:
        rel_off, fmt = entry
        off = record_offset + rel_off
        if off + struct.calcsize(fmt) > len(decompressed):
            return None
        return off, fmt
    for table, max_size in _TAIL_OFFSET_TABLES:
        tail_entry = table.get(prop_hash)
        if tail_entry is None:
            continue
        tail_rel, fmt = tail_entry
        # Try the caller's size first, then the real record end -- enumerate_savegameobjects()
        # measures to the next ALIGNED typehash, so an unaligned neighbor makes size too big.
        for size in (record_size, true_record_end(decompressed, record_offset) - record_offset):
            if size is None or not (0 < size <= max_size):
                continue
            off = record_offset + size + tail_rel
            if 0 <= off <= len(decompressed) - struct.calcsize(fmt):
                return off, fmt
    tail_entry = POP_GPM_TAIL_OFFSETS.get(prop_hash)
    if tail_entry is not None:
        rel, fmt = tail_entry
        start = popgameplaymanager_tail_start(decompressed, record_offset)
        if start is not None:
            off = start + rel
            if 0 <= off <= len(decompressed) - struct.calcsize(fmt):
                return off, fmt
    blob_entry = SECTION_GAME_DATA_BLOB_FIELDS.get(prop_hash)
    if blob_entry is not None and name_table_end is not None:
        rel, fmt = blob_entry
        start = _find_length_prefixed_blob(decompressed, name_table_end, SECTION_GAME_DATA_BLOB_LEN,
                                            true_record_end(decompressed, record_offset))
        if start is not None:
            off = start + rel
            if 0 <= off <= len(decompressed) - struct.calcsize(fmt):
                return off, fmt
    return None


def decode_property_value(decompressed, record_offset, prop_hash, record_size=None,
                          name_table_end=None):
    """Return a decoded value for a property if its byte position is confirmed (see
    resolve_property_value_slot), else None -- callers should show something honest (not a guess)
    when this returns None."""
    slot = resolve_property_value_slot(decompressed, record_offset, prop_hash,
                                        record_size=record_size, name_table_end=name_table_end)
    if slot is None:
        return None
    off, fmt = slot
    return struct.unpack_from(fmt, decompressed, off)[0]


# POP0.schema marks a field as an enum (kind 0x19) but never names its members. The exe has its
# own enum tables (name string + int value + hash per member), readable from Ghidra. Keyed by
# field name ('MIState'), not the enum's type name ('MissionItemState'), since that's all callers
# have on hand.
ENUM_NAMES = {
    'FertileGroundStatus': {
        0: 'FertileGroundStatus_Available',
        1: 'FertileGroundStatus_Healed',
        2: 'FertileGroundStatus_Locked',
    },
    'MIState': {
        0: 'MissionItemState_Locked',
        1: 'MissionItemState_WaitingForData',
        2: 'MissionItemState_Unlocked',
        3: 'MissionItemState_Completed',
    },
    # Read from the exe's enum tables: descriptor [array_VA][count][type_hash][type_name_VA],
    # then `count` entries of [member_name_VA][value][hash]. Look up by type_hash (the schema's
    # own field-type hash), not by name string -- many enums don't prefix members with the type
    # name. Verified by reproducing MIState/FertileGroundStatus above exactly.
    'CurrentPopGameStage': {
        0: 'Beginning',
        1: 'TutorialDone',
        2: 'TreeOfLifeEvent',
        3: 'HealingFertileGrounds',
        4: 'KilledAriman',
        5: 'BroughtBackElika',
    },
    'CurrentAct': {
        0: 'MissionActType_Invalid',
        1: 'MissionActType_Act1',
        2: 'MissionActType_Act2',
        3: 'MissionActType_Act3',
    },
    'BondState': {
        0: 'STRANGERS',
        1: 'ALLIES',
        2: 'COMPANIONS',
        3: 'BONDSTATE_MAXIMUM',   # sentinel/count marker, not a state the game sits in
    },
    'SpecialGamePlayContext': {
        0: 'SpecialGamePlayContext_None',
        1: 'SpecialGamePlayContext_Puzzle',
        2: 'SpecialGamePlayContext_Challenge',
    },
    'TrapType': {
        0: 'Tremor',
        1: 'Geyser',
        2: 'Swarm',
        3: 'GooGaz',
        4: 'Poison',
        5: 'InvalidTrap',
    },
    'MagicPlateComponentType': {
        0: 'MagicType_Invalid',
        1: 'MagicType_Rebound',
        2: 'MagicType_Target',
        3: 'MagicType_Grapple',
        4: 'MagicType_Dash',
        5: 'MagicType_FlyOnBeam',
    },
}


# Fields that are bit sets rather than numbers -- decimal hides which bits are set.
#
# AllCombosUsedAtLeastOnce: one bit per combo, confirmed by watching it only ever ADD bits across
# a playthrough (never clears one), i.e. "have you pulled this combo off yet".
#
# ActiveSlotData is NOT an enum despite -2/-1/127 looking like one (kind 3/s8, field_typehash=0 --
# a real enum always names its type). Only bits 0 and 7 vary; it's a slot mask matching its
# siblings Active/ActiveSlots/ActiveInAllSlots/IsInWorld. Not collection state: it shows no
# correlation with seeds collected, and the same region's value differs between saves regardless.
BITMASK_FIELDS = frozenset(('AllCombosUsedAtLeastOnce', 'ActiveSlotData'))


def enum_name(field_name, value):
    """Resolve an enum field's raw int value to its real member name (see ENUM_NAMES above), or
    None if this field (or this particular value) isn't in the table yet -- callers should fall
    back to showing the raw int rather than inventing a name."""
    table = ENUM_NAMES.get(field_name)
    if table is None:
        return None
    return table.get(value)


# Names save_schema.py patches to a 1-byte width itself -- that patch leaves them looking like
# kind 0, but they're a 0-255 brightness slider, not flags. Keep them out of the bool set.
_NOT_REALLY_BOOL = frozenset(('Brightness', 'BrightnessDefault'))

_BOOL_FIELDS = None


def bool_field_names():
    """Field names the schema declares as a 1-byte bool (kind 0) everywhere they appear.

    Requiring *every* declaration of a name to be kind 0 is deliberate: a name declared bool on one
    class and something wider on another (Brightness is the real example) isn't safely a bool, and
    a field the editor wrongly treats as one would silently clamp a real value to 0/1."""
    global _BOOL_FIELDS
    if _BOOL_FIELDS is not None:
        return _BOOL_FIELDS
    kinds = {}
    for cls, fields in full_schema_census().items():
        for nm, kind, w in fields:
            kinds.setdefault(nm, set()).add(kind)
    _BOOL_FIELDS = frozenset(nm for nm, ks in kinds.items()
                             if ks == {0} and nm not in _NOT_REALLY_BOOL)
    return _BOOL_FIELDS


def is_bool_field(field_name):
    """True if this field is a plain true/false flag -- lets the editor offer a false/true choice
    instead of a free-text byte box that would happily accept 255."""
    return field_name in bool_field_names()


# A SaveGameObject's `uid` is the same hash-of-instance-name scheme as a .forge bundle's resource
# table, e.g. uid=0x07c1406e -> `OB1_ObjPlatform_FirstTime_Healed`. Some UID fields point into
# per-region world forges rather than just POP0_ROOT.
#
# Scraping forges live is too slow to do on the fly, so build_name_registry.py does it once
# offline into a JSON cache. load_forge_name_registry() uses that cache if present, else falls
# back to a quick POP0_ROOT-only scan.
_FORGE_NAME_REGISTRY = None
# Only used as a fallback live scan when forge_name_registry.json (the pre-built cache, shipped
# alongside this file) is missing -- override with $POP2008_FORGE_PATH if you need it, e.g. to
# point at your own DataPC.forge (found in the game's install directory).
DEFAULT_FORGE_PATH = os.environ.get('POP2008_FORGE_PATH', 'DataPC.forge')
DEFAULT_NAME_BUNDLES = ('POP0_ROOT',)
NAME_REGISTRY_CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'forge_name_registry.json')


def load_forge_name_registry(forge_path=DEFAULT_FORGE_PATH, bundle_names=DEFAULT_NAME_BUNDLES):
    """{instance_uid: real_name}. Loads the offline batch cache (see build_name_registry.py) if
    present -- covers every scraped region forge, tens of thousands of names. Otherwise falls back
    to a live, POP0_ROOT-only scan (fast on its own, but far narrower coverage: only the 705
    MissionItem-family resources, not the broader world-entity set the full cache has). Cached in
    memory after first call. Fails soft (returns {}) if nothing is available on this machine."""
    global _FORGE_NAME_REGISTRY
    if _FORGE_NAME_REGISTRY is not None:
        return _FORGE_NAME_REGISTRY
    if os.path.isfile(NAME_REGISTRY_CACHE):
        try:
            import json
            with open(NAME_REGISTRY_CACHE, 'r', encoding='utf-8') as f:
                raw = json.load(f)
            _FORGE_NAME_REGISTRY = {int(h, 16): nm for h, nm in raw.items()}
            return _FORGE_NAME_REGISTRY
        except Exception:
            pass    # fall through to the live scan below if the cache is missing/corrupt
    registry = {}
    try:
        from forge_file import ForgeFile
        from bundle_reader import parse_bundle
        from resource_names import list_resources
        fo = ForgeFile(forge_path)
        for bn in bundle_names:
            e = next((x for x in fo.named() if x.name == bn), None)
            if e is None:
                continue
            raw = fo.data[e.offset:e.offset + e.size]
            b = parse_bundle(raw, False)
            for r in list_resources(b, False):
                registry[r['hash'] & 0xffffffff] = r['name']
    except Exception:
        pass
    _FORGE_NAME_REGISTRY = registry
    return registry


def resolve_instance_name(uid):
    """uid -> real instance name if it's a known POP0_ROOT resource, else None."""
    if uid is None:
        return None
    return load_forge_name_registry().get(uid & 0xffffffff)


def describe_record(decompressed, o):
    """Short, human-readable label for one enumerate_savegameobjects() entry -- shows real
    property names where known (see read_property_table) instead of just index/offset/size.

    Prefixes the label with a guessed class name (see guess_record_class) when the property
    table's own names confidently match one census class, e.g. "PopGamePlayManager:
    TargetSectionID, MousePosition, ... (+21 more)". Also resolves the record's own `uid` against
    the POP0_ROOT instance-name registry when possible, e.g. "MissionItem
    'OB1_ObjPlatform_FirstTime_Healed': MIState, WasEverCompleted, WasEverPlayed"."""
    ptab = read_property_table(decompressed, o['offset'], record_size=o['size'])
    if ptab:
        names_here = [p['name'] for p in ptab['properties']]
        shown = names_here[:4]
        more = ptab['count'] - len(shown)
        label = ', '.join(shown) + (', ... (+%d more)' % more if more > 0 else '')
        cls, score = guess_record_class(names_here)
        inst_name = resolve_instance_name(o.get('uid'))
        prefix = cls or ''
        if inst_name:
            prefix = ("%s '%s'" % (prefix, inst_name)) if prefix else ("'%s'" % inst_name)
        if prefix:
            label = '%s: %s' % (prefix, label)
        return label
    if o['size'] == 364:
        slots = read_slots(decompressed, o['offset'])
        if slots:
            return 'CompositeSaveGameObject (4 children, states: %s)' % (
                ','.join(str(s['state']) for s in slots))
    return '(unrecognized shape)'


def read_slots(decompressed, record_offset):
    """For a normal 364-byte SaveGameObject array entry (see enumerate_savegameobjects), decode
    its 4 nested 91-byte sub-blocks: [typehash(4)][uid(4)][...][state byte @ local+85]. Returns a
    list of 4 dicts (uid, state) or None if this record isn't the expected 364-byte shape. The
    state byte's meaning isn't decoded yet -- see the composite-slot-state notes elsewhere."""
    if record_offset + 364 > len(decompressed):
        return None
    slots = []
    for slot in range(4):
        base = record_offset + slot * 91
        if base + 91 > len(decompressed):
            return None
        th = struct.unpack_from('<I', decompressed, base)[0]
        if th != ROOT_TYPEHASH:
            return None
        uid = struct.unpack_from('<I', decompressed, base + 4)[0]
        state = decompressed[base + 85]
        slots.append(dict(uid=uid, state=state))
    return slots


def try_parse_root(decompressed):
    """Best-effort field decode of blob1's root SaveGameObject. The generic schema object graph's
    managed-object convention (name string right after [typehash][size]) doesn't match what's
    actually here -- those bytes decode as a UID8, not a string. This reads what's solidly known
    (typehash, declared size); full field-level decode isn't cracked yet. Callers should treat the
    field contents as raw/unknown until this is filled in."""
    if len(decompressed) < 16:
        return None
    th = struct.unpack_from('<I', decompressed, 8)[0]
    size = struct.unpack_from('<I', decompressed, 12)[0]
    return dict(typehash=th, typename=names_lookup(th), declared_size=size,
                header_end=16, body_end=16 + size)


class SaveFile:
    def __init__(self, path):
        self.path = path
        self.data = open(path, 'rb').read()
        self.header = parse_header(self.data)
        b1_off = HEADER_SIZE + self.header['blob2_size']
        self.blob2_off = HEADER_SIZE
        self.blob1_off = b1_off
        self.trailer_off = b1_off + self.header['blob1_size']
        self.blob2 = parse_blob2(self.data, self.blob2_off, self.header['blob2_size'])
        chash, region = resolve_checkpoint_code(self.blob2['checkpoint_code'])
        self.blob2['checkpoint_hash'] = chash
        self.blob2['checkpoint_region'] = region
        self.trailer_png = self.data[self.trailer_off:self.trailer_off + self.header['trailer_size']]
        self._decompressed = None
        self._decompress_error = None

    @property
    def decompressed_blob1(self):
        """A mutable bytearray, not plain bytes, so save_explorer.py's edit-value feature can
        mutate it in place. Edits persist for the rest of this SaveFile's lifetime (survive
        re-selecting the same file's tree, don't survive reloading from disk -- there's no
        write-back-to-disk path yet)."""
        if self._decompressed is None and self._decompress_error is None:
            try:
                self._decompressed = bytearray(decompress_blob1(
                    self.data, self.blob1_off, self.header['blob1_size']))
            except Exception as ex:
                self._decompress_error = str(ex)
        return self._decompressed

    def summary(self):
        h = self.header
        ts = h['timestamp_utc']
        return dict(
            file=os.path.basename(self.path),
            title=h['title'], level=h['level_name'],
            timestamp_utc=ts.isoformat() if ts else None,
            checkpoint_code=self.blob2['checkpoint_code'],
            size=len(self.data),
        )


if __name__ == '__main__':
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    path = sys.argv[1] if len(sys.argv) > 1 else None
    if not path:
        print(__doc__)
        raise SystemExit(1)
    sf = SaveFile(path)
    print(sf.summary())
    dec = sf.decompressed_blob1
    if dec is None:
        print('blob1 decompression FAILED:', sf._decompress_error)
    else:
        print('blob1 decompressed OK: %d bytes' % len(dec))
        root = try_parse_root(dec)
        print('root:', root)
