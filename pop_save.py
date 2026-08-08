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


def decompress_blob1(data, off, size):
    """Decompress blob1 into the raw serialized SaveGameObject bytes.

    Wrapper (all little-endian):
      blob1[0:4)   u32 outer size = size - 4
      blob1[4:6)   2 bytes, purpose unknown, doesn't affect decoding
      blob1[6:10)  u32, not a reliable "decompressed size" -- varies independent of output length
      blob1[10:18) SECTION_MAGIC, same as forge sections
      blob1[18:38) ver/comp/const/cnt + first block's (us,cs) table entry -- not decoded field by
                   field, we just hand offset 38 straight to bundle_reader.lzss_block and it works
      Then repeated `lzss_block` calls, each followed by a 4-byte checksum that has to be skipped
      (not fed to the next lzss_block call).
    """
    blob1 = data[off:off + size]
    if len(blob1) < 40:
        raise SaveFormatError("blob1 too short: %d bytes" % len(blob1))
    p = 38
    out = bytearray()
    blocks = 0
    while p < len(blob1) - 4:
        chunk, consumed = lzss_block(blob1, p)
        out += chunk
        p += consumed + 4          # +4: skip the per-block checksum before the next block
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
    """Scan the whole decompressed blob1 for the PropertyPath entry signature
    (`[u32 marker=2 i.e. 'Object'][u32 class typehash][u16 flag=0xffff][u32 field name hash]`,
    14 bytes total) and return every (class_name, field_name) pair found, with occurrence counts.

    Much faster than hunting for names one record at a time -- one pass over a save turns up real
    names for `Powers`, `Traps`, `Variables`, `RulesLibraryBook.RuntimeEnabled`, and
    `AchievementsTrackingData`.

    The marker must be filtered to exactly 2, not any small integer -- broadening it pulls in
    false positives (e.g. CompositeSaveGameObject children's own [typehash][uid] headers look like
    a hit when uid happens to be small). The class-typehash -> field-name-hash gap is 6 bytes (a
    u16 0xffff flag, nothing else), not 4.
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
# These describe a field's TYPE, they do not hold its value.
#
# Worth being blunt about the trap here, because two separate "confirmed offsets" in this file were
# retracted after falling into it: the single interesting-looking byte in one of these entries is
# the schema's own `kind` code, not data. That's why entries for TrapType/MagicPlateType all read
# 25 (0x19 = kind Enum) and why the old StaminaBonus* offsets all read 7 (0x07 = kind u32) -- a
# constant that looks like a plausible value is much more likely to be a type tag than a real one.
# The give-away is the hash: it resolves to an enum's TYPE name (e.g. "MissionItemState") or a
# "Class::Field" debug name, and the byte never varies across the whole corpus.
#
# Kept because the manifest is genuinely useful for LOCATING a record's value blob (walking these
# entries tells you where the type descriptions stop and real data starts, which is how
# MissionItem's 6-byte blob was pinned down), just never for reading a value out of.
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
    """List every SaveGameObject-typed record in the decompressed blob1 buffer.

    blob1 isn't one root object, it's an array of ~225 individually-tracked SaveGameObject
    instances - one per stateful world object (checkpoints, doors, switches, collectible trackers,
    etc). Found by scanning for every occurrence of the typehash (0x89DDA5B). `end` is just "where
    the next entry starts", not a real decoded size field - haven't figured out this class's actual
    size field yet.

    Known gap, not worth fixing right now: this only checks u32-aligned positions, so it misses any
    record whose typehash lands at a non-4-aligned offset (a real PopGamePlayManager record does
    this). Tried a general byte-level rescan twice and reverted both times - a normal
    CompositeSaveGameObject's 4 nested 91-byte sub-blocks (see read_slots) share this same
    typehash, and since 91 isn't a multiple of 4, a blind rescan also picks those up and roughly
    doubles or triples the record count with junk fragments instead of real new records (not every
    composite record is a clean 4x91 block, some have different slot counts). Use
    find_unaligned_records() below for the specific classes that actually need this instead -
    fixing the general scanner properly needs a composite walker that's aware of slot counts, which
    doesn't exist yet.

    Per-entry `uid` is the 4 bytes right after the typehash. It's genuinely per-instance (differs
    between objects, matches across saves for the same object) - unlike the ~340-byte tail of a
    normal 364-byte entry, which is just a shared template, byte-identical everywhere.
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


def find_unaligned_records(decompressed):
    """Narrowly-targeted lookup for census-class records that enumerate_savegameobjects() misses
    because their typehash sits at a non-4-byte-aligned offset. For each class in
    save_persisted_census() with at least MIN_FIELDS fields, anchor on its first ANCHOR_LEN
    declared fields' name hashes at the 11-byte name-record stride read_property_table uses, and
    require all of them to line up before accepting a hit.

    Only returns records whose offset is NOT 4-byte-aligned -- anything aligned is already found
    by enumerate_savegameobjects(). Also excludes anything falling inside an already-known 364-byte
    `CompositeSaveGameObject` span, since that record's shared static template happens to contain a
    few bytes that read as real name hashes too (MIState, WasEverCompleted, WasEverPlayed).

    Returns a list of dicts (offset, klass, uid). No 'end'/'size' boundary -- callers should treat
    these as point discoveries to inspect directly, not a complete/orderable record list."""
    composite_spans = [(o['offset'], o['end']) for o in enumerate_savegameobjects(decompressed)
                        if o['kind'] == 'normal']

    def _inside_composite(off):
        return any(lo <= off < hi for lo, hi in composite_spans)

    # A 2-hash anchor isn't strong enough on its own: small/common classes like MissionItem (only
    # 3 fields) still produce hundreds of false positives even excluding composite spans, since the
    # same field-name hashes recur elsewhere in the file too. Only classes with enough fields to
    # check a 4-hash anchor are trustworthy here.
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
    """Same shape as save_persisted_census() but with every declared field for every class, not
    just SAVE_PERSIST-flagged ones. Used as a fallback in guess_record_class() for records whose
    only resolvable property is a SERIALIZE_BIT-only field (e.g. `Graph.RulesLibraryBook` --
    SERIALIZE_BIT but no SAVE_PERSIST_BIT). These are real instances of a real census class (Graph
    itself has SAVE_PERSIST fields too, e.g. Variables) that just didn't happen to keep a
    SAVE_PERSIST field name after read_property_table's desync-guard truncation -- they deserve a
    real class label instead of '(no class match)'."""
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
        # CompositeSaveGameObject.SavedObjects shape (4 nested 91-byte children, see read_slots())
        # -- its shared static template happens to contain a few byte sequences that coincidentally
        # equal real name hashes (MIState, WasEverCompleted, ...), producing a convincing-looking
        # but wrong property table without this check.
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
    # record[0]'s 5 simple properties, packed back to back as 4-byte slots starting at 473.
    #   CurrentPopGameStage @473 - jumps 0->3 right when you first reach The Cauldron, then holds.
    #     Coarse chapter/stage enum.
    #   NumberCompletedFight @477 - small counter, barely moves. Fight count.
    #   SparkleCount @481 - climbs steadily. Collectible count.
    #   LastPopEnvironmentAreaPortalID @485 - not a counter, but the same value shows up again
    #     every time you revisit the same portal. Portal identity hash.
    #   LastPopEnvironmentAreaPortalBlendingRatio @489 - float32, watched it go 0.0856 -> 1.0000
    #     between two saves right as a blend finished.
    # These offsets are specific to record[0]'s own layout, not a general rule for every table.
    zlib.crc32(b'CurrentPopGameStage') & 0xffffffff: (473, '<I'),
    zlib.crc32(b'NumberCompletedFight') & 0xffffffff: (477, '<I'),
    zlib.crc32(b'SparkleCount') & 0xffffffff: (481, '<I'),
    zlib.crc32(b'LastPopEnvironmentAreaPortalID') & 0xffffffff: (485, '<I'),
    zlib.crc32(b'LastPopEnvironmentAreaPortalBlendingRatio') & 0xffffffff: (489, '<f'),

    # The ability/stamina tracker (starts with StateOffensiveLocked, 27 properties: 19 bools then
    # 8 StaminaBonus* numbers). Found by diffing a save right before vs. right after first reaching
    # The Cauldron - one byte flipped, and it landed on DeflectLocked, which lines up (that's one
    # of the first moves you unlock there).
    #
    # Both halves sit in one value blob at the end of the record, same length-prefixed shape as
    # MissionItem's: a u32 at +537, then 19 bools at 541..559 and the 8 StaminaBonus* ints at
    # 560..591 (4 bytes each, declared order). Byte 540 is a leading pad -- it reads 0 in all 106
    # saves, whereas 559 flips between 0 and 1, which is what fixes the bool run at 541 rather than
    # 540 and keeps DeflectLocked on 552 where the original diff put it.
    #
    # An earlier attempt put StaminaBonus* at 479..535 and had to be retracted: every save read a
    # literal 7 there, which is kind u32 (0x07), i.e. a type tag. The real values are obvious once
    # you land on them -- Hunter/Concubine/MourningKing move in multiples of 15, they only climb
    # over a playthrough (0 -> 15 -> 60 -> 120), and they reset to 0 when a new playthrough starts.
    # Warrior/MonsterX/Guard are 0 everywhere in this corpus, so those three are placement-by-
    # declaration-order rather than independently witnessed changing.
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

    # MissionItem's 3 save-persisted fields. A plain MissionItem record is exactly 91 bytes and its
    # values sit in a length-prefixed blob at the very end: a u32 at +81 holding 6 (== the schema's
    # own declared widths, MIState 4 + two 1-byte bools), then the 6-byte blob at +85..+90 in
    # declared order. The u32-6 prefix is what pins this down -- it lines up on 62535 records
    # across the whole save folder with no exceptions, and the blob ends exactly on the record
    # boundary.
    #
    # Careful with the fixed offsets: they're right for the 91-byte shape (the overwhelming
    # majority), but plenty of "MissionItem" matches are actually bigger MissionItemList/
    # MissionItemSceneSequencer containers wrapping a child, where the blob sits elsewhere.
    #
    # MIState reads 0/2/3 only, matching the real enum. Both bools, on the other hand, are 0 in
    # every single record in the corpus -- including all 12614 where MIState is 3 (Completed),
    # which is exactly where WasEverCompleted "should" be 1. The position is structurally certain
    # (the length prefix leaves nowhere else for them to be); the game just never persists them as
    # true, so it very likely rederives both from MIState on load.
    zlib.crc32(b'MIState') & 0xffffffff: (85, 'B'),
    zlib.crc32(b'WasEverCompleted') & 0xffffffff: (89, 'B'),
    zlib.crc32(b'WasEverPlayed') & 0xffffffff: (90, 'B'),

    # PopGamePlayManager -- the per-checkpoint world state (where you are, where the camera is,
    # how far through the act). Its value blob starts at +465 and runs in declared order, so every
    # offset below is just the running total of the schema's own widths from there.
    #
    # Anchor: PrinceMatrix and LoverMatrix are 4x4 affine transforms sitting back to back, which is
    # a shape you can spot without knowing anything else (rows 0-2 end in 0.0, row 3 ends in 1.0).
    # That pair lands on +481 in all 66 records in the corpus, and 481 minus the 16 bytes the three
    # fields before it declare puts the blob at 465.
    #
    # What makes this trustworthy rather than plausible: reading the chain back gives values that
    # could not survive a wrong offset. CameraOrientation is a unit quaternion (|q| == 1.000 in
    # every record), CameraFOV is 0.768 rad (44 degrees), and CameraPos lands 4-15 units from the
    # Prince's own position -- i.e. behind a third-person camera.
    #
    # The chain stops at BondState: ActiveODDTags is a variable-length array, so everything
    # declared after it (SavePrinceDeathHeight ... SaveElikaCapturedPos) has no fixed offset and is
    # deliberately left unconfirmed. CurrentTrapSynchroZone isn't in the record at all.
    zlib.crc32(b'TargetSectionID') & 0xffffffff: (465, '<I'),
    zlib.crc32(b'SpecialGamePlayContext') & 0xffffffff: (477, '<I'),
    zlib.crc32(b'SavedDivisionID') & 0xffffffff: (609, '<I'),
    zlib.crc32(b'SavedCorruptionZoneID') & 0xffffffff: (613, '<I'),
    zlib.crc32(b'CameraFOV') & 0xffffffff: (649, '<f'),
    zlib.crc32(b'CurrentFightCount') & 0xffffffff: (653, '<I'),
    zlib.crc32(b'CurrentAct') & 0xffffffff: (657, '<I'),
    zlib.crc32(b'BondState') & 0xffffffff: (661, '<I'),

    # PopSoundReverbManager -- a 51-byte record with a single declared field, and the tidiest
    # example of the length-prefix shape in the whole file: u32 4 at +43 (matching the field's
    # declared width) then the value at +47, running to the record boundary. Both the size and the
    # prefix hold on all 106 records. Reads 0 in most saves and a portal-ID-looking hash otherwise.
    zlib.crc32(b'CurrentPortalSoundReverbSetObjectID') & 0xffffffff: (47, '<I'),
}


# Fields whose position is confirmed but that hold several numbers rather than one, so they can't
# go in CONFIRMED_VALUE_OFFSETS' single-scalar model. Each entry lists the components worth
# showing, as (label, offset relative to the field, struct format).
#
# For the two 4x4 transforms only the translation row is listed: the other 13 floats are the
# rotation basis, and the X/Y/Z here is the part anyone actually wants (it's where the Prince and
# Elika are standing).
MULTI_COMPONENT_OFFSETS = {
    zlib.crc32(b'MousePosition') & 0xffffffff: (469, [('X', 0, '<f'), ('Y', 4, '<f')]),
    zlib.crc32(b'PrinceMatrix') & 0xffffffff: (481, [('X', 48, '<f'), ('Y', 52, '<f'), ('Z', 56, '<f')]),
    zlib.crc32(b'LoverMatrix') & 0xffffffff: (545, [('X', 48, '<f'), ('Y', 52, '<f'), ('Z', 56, '<f')]),
    zlib.crc32(b'CameraPos') & 0xffffffff: (617, [('X', 0, '<f'), ('Y', 4, '<f'), ('Z', 8, '<f')]),
    zlib.crc32(b'CameraOrientation') & 0xffffffff: (633, [('X', 0, '<f'), ('Y', 4, '<f'),
                                                          ('Z', 8, '<f'), ('W', 12, '<f')]),
}


def resolve_multi_component(decompressed, record_offset, prop_hash):
    """Component rows for a multi-number field (see MULTI_COMPONENT_OFFSETS), as
    [(label, absolute_offset, fmt, value), ...], or None if this field isn't one of them."""
    entry = MULTI_COMPONENT_OFFSETS.get(prop_hash)
    if entry is None:
        return None
    base, comps = entry
    out = []
    for label, rel, fmt in comps:
        off = record_offset + base + rel
        if off + struct.calcsize(fmt) > len(decompressed):
            return None
        out.append((label, off, fmt, struct.unpack_from(fmt, decompressed, off)[0]))
    return out


# record[0]'s 6th property, "AchievementsTrackingData" itself, is a nested struct, not a plain
# value - read_property_table()'s desync guard stops scanning right at this property, so these 14
# sub-fields never show up in ptab['properties'] and can't go through CONFIRMED_VALUE_OFFSETS the
# normal way.
#
# Turns out you don't need to crack the nested format: the census's declared widths for all 14
# fields add up to exactly 51 bytes, and record[0] is always exactly 493 (where the 5 fields above
# end) + 51 = 544 bytes. So they're just packed back to back in declaration order right after the
# first 5 fields, same as those are. Checked it decodes sanely - playtime in seconds looks like
# real session lengths, the counters only go up, the bools stay 0/1. Offsets below are absolute
# from record[0]'s start, not from "AchievementsTrackingData"'s own position.
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


# SectionGameData values. This one's annoying: unlike record[0], there's a variable-length gap
# between the name table and the actual values (an extra 8 bytes sometimes shows up, bumping the
# record from 120 to 128 bytes), so you can't just use a fixed offset from the start. What does
# stay put: the 4 values are always the last 16 bytes of the record, packed in declaration order.
#
# Checked this against 53 same-uid pairs across different saves: NbTimeVisited only ever goes up,
# FertileGroundStatus stays within {0,1,2} (its real enum range) and never changes once set,
# NbSparklesCollected/NbFightsDone behave like normal per-visit counters. No bad readings.
#
# One gotcha: guess_record_class also matches much bigger, unrelated records as "SectionGameData"
# just because they happen to share these 4 property names among a lot of others that got
# truncated away. SECTION_GAME_DATA_MAX_SIZE keeps this decode from firing on those.
SECTION_GAME_DATA_MAX_SIZE = 150

SECTION_GAME_DATA_TAIL_OFFSETS = {
    zlib.crc32(b'NbTimeVisited') & 0xffffffff: (-16, '<I'),
    zlib.crc32(b'NbSparklesCollected') & 0xffffffff: (-12, '<I'),
    zlib.crc32(b'FertileGroundStatus') & 0xffffffff: (-8, '<I'),
    zlib.crc32(b'NbFightsDone') & 0xffffffff: (-4, '<I'),
}

# CorruptionZone.CorruptionLevel -- same "last N bytes" trick as SectionGameData. Same-uid records
# show the last byte toggling cleanly between 0 and 1 over time, which matches the schema (kind
# s8, 1 byte). Same oversized-record false-positive problem as above, so it's gated the same way.
CORRUPTION_ZONE_MAX_SIZE = 60
CORRUPTION_ZONE_TAIL_OFFSETS = {
    zlib.crc32(b'CorruptionLevel') & 0xffffffff: (-1, 'b'),
}

# IGraphRule.RuntimeEnabled -- same shape again, last byte of a 48-byte record. Didn't catch any
# single instance toggling over time here, but different rule instances do show a real mix of 0
# and 1 (never anything else), which is enough to trust given the position already checks out for
# CorruptionZone at the same record size.
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

# Fallback for SectionGameData records that the tail rule can't touch: some are hundreds of bytes
# long (the 4 fields are still the whole declared set, but the record carries a lot else), so
# "last 16 bytes" doesn't apply. Those still carry the same length-prefixed blob every other class
# uses, so find it by its u32 = 16 header instead of by position.
#
# Only worth doing for a blob length distinctive enough not to match noise -- 16 is, a 1-byte blob
# (CorruptionZone/IGraphRule) very much isn't, so those keep the tail rule only. Checked against
# the records where BOTH rules apply: same offset on 2187 of 2188, and the tail rule is tried
# first, so that one disagreement never actually reaches this path.
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
        # Try the caller's size first, then the record's real end. enumerate_savegameobjects()
        # measures to the next 4-ALIGNED typehash, so a record followed by an unaligned one gets
        # reported far too big and fails the size gate below -- true_record_end() doesn't care
        # about alignment and recovers those.
        for size in (record_size, true_record_end(decompressed, record_offset) - record_offset):
            if size is None or not (0 < size <= max_size):
                continue
            off = record_offset + size + tail_rel
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


# POP0.schema doesn't store enum member names anywhere -- a field's `kind` just says "this is an
# enum" (kind 0x19), not what the members are called or what their values mean. The game exe has
# its own enum tables though, found by locating a pointer to the enum's name string in Ghidra and
# reading the small linked-list struct next to it (name + int value + hash per member). More
# kind-0x19 fields could get the same treatment later (CurrentPopGameStage, BondState, etc. -- see
# save_persisted_census() for candidates). Keyed by field name ('MIState'), not the enum's own type
# name ('MissionItemState'), since that's all enum_name()'s caller has on hand.
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
}


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


# A SaveGameObject's `uid` is the same hash-of-the-instance-name scheme used for every resource's
# `hash` field in a .forge bundle's resource table (see forge/resource_names.list_resources()). For
# MissionItem-family trackers that resolves to a real named resource in POP0_ROOT (DataPC.forge) --
# e.g. uid=0x07c1406e is `OB1_ObjPlatform_FirstTime_Healed`. Other UID fields (like
# LastPopEnvironmentAreaPortalID) point into the per-region world forges instead
# (DataPC_HC.forge, DataPC_OB.forge, ...), not just POP0_ROOT.
#
# Scraping those region forges live is too slow for this tool to do on the fly (a single forge file
# can take minutes, the full set 20-25 minutes), so build_name_registry.py does it once offline and
# writes a JSON cache next to this file. load_forge_name_registry() below loads that cache if it's
# there, and falls back to a quick POP0_ROOT-only scan if it isn't.
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
