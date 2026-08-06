"""build_name_registry.py -- offline batch builder for the save-explorer's instance-name cache.

Resolving a save record's UID to a real name (see pop_save.load_forge_name_registry) means
scraping every world-area forge's resource tables, and that's way too slow to do live - each
"_LU" world-section bundle is tens to hundreds of MB decompressed, there are 60+ of them, and a
single forge file alone can take two minutes.

So this does the slow scan once and writes a flat JSON cache ({"<hex_uid>": "name", ...}) that
pop_save.load_forge_name_registry() loads near-instantly. Only needs re-running if the game
install changes, which for a released retail game basically never happens. Scans every
DataPC*.forge file in the directory, no exclusions.

Usage:  python build_name_registry.py [--out PATH] [--forge-dir DIR]
"""
import argparse
import glob
import json
import os
import struct
import sys
import time
import zlib

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(_HERE, 'forge'))
from forge_file import ForgeFile
from bundle_reader import parse_bundle, BundleError
from resource_names import list_resources

# Override with $POP2008_FORGE_DIR or --forge-dir -- the folder containing the game's
# DataPC*.forge files (its install directory).
FORGE_DIR = os.environ.get('POP2008_FORGE_DIR', '.')

DEFAULT_OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "forge_name_registry.json")

# ---- SectionGameData decoding ----
# SectionGameData instances (the region-visit trackers - NbTimeVisited/NbSparklesCollected/
# FertileGroundStatus/NbFightsDone) don't have a human-authored name in the resource table
# (`r['name'] == ''`), so it'd otherwise just show up as a raw UID. But every one of
# SectionGameData's fields, including `SectionID` (points at the real PopWorldSection this tracker
# belongs to, e.g. "DE3_TerraceCorridor"), has SERIALIZE_BIT set - it's a normal, fully-parseable
# .forge object, unlike MissionItem's save-only fields. DataPC_POP0WORLD.forge's "POP0WORLD" bundle
# holds all 162 SectionGameData templates for the whole game in one place.
#
# One instance's layout (checked against real bytes):
#   [typehash(4)][size(4)=29][namelen(4)=0][null(1)][uid8: word0=own uid(4), word1=typehash again(4)]
#   [SectionID(4)][NbTimeVisited(4)][NbSparklesCollected(4)][FertileGroundStatus(4)][NbFightsDone(4)]
#   [IsBossDefeated(1)]   = 42 bytes, and that lines up exactly with the resource table's own size.
SECTION_GAME_DATA_TH = zlib.crc32(b'SectionGameData') & 0xffffffff


def decode_section_game_data(body, res_entry, by_hash):
    """For one SectionGameData resource entry, decode its SectionID field and resolve it against
    the same bundle's own resource table (SectionID references live in the same POP0WORLD bundle
    as the trackers themselves). Returns (uid, resolved_section_name), or None if the shape doesn't
    match - a mismatch here should never crash the whole scan, just skip it."""
    off = res_entry['body_off']
    try:
        typehash, size = struct.unpack_from('<II', body, off)
        if typehash != SECTION_GAME_DATA_TH or size != 29:
            return None
        namelen = struct.unpack_from('<I', body, off + 8)[0]
        if namelen != 0:
            return None
        body_start = off + 12 + 1
        uid = struct.unpack_from('<I', body, body_start)[0]
        section_id = struct.unpack_from('<I', body, body_start + 8)[0]
    except struct.error:
        return None
    sec = by_hash.get(section_id)
    if not sec or not sec.get('name'):
        return None
    return uid, sec['name']


def should_skip_bundle(name, size):
    if not name or size == 0:
        return True
    if name == "GlobalMetaFile":
        return True
    if name.endswith("_FAKE_LU"):
        # lower-res/reduced streaming variants -- same instance names as the real _LU bundle,
        # scraping them too would only cost time for zero new names
        return True
    return False


def _save(registry, out_path):
    out = {"%08x" % h: name for h, name in registry.items()}
    tmp = out_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=0, sort_keys=True)
    os.replace(tmp, out_path)   # atomic on both POSIX and Windows -- never leaves a half-written cache


def discover_forge_files(forge_dir):
    """Every DataPC*.forge in the directory, no exclusions. Sorted so smaller/faster files (base
    game, region forges) checkpoint early and the biggest ones (StreamedSounds*, ~5000 entries
    each) run last."""
    paths = glob.glob(os.path.join(forge_dir, "DataPC*.forge"))
    return sorted(os.path.basename(p) for p in paths)


def build(forge_files=None, forge_dir=FORGE_DIR, verbose=True, out_path=None):
    """out_path, if given, gets a checkpoint write after every forge file, not just at the end -
    a full run over every DataPC*.forge file takes a while, and one bad bundle shouldn't wipe out
    everything that's already been scraped (this happened once: a bundle threw a raw IndexError
    deep in the LZSS decoder and killed an earlier un-checkpointed run with nothing saved). Any
    exception during one bundle's decode is caught, logged, and skipped rather than aborting.

    Also decodes SectionGameData instances (see decode_section_game_data) and adds them to the
    same registry as `(SectionGameData) <SectionName>` - they have no name of their own in the
    resource table, so without this they'd just get silently dropped by the plain name-scraping
    loop below."""
    if forge_files is None:
        forge_files = discover_forge_files(forge_dir)
        if verbose:
            print("discovered %d forge files: %s" % (len(forge_files), ', '.join(forge_files)))
    registry = {}
    t0 = time.time()
    for fname in forge_files:
        path = os.path.join(forge_dir, fname)
        if not os.path.isfile(path):
            if verbose:
                print("  (skip, not found) %s" % path)
            continue
        fo = ForgeFile(path)
        for e in fo.named():
            if should_skip_bundle(e.name, e.size):
                continue
            bt0 = time.time()
            raw = fo.data[e.offset:e.offset + e.size]
            try:
                b = parse_bundle(raw, False)
                res = list_resources(b, False)
            except Exception as ex:
                if verbose:
                    print("  %-30s %-28s SKIPPED (%s: %s)" % (fname, e.name, type(ex).__name__, ex))
                continue
            added = 0
            by_hash = None   # built lazily, only if this bundle actually has SectionGameData in it
            for r in res:
                h = r['hash'] & 0xffffffff
                if r['name'] and h not in registry:
                    registry[h] = r['name']
                    added += 1
                elif r['typehash'] == SECTION_GAME_DATA_TH:
                    if by_hash is None:
                        by_hash = {rr['hash'] & 0xffffffff: rr for rr in res}
                    decoded = decode_section_game_data(b['body'], r, by_hash)
                    if decoded:
                        uid, section_name = decoded
                        if uid not in registry:
                            registry[uid] = '(SectionGameData) %s' % section_name
                            added += 1
            if verbose:
                print("  %-30s %-28s +%-5d names (%d total)  %.1fs" %
                      (fname, e.name, added, len(registry), time.time() - bt0))
        if out_path:
            _save(registry, out_path)
            if verbose:
                print("  [checkpoint written after %s: %d names]" % (fname, len(registry)))
    if verbose:
        print("done: %d unique names in %.1fs" % (len(registry), time.time() - t0))
    return registry


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--forge-dir", default=FORGE_DIR)
    args = ap.parse_args()

    registry = build(forge_dir=args.forge_dir, out_path=args.out)
    _save(registry, args.out)
    print("wrote %s (%d entries)" % (args.out, len(registry)))


if __name__ == "__main__":
    main()
