# PoP2008 Save Explorer

A GUI tool for browsing and inspecting `.PoPSavedGame` save files from *Prince of Persia (2008)*.

It reads a save's header, checkpoint info, embedded screenshot, and the decompressed game-state
blob, and shows a structural breakdown of every record inside — with object UIDs resolved to real
in-game names wherever possible, and known fields (level progress, achievements, region trackers,
etc.) decoded to actual values.

This is a read-only browser/inspector, not a save editor — there's no write-back-to-disk path yet
(the per-block checksum scheme in the save's compressed blob isn't cracked).

## Requirements

- Python 3, with Tkinter (bundled with most Python installs; on Linux you may need a separate
  `python3-tk` package)
- No third-party dependencies

## Usage

```
python save_explorer.py [save_folder_or_file]
```

With no argument, it opens the game's default save folder
(`Documents/Prince of Persia/Save`). Pass a folder to browse, or a specific
`.PoPSavedGame` file to open directly.

## Files

- `save_explorer.py` — the GUI itself
- `pop_save.py` — save-file format: header/checkpoint parsing, LZSS decompression, record
  walking, and all the reverse-engineered field decoding
- `save_schema.py` — loads `POP0.schema` for schema-driven record classification
- `build_name_registry.py` — offline tool that scans your game install's `.forge` archives and
  builds `forge_name_registry.json`, the UID → instance-name cache
- `forge/` — low-level readers for the game's `.forge` archive format (used by
  `build_name_registry.py`; not needed for basic save browsing)

## Instance name resolution

Object UIDs in a save are resolved to real names (e.g. `OB1_ObjPlatform_FirstTime_Healed`) using
`forge_name_registry.json`, a pre-built cache checked into this repo. If that file is missing,
the tool falls back to a small, fast, live scan that only covers `MissionItem`-family objects
(a few hundred names instead of tens of thousands).

To rebuild the cache from your own game install:

```
python build_name_registry.py --forge-dir "<path to game install>"
```

This is a one-time, offline operation and takes 20-25 minutes — it has to decompress every
`.forge` archive in the game.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `POP2008_SAVE_DIR` | `~/Documents/Prince of Persia/Save` | Default save folder |
| `POP2008_FORGE_DIR` | `.` | Game install folder, for `build_name_registry.py` |
| `POP0_SCHEMA_PATH` | `POP0.schema` | Path to the schema file used for record classification |

`POP0.schema` is included in this repo, so `POP0_SCHEMA_PATH` normally doesn't need to be set.
