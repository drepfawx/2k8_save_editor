"""Vanilla-JS + pywebview UI prototype. Python stays the only backend -- pop_save.py is untouched,
this just exposes it to a plain HTML/CSS/JS frontend instead of Qt widgets.

Layout: a "Load Save..." button opens a native file dialog; the left panel shows a handful of
headline stats (light seeds, traps/powers enabled, ...); the right panel shows the full decoded
tree, same data as save_explorer.py's detail pane.

Run: python web_ui/server.py
"""
import json
import os
import sys
import zlib

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.join(_ROOT, 'forge'))

import pop_save as PS
import webview
from webview.dom import DOMEventHandler

DEFAULT_SAVE_DIR = os.path.join(os.path.expanduser('~'), 'Documents', 'Prince of Persia', 'Save')


def node(label, value='', mono=False, children=None):
    return dict(label=label, value=value, mono=mono, children=children or [])


def format_value(prop_name, val):
    """Same formatting rules as save_explorer.py's _format_property_value."""
    enum_nm = PS.enum_name(prop_name, val) if isinstance(val, int) else None
    if enum_nm:
        return '%s (%d)' % (enum_nm, val)
    if val is None:
        return '(unresolved name)' if prop_name.startswith('0x') else '(value position not yet confirmed)'
    if isinstance(val, float):
        return '%.4f' % val
    if isinstance(val, int) and prop_name in PS.BITMASK_FIELDS:
        if -128 <= val < 256:
            return '0x%02x (%s)' % (val & 0xff, format(val & 0xff, '08b'))
        return '%#018x (%d bits set)' % (val, bin(val).count('1'))
    if isinstance(val, int) and PS.is_bool_field(prop_name):
        return {0: 'false (0)', 1: 'true (1)'}.get(val, '%d (unexpected for a bool)' % val)
    if prop_name.endswith('ID') or prop_name == 'ObjectToSave':
        if val == 0:
            return '0 (none)'
        name = PS.resolve_instance_name(val)
        return '%s (%#010x)' % (name, val) if name else '%#010x' % val
    return str(val)


def build_property_node(dec, offset, prop, record_size, name_table_end):
    val = PS.decode_property_value(dec, offset, prop['hash'], record_size=record_size,
                                    name_table_end=name_table_end)
    comps = PS.resolve_multi_component(dec, offset, prop['hash'])
    nested = (PS.decode_achievements_tracking_data(dec, offset)
              if prop['name'] == 'AchievementsTrackingData' else None)
    arr = PS.active_odd_tags(dec, offset, prop['hash'])
    if val is not None:
        shown = format_value(prop['name'], val)
    elif comps:
        shown = ', '.join('%s=%.3f' % (lbl, v) for lbl, _o, _f, v in comps)
    elif arr is not None:
        shown = '(array, %d entries)' % arr[0]
    elif nested:
        shown = ''
    else:
        shown = format_value(prop['name'], None)
    n = node(prop['name'], shown)
    if comps:
        for lbl, _o, _f, v in comps:
            n['children'].append(node(lbl, '%.4f' % v, mono=True))
    if nested:
        for name, _o, _f, v in nested:
            n['children'].append(node(name, format_value(name, v), mono=True))
    return n


def build_array_container_tree(dec, traps, powers, portals):
    root = node("Traps & Powers",
                "%d traps · %d powers · %d portal loaders" %
                (sum(len(r['elements']) for r in traps),
                 sum(len(r['elements']) for r in powers), len(portals)))
    for klass, field, recs in (('TrapsManager', 'Traps', traps), ('PowersManager', 'Powers', powers)):
        for r in recs:
            rnode = node(klass, '%s[%d]' % (field, len(r['elements'])))
            for k, elem in enumerate(r['elements']):
                enode = node('[%d]' % k)
                for fname, val in elem.items():
                    if fname in ('Enabled', 'ManualActivation'):
                        shown = 'true' if val else 'false'
                    else:
                        nm = PS.enum_name(fname, val)
                        shown = '%s (%d)' % (nm, val) if nm else str(val)
                    enode['children'].append(node(fname, shown, mono=True))
                rnode['children'].append(enode)
            root['children'].append(rnode)
    for r in portals:
        used = sum(1 for x in r['object_to_save'] if x)
        pnode = node('PortalDynamicLoaderSaveState',
                      '%d / %d slots used' % (used, PS.FIXED_ARRAY_CAPACITY))
        for k in range(PS.FIXED_ARRAY_CAPACITY):
            obj_id, flag = r['object_to_save'][k], r['active_flag'][k]
            if not obj_id and not flag:
                continue
            onode = node('ObjectToSave[%d]' % k, format_value('ObjectToSave', obj_id), mono=True)
            onode['children'].append(node('ActiveFlag', 'true' if flag else 'false', mono=True))
            pnode['children'].append(onode)
        root['children'].append(pnode)
    return root


def build_game_state_tree(dec):
    objs = PS.enumerate_savegameobjects(dec)
    items = PS.find_mission_items(dec)
    regions = PS.find_section_game_data(dec)
    comps = PS.find_composites(dec)
    graphs = PS.find_graphs(dec)
    singles = {f: PS.find_single_field_records(dec, f) for f in ('CorruptionLevel', 'RuntimeEnabled')}
    traps = PS.find_array_containers(dec, 'Traps')
    powers = PS.find_array_containers(dec, 'Powers')
    portals = PS.find_fixed_capacity_arrays(dec)
    # find_unaligned_records() only ever returns PopGamePlayManager in practice (checked against
    # the whole corpus) -- fold straight into World objects below, no separate "missed" bucket.
    pgpm_unaligned = [e for e in PS.find_unaligned_records(dec) if e['klass'] == 'PopGamePlayManager']

    claimed = set()
    for rs in (items, regions, comps, graphs, traps, powers, portals):
        claimed.update(r['offset'] for r in rs)
    for rs in singles.values():
        claimed.update(r['offset'] for r in rs)

    others = [o for o in objs if o['offset'] not in claimed]
    others += [dict(offset=e['offset'], end=None, size=None, uid=e['uid'], kind='unaligned')
               for e in pgpm_unaligned]
    others.sort(key=lambda o: o['offset'])

    sections = []

    # -- SaveGameObject array --
    arr_children = []
    current_act = None   # raw int -- the summary panel formats this differently than the tree does
    for o in others:
        ptab = PS.read_property_table(dec, o['offset'], record_size=o['size'])
        inst_name = PS.resolve_instance_name(o['uid'])
        cls = None
        if ptab:
            cls, _ = PS.guess_record_class([p['name'] for p in ptab['properties']])
        elif o['size'] == 364:
            cls = 'CompositeSaveGameObject'
        label = inst_name or cls or ('(unrecognized shape)' if ptab is None else '(unnamed)')
        rnode = node(label, cls or '')
        if ptab:
            for prop in ptab['properties']:
                rnode['children'].append(
                    build_property_node(dec, o['offset'], prop, o['size'], ptab['name_table_end']))
            if cls == 'PopGamePlayManager' and current_act is None:
                act_hash = zlib.crc32(b'CurrentAct') & 0xffffffff
                current_act = PS.decode_property_value(dec, o['offset'], act_hash, record_size=o['size'],
                                                        name_table_end=ptab['name_table_end'])
        arr_children.append(rnode)
    sections.append(node('World objects (%d)' % len(others), '', children=arr_children))

    # -- Mission items --
    mi_children = []
    for it in items:
        name = PS.resolve_instance_name(it['uid']) or '%#010x' % it['uid']
        mnode = node(name, '')
        for lbl, rel in (('MIState', 0), ('WasEverCompleted', 4), ('WasEverPlayed', 5)):
            val = dec[it['state_offset'] + rel]
            mnode['children'].append(node(lbl, format_value(lbl, val), mono=True))
        mi_children.append(mnode)
    sections.append(node('Mission items (%d)' % len(items), '', children=mi_children))

    # -- Region trackers --
    labelled = []
    for r in regions:
        nm = (PS.resolve_instance_name(r['uid']) or '%#010x' % r['uid']).replace('(SectionGameData) ', '')
        labelled.append((nm, '_FAKE' in nm, r))
    live = [r for nm, fake, r in labelled if r['initialized'] and not fake]
    total_seeds = sum(r['NbSparklesCollected'] for r in live)

    def _order(t):
        nm, fake, r = t
        rank = PS.seed_region_rank(nm)
        if fake or not r['initialized'] or rank is None:
            return (1, 1 if fake else 0, 0 if r['initialized'] else 1, 0, nm.lower())
        return (0, 0, 0, rank, '')

    reg_children = []
    for nm, fake, r in sorted(labelled, key=_order):
        note = '(streaming variant)' if fake else ('(never loaded)' if not r['initialized'] else '')
        rnode = node(nm, note)
        if r['initialized']:
            for lbl in ('NbTimeVisited', 'NbSparklesCollected', 'FertileGroundStatus', 'NbFightsDone'):
                rnode['children'].append(node(lbl, format_value(lbl, r[lbl]), mono=True))
        reg_children.append(rnode)
    sections.append(node('Region trackers (%d regions, %d light seeds)' % (len(live), total_seeds),
                         '', children=reg_children))

    # -- Composite objects --
    comp_children = []
    nkids = 0
    for c in comps:
        nm = PS.resolve_instance_name(c['uid']) or '%#010x' % c['uid']
        cnode = node(nm, '')
        for ch in c['children']:
            nkids += 1
            if ch.get('empty'):
                cnode['children'].append(node('(empty)', '%#010x' % ch['uid']))
                continue
            val = PS.composite_child_value(dec, ch)
            shown = format_value(ch['name'], val) if val is not None else (
                '(%d bytes, kind %#x)' % (ch['value_len'], ch['kind']))
            cnode['children'].append(node(ch['name'], shown, mono=True))
        comp_children.append(cnode)
    sections.append(node('Composite objects (%d instances, %d components)' % (len(comps), nkids), '', children=comp_children))

    # -- Graph rule variables --
    graph_children = []
    nvars = 0
    for g in sorted(graphs, key=lambda g: g['klass']):
        nvars += len(g['variables'])
        gnode = node(g['klass'], 'Variables[%d]' % len(g['variables']))
        for var in g['variables']:
            vnode = node('[%d] %s' % (var['index'], var['klass']), '')
            for f in var['fields']:
                vnode['children'].append(node(f['field_name'], '%.4f' % f['value'], mono=True))
            gnode['children'].append(vnode)
        graph_children.append(gnode)
    sections.append(node('Graph rule variables (%d graphs, %d variables)' % (len(graphs), nvars),
                         '', children=graph_children))

    # -- Corruption zones / Graph rules --
    for section, field in (('Corruption zones', 'CorruptionLevel'), ('Graph rules', 'RuntimeEnabled')):
        found = singles[field]
        if not found:
            continue
        sect_children = []
        for r in found:
            nm = PS.resolve_instance_name(r['uid']) or '%#010x' % r['uid']
            sect_children.append(node(nm, format_value(field, r['value']), mono=True))
        sections.append(node('%s (%d found, %d set)' % (section, len(found), sum(1 for r in found if r['value'])),
                             '', children=sect_children))

    # -- Traps & Powers --
    sections.append(build_array_container_tree(dec, traps, powers, portals))

    return node('Game State (blob1)', '', children=sections), dict(
        light_seeds=total_seeds, traps=traps, powers=powers, singles=singles, current_act=current_act)


def build_header_node(sf):
    h = sf.header
    ts = h['timestamp_utc']
    children = [
        node('magic', '%#010x (RGMH)' % h['magic']),
        node('title', h['title']),
        node('level_name', h['level_name']),
        node('timestamp (UTC)', ts.isoformat(sep=' ') if ts else '(invalid)'),
    ]
    return node('Header', '', children=children)


def build_checkpoint_node(sf):
    b2 = sf.blob2
    children = [
        node('checkpoint_code', b2['checkpoint_code']),
        node('resolved region', b2['checkpoint_region'] or '(unknown code)'),
        node('level_name', b2['level_name']),
    ]
    return node('Checkpoint', '', children=children)


# Display names are the real in-game ability names (Ormazd's four gifts), not the internal
# MagicPlateComponentType enum names -- Rebound=Steps, Grapple=Hand, Dash=Breath, FlyOnBeam=Wings.
# Colors as specified by the user: red/blue/green/yellow respectively.
# MagicType_Invalid/MagicType_Target aren't real acquirable plates (Invalid's a sentinel; Target
# was never called out), so they're left out of this list entirely, not just uncolored.
POWER_PLATE_INFO = [
    ('Step of Ormazd', 1, '#e5484d'),    # Rebound / red
    ('Hand of Ormazd', 3, '#3b9eff'),     # Grapple / blue
    ('Breath of Ormazd', 4, '#30a46c'),   # Dash / green
    ('Wings of Ormazd', 5, '#f5c518'),    # FlyOnBeam / yellow
]

LIGHT_SEEDS_MAX = 1001

ACT_LABELS = {0: 'Act 0', 1: 'Act 1', 2: 'Act 2', 3: 'Act 3'}

# The 24 real levels (LR1-6 / OB1-6 / RC1-6 / HC1-6). find_single_field_records('CorruptionLevel')
# also picks up ~13 unrelated records per save (streaming "_FAKE" variants, tree/fire sub-zones,
# CorruptionRegionCellData, ...) that aren't levels at all -- the summary panel should only ever
# count these 24, even though the detailed tree still shows everything found.
CORRUPTION_ZONE_NAMES = frozenset('%s%d' % (prefix, n)
                                   for prefix in ('LR', 'OB', 'RC', 'HC') for n in range(1, 7))


def compute_power_plates(powers):
    enabled_by_type = {}
    for r in powers:
        for e in r['elements']:
            enabled_by_type[e['MagicPlateComponentType']] = bool(e['Enabled'])
    return [dict(name=name, color=color, enabled=enabled_by_type.get(type_val, False))
            for name, type_val, color in POWER_PLATE_INFO]


def compute_summary(dec, extra):
    singles = extra['singles']
    corruption_found = [r for r in singles.get('CorruptionLevel', [])
                         if PS.resolve_instance_name(r['uid']) in CORRUPTION_ZONE_NAMES]
    # CorruptionLevel == 0 means clean/healed -- the summary shows progress towards healing all
    # 24, not how many are still corrupted.
    healed = sum(1 for r in corruption_found if not r['value'])
    act = extra['current_act']

    return dict(
        current_act=ACT_LABELS.get(act, 'Act %s' % act if act is not None else 'unknown'),
        light_seeds=extra['light_seeds'],
        light_seeds_max=LIGHT_SEEDS_MAX,
        power_plates=compute_power_plates(extra['powers']),
        healed_levels=healed,
        healed_levels_total=len(CORRUPTION_ZONE_NAMES),
    )


def load_save_data(path):
    """Shared by the Load Save button (Api.load_save, called from JS) and the drag-and-drop
    handler (setup_drag_drop, called from the pywebview DOM event system) -- same result shape
    either way."""
    try:
        sf = PS.SaveFile(path)
        dec = sf.decompressed_blob1
    except Exception as exc:
        return dict(error=str(exc))
    if dec is None:
        return dict(error='decompression failed: %s' % sf._decompress_error)
    game_state_node, extra = build_game_state_tree(dec)
    tree = node('root', '', children=[build_header_node(sf), build_checkpoint_node(sf), game_state_node])
    return dict(
        title=os.path.splitext(os.path.basename(path))[0],
        subtitle=sf.blob2['checkpoint_region'] or sf.header['level_name'] or '',
        summary=compute_summary(dec, extra),
        tree=tree,
    )


def setup_drag_drop(window):
    """Wires real OS file drag-and-drop onto #drop-zone. Browsers only expose a blob for a
    dropped file, not a filesystem path -- pywebview's window.dom event binding is what actually
    populates a real path (as 'pywebviewFullPath' on the file dict), but only for handlers
    registered this way, not a plain JS addEventListener. Visual drag-over feedback is still
    handled entirely in app.js (doesn't need a real path, so no need to round-trip through here)."""
    zone = window.dom.get_element('#drop-zone')
    if zone is None:
        return

    def on_drop(event):
        files = (event.get('dataTransfer') or {}).get('files') or []
        for f in files:
            path = f.get('pywebviewFullPath')
            if path:
                result = load_save_data(path)
                window.evaluate_js('window.__onSaveDropped(%s)' % json.dumps(result))
                return

    zone.events.drop += DOMEventHandler(on_drop, prevent_default=True, stop_propagation=True)


class Api:
    def __init__(self, window_ref):
        self._window_ref = window_ref

    def open_file_dialog(self):
        win = self._window_ref[0]
        result = win.create_file_dialog(
            webview.FileDialog.OPEN,
            directory=DEFAULT_SAVE_DIR if os.path.isdir(DEFAULT_SAVE_DIR) else '',
            file_types=('PoP2008 save (*.PoPSavedGame)', 'All files (*.*)'),
        )
        return result[0] if result else None

    def load_save(self, path):
        return load_save_data(path)

    def minimize(self):
        self._window_ref[0].minimize()

    def toggle_maximize(self):
        win = self._window_ref[0]
        if getattr(win, '_is_max', False):
            win.restore()
            win._is_max = False
        else:
            win.maximize()
            win._is_max = True

    def close(self):
        self._window_ref[0].destroy()


def main():
    window_ref = [None]
    api = Api(window_ref)
    window = webview.create_window(
        'PoP2008 Save Editor',
        url=os.path.join(_HERE, 'index.html'),
        js_api=api,
        width=1100, height=720, min_size=(760, 420),
        frameless=True, easy_drag=False,
        background_color='#17171b',
    )
    window_ref[0] = window
    window.events.loaded += lambda: setup_drag_drop(window)
    webview.start(gui='edgechromium', debug=True)


if __name__ == '__main__':
    main()
