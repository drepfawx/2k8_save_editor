"""save_explorer.py -- GUI browser for PoP2008 .PoPSavedGame files.

Left pane: every save in a folder (default: the real PC save folder), sorted newest first,
showing level/timestamp/checkpoint parsed straight from the header (fast -- no decompression
needed to list). Right pane: full structural breakdown of the selected save --

  Header       every field from pop_save.parse_header() (magic/version/sizes/timestamp/embedded
               strings), ground-truthed against PrinceOfPersia_Launchera.exe's writer+loader.
  Checkpoint   blob2's checkpoint-ID + level name (the small record the save browser itself
               reads without touching the big blob).
  Game State   blob1, decompressed (see pop_save.py's docstring). Root type is SaveGameObject;
               full field-level decode isn't cracked yet, so this shows what's known
               (typehash/declared size) plus a raw hex dump of the decompressed bytes rather than
               pretending to have fields it doesn't.

Object UIDs are resolved to real instance names (e.g. "OB1_ObjPlatform_FirstTime_Healed") wherever
possible -- see pop_save.load_forge_name_registry(). This works out of the box with the shipped
forge_name_registry.json cache (tens of thousands of names); if that's missing it falls back to a
small, fast, POP0_ROOT-only live scan (~700 names, MissionItem-family trackers only). Run
`python build_name_registry.py` to rebuild the full cache from your own game install (takes
20-25 minutes, offline, one-time).

Run:  python save_explorer.py [save_folder_or_file]
"""
import os
import sys
import struct
import glob

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pop_save as PS

# Override with $POP2008_SAVE_DIR, or just pass a folder/file on the command line
# (see main() below) -- defaults to the game's standard install location.
DEFAULT_SAVE_DIR = os.environ.get(
    'POP2008_SAVE_DIR',
    os.path.join(os.path.expanduser('~'), 'Documents', 'Prince of Persia', 'Save'))


def hexdump_lines(data, max_bytes=0x2000):
    out = []
    n = min(len(data), max_bytes)
    for off in range(0, n, 16):
        chunk = data[off:off + 16]
        hexs = ' '.join('%02x' % b for b in chunk)
        asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        out.append('%06x  %-48s %s' % (off, hexs, asc))
    if len(data) > max_bytes:
        out.append('... (%d more bytes, truncated)' % (len(data) - max_bytes))
    return '\n'.join(out)


class SaveExplorer(tk.Tk):
    def __init__(self, start_path):
        super().__init__()
        self.title('PoP2008 Save Explorer')
        self.geometry('1200x760')
        self.save_dir = DEFAULT_SAVE_DIR
        self.current = None
        self._photo = None  # keep a reference so Tk doesn't GC the screenshot

        self._build_ui()
        self._update_displaycolumns()
        self._report_name_registry()

        if start_path and os.path.isdir(start_path):
            self.save_dir = start_path
        elif start_path and os.path.isfile(start_path):
            self.save_dir = os.path.dirname(start_path)
        self.refresh_list()
        if start_path and os.path.isfile(start_path):
            self._select_file(start_path)

    def _report_name_registry(self):
        """Show which name registry got loaded, in the window title so it doesn't get wiped out by
        refresh_list()'s status-bar updates. Easy to not notice you're only running the small
        built-in fallback (~700 names) instead of the full offline-built cache (tens of thousands),
        and that difference matters a lot for how many UIDs actually get a real name."""
        n = len(PS.load_forge_name_registry())
        if os.path.isfile(PS.NAME_REGISTRY_CACHE):
            suffix = '[name registry: %d, full cache]' % n
        else:
            suffix = '[name registry: %d, POP0_ROOT-only -- run build_name_registry.py for more]' % n
        self.title('PoP2008 Save Explorer  %s' % suffix)

    # Columns beyond the always-visible tree column ('#0'/Field). id -> (heading label, width).
    # Order here is also display order when a column is visible. 'value'/'typehash'/'uid' default
    # on; offset/size/kind default off (rarely needed, mostly noise) but can all be toggled
    # independently via the View menu or by right-clicking any column header -- see
    # _update_displaycolumns/_show_header_menu.
    DETAIL_COLUMNS = [
        ('value', 'Value', 380),
        ('typehash', 'Typehash', 90),
        ('uid', 'UID', 90),
        ('offset', 'Offset', 80),
        ('size', 'Size', 90),
        ('kind', 'Kind', 90),
    ]
    DEFAULT_HIDDEN_COLUMNS = {'offset', 'size', 'kind'}

    # ---------------- UI ----------------
    def _build_ui(self):
        menubar = tk.Menu(self)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label='Open save file...', command=self.open_file_dialog)
        filemenu.add_command(label='Open save folder...', command=self.open_folder_dialog)
        filemenu.add_separator()
        filemenu.add_command(label='Export decompressed blob1...', command=self.export_blob1)
        filemenu.add_separator()
        filemenu.add_command(label='Exit', command=self.destroy)
        menubar.add_cascade(label='File', menu=filemenu)

        # View menu: one checkbutton per detail-tree column, toggling it in/out of
        # self.detail_tree['displaycolumns'] -- Tk's own built-in mechanism for hiding a column
        # without discarding its data, so no changes needed anywhere columns get populated.
        viewmenu = tk.Menu(menubar, tearoff=0)
        self._col_vars = {}
        for cid, label, _w in self.DETAIL_COLUMNS:
            var = tk.BooleanVar(value=(cid not in self.DEFAULT_HIDDEN_COLUMNS))
            self._col_vars[cid] = var
            viewmenu.add_checkbutton(label=label, variable=var, command=self._update_displaycolumns)
        viewmenu.add_separator()
        viewmenu.add_command(label='Show all columns', command=self._show_all_columns)
        viewmenu.add_command(label='Hide all except Value', command=self._hide_metadata_columns)
        menubar.add_cascade(label='View', menu=viewmenu)

        self.config(menu=menubar)

        paned = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        # ---- left: file list ----
        left = ttk.Frame(paned)
        paned.add(left, weight=1)
        self.dir_label = ttk.Label(left, text=self.save_dir, anchor='w')
        self.dir_label.pack(fill=tk.X, padx=4, pady=(4, 0))

        cols = ('level', 'timestamp', 'checkpoint', 'size')
        self.tree_files = ttk.Treeview(left, columns=cols, show='headings', selectmode='browse')
        for c, w in zip(cols, (110, 140, 100, 70)):
            self.tree_files.heading(c, text=c.capitalize())
            self.tree_files.column(c, width=w, anchor='w')
        self.tree_files.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        self.tree_files.bind('<<TreeviewSelect>>', self._on_select_file)

        # ---- right: details ----
        right = ttk.Frame(paned)
        paned.add(right, weight=3)

        # Search bar: Enter/Find Next jumps to the next row (wrapping around) whose Field text or
        # any visible-or-not column value contains the query (case-insensitive substring); Find
        # Prev walks backwards. Ancestor nodes are auto-opened so `see()` can actually scroll to a
        # match hidden inside a collapsed section.
        search_bar = ttk.Frame(right)
        search_bar.pack(fill=tk.X, side=tk.TOP, padx=4, pady=(4, 0))
        ttk.Label(search_bar, text='Search:').pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_bar, textvariable=self.search_var)
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        search_entry.bind('<Return>', lambda ev: self._do_search(reverse=False))
        search_entry.bind('<Shift-Return>', lambda ev: self._do_search(reverse=True))
        ttk.Button(search_bar, text='Find Next', command=lambda: self._do_search(reverse=False)).pack(side=tk.LEFT)
        ttk.Button(search_bar, text='Find Prev', command=lambda: self._do_search(reverse=True)).pack(side=tk.LEFT, padx=(4, 0))

        # Columns beyond 'value' (typehash/uid/offset/size/kind) are populated directly on the
        # top-level record row itself, not as expandable child rows, so the identifying info is
        # visible without needing to expand the row. Leaf/child rows (real per-field values,
        # composite slot states) only ever populate the 'value' column; the rest stay blank (Tk
        # leaves unspecified trailing `values` entries blank automatically).
        detail_cols = tuple(cid for cid, _label, _w in self.DETAIL_COLUMNS)
        self.detail_tree = ttk.Treeview(right, columns=detail_cols, show='tree headings')
        self.detail_tree.heading('#0', text='Field')
        for cid, label, w in self.DETAIL_COLUMNS:
            self.detail_tree.heading(cid, text=label)
            self.detail_tree.column(cid, width=w, anchor='w')
        self.detail_tree.column('#0', width=280)
        self.detail_tree.pack(fill=tk.BOTH, expand=True, side=tk.TOP)
        self.detail_tree.bind('<<TreeviewSelect>>', self._on_select_detail)
        self._ctx_menu = tk.Menu(self, tearoff=0)
        self._header_menu = tk.Menu(self, tearoff=0)
        self.detail_tree.bind('<Button-3>', self.on_tree_right_click)
        self.detail_tree.bind('<Double-1>', self.on_tree_double_click)
        self._editable = {}   # iid -> {kind, offset, fmt, prop_name} -- see _populate_details
        self._dirty = False

        bottom = ttk.Frame(right)
        bottom.pack(fill=tk.BOTH, expand=False, side=tk.BOTTOM)

        self.hexbox = tk.Text(bottom, height=16, wrap='none', font=('Consolas', 9))
        self.hexbox.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=6, pady=6)

        self.status = ttk.Label(self, text='', anchor='w')
        self.status.pack(fill=tk.X, side=tk.BOTTOM)

    # ---------------- column visibility ----------------
    def _update_displaycolumns(self):
        """Applies the View menu's checkbutton states to the tree via Tk's own `displaycolumns`
        option -- hides a column from view without discarding any of its data, so nothing
        elsewhere (row-building, copy-to-clipboard) needs to know or care which columns are
        currently visible. `displaycolumns` must never be empty (Tk treats that as "show all"),
        so if the user unchecks everything, at least 'value' stays forced on."""
        visible = [cid for cid, _label, _w in self.DETAIL_COLUMNS if self._col_vars[cid].get()]
        if not visible:
            visible = ['value']
            self._col_vars['value'].set(True)
        self.detail_tree['displaycolumns'] = visible

    def _show_all_columns(self):
        for var in self._col_vars.values():
            var.set(True)
        self._update_displaycolumns()

    def _hide_metadata_columns(self):
        for cid, var in self._col_vars.items():
            var.set(cid == 'value')
        self._update_displaycolumns()

    def _show_header_menu(self, ev):
        """Right-click-on-any-column-header menu -- same checkbutton state (self._col_vars) as the
        View menu, just reachable at the point of interest instead of a separate menubar.
        identify_region() in on_tree_right_click already guarantees this is only ever called for
        an actual heading-area click."""
        menu = self._header_menu
        menu.delete(0, 'end')
        for cid, label, _w in self.DETAIL_COLUMNS:
            menu.add_checkbutton(label=label, variable=self._col_vars[cid], command=self._update_displaycolumns)
        menu.add_separator()
        menu.add_command(label='Show all columns', command=self._show_all_columns)
        menu.add_command(label='Hide all except Value', command=self._hide_metadata_columns)
        try:
            menu.tk_popup(ev.x_root, ev.y_root)
        finally:
            menu.grab_release()

    # ---------------- search ----------------
    def _all_tree_items(self, parent=''):
        """Every row in the detail tree, in display order, regardless of collapsed/expanded
        state -- get_children() already returns children of a closed node, 'open' only affects
        what's drawn on screen, so a plain recursive walk is enough to search everything."""
        items = []
        for iid in self.detail_tree.get_children(parent):
            items.append(iid)
            items.extend(self._all_tree_items(iid))
        return items

    def _reveal_item(self, iid):
        parent = self.detail_tree.parent(iid)
        while parent:
            self.detail_tree.item(parent, open=True)
            parent = self.detail_tree.parent(parent)
        self.detail_tree.selection_set(iid)
        self.detail_tree.focus(iid)
        self.detail_tree.see(iid)

    def _do_search(self, reverse=False):
        query = self.search_var.get().strip().lower()
        if not query:
            return
        items = self._all_tree_items()
        n = len(items)
        if not n:
            return
        sel = self.detail_tree.selection()
        start = items.index(sel[0]) if sel and sel[0] in items else -1
        step = -1 if reverse else 1
        for k in range(1, n + 1):
            idx = (start + step * k) % n
            iid = items[idx]
            field = (self.detail_tree.item(iid, 'text') or '').lower()
            values = self.detail_tree.item(iid, 'values') or ()
            haystack = field + ' ' + ' '.join(str(v).lower() for v in values)
            if query in haystack:
                self._reveal_item(iid)
                self.status.config(text='Found "%s"' % self.search_var.get())
                return
        self.status.config(text='No match for "%s"' % self.search_var.get())

    # ---------------- actions ----------------
    def open_file_dialog(self):
        path = filedialog.askopenfilename(
            initialdir=self.save_dir, filetypes=[('PoP2008 save', '*.PoPSavedGame'), ('All files', '*.*')])
        if path:
            self.save_dir = os.path.dirname(path)
            self.dir_label.config(text=self.save_dir)
            self.refresh_list()
            self._select_file(path)

    def open_folder_dialog(self):
        d = filedialog.askdirectory(initialdir=self.save_dir)
        if d:
            self.save_dir = d
            self.dir_label.config(text=self.save_dir)
            self.refresh_list()

    def refresh_list(self):
        self.tree_files.delete(*self.tree_files.get_children())
        files = sorted(glob.glob(os.path.join(self.save_dir, '*.PoPSavedGame')),
                        key=os.path.getmtime, reverse=True)
        for fn in files:
            try:
                raw = open(fn, 'rb').read(0x203F + 0x400)
                h = PS.parse_header(raw)
                b2 = PS.parse_blob2(raw, PS.HEADER_SIZE, min(h['blob2_size'], 0x400))
                _, region = PS.resolve_checkpoint_code(b2['checkpoint_code'])
            except Exception:
                self.tree_files.insert('', tk.END, iid=fn, values=('?', '?', '?', '?'),
                                        text=os.path.basename(fn))
                continue
            ts = h['timestamp_utc'].isoformat(sep=' ') if h['timestamp_utc'] else '?'
            self.tree_files.insert('', tk.END, iid=fn,
                                    values=(h['level_name'], ts, region or '', os.path.getsize(fn)),
                                    text=os.path.basename(fn))
        self.status.config(text='%d save(s) in %s' % (len(files), self.save_dir))

    # ---------------- record-tree row builders ----------------
    def _insert_record_row(self, parent, dec, iid, index, offset, uid, kind, size, tag, extra=None):
        """Insert a top-level SaveGameObject-array record row: resolved instance name if we have
        one (pop_save.resolve_instance_name), else a guessed class name (pop_save.
        guess_record_class), else a generic placeholder. typehash/uid/offset/size/kind go directly
        on this row as columns instead of child rows, so you can see what a record is without
        expanding it. Value stays empty here since this row is just a container - the caller fills
        in real per-field values right after this returns.

        The 'typehash' column shows the guessed class name rather than the literal on-disk
        typehash, since that constant is always just SaveGameObject's own value (0x089dda5b) no
        matter what the guessed class is, so printing it on every row would be pointless. Falls
        back to the raw hex if nothing could be guessed.

        Returns (node, ptab) so the caller can reuse the already-computed read_property_table()
        result instead of fetching it again."""
        ptab = PS.read_property_table(dec, offset, record_size=size) if dec is not None else None
        inst_name = PS.resolve_instance_name(uid)
        cls = None
        if ptab:
            cls, _ = PS.guess_record_class([p['name'] for p in ptab['properties']])
        elif size == 364:
            # read_property_table() always returns None for exactly-364-byte records (the
            # CompositeSaveGameObject false-positive guard) -- that's a known, deterministic
            # shape, not "no class known", so still label it even when no instance name resolves.
            cls = 'CompositeSaveGameObject'
        if inst_name:
            label = inst_name
        elif cls:
            label = cls
        elif ptab is None:
            label = '(unrecognized shape)'
        else:
            label = '(unnamed)'
        prefix = ('[%d] ' % index) if index is not None else ''
        col_vals = {
            'value': '',
            'typehash': cls if cls else ('%#010x' % PS.ROOT_TYPEHASH),
            'uid': ('%#010x' % uid) if uid is not None else '(none)',
            'offset': '%#x' % offset,
            'size': ('%d B' % size) if size is not None else '?',
            'kind': kind,
        }
        node = self.detail_tree.insert(
            parent, tk.END, iid=iid, text='%s%s' % (prefix, label),
            values=tuple(col_vals[c] for c in ('value', 'typehash', 'uid', 'offset', 'size', 'kind')),
            tags=(tag,))
        for nm, val in (extra or []):
            self.detail_tree.insert(node, tk.END, text='  ' + nm, values=(val,))
        return node, ptab

    @staticmethod
    def _format_property_value(prop_name, val):
        """Shared by the initial row-build and the post-edit refresh so an edited value redisplays
        with the same formatting rules as the original decode."""
        enum_nm = PS.enum_name(prop_name, val) if isinstance(val, int) else None
        if enum_nm:
            return '%s (%d)' % (enum_nm, val)
        if val is not None:
            if isinstance(val, float):
                return '%.4f' % val
            elif isinstance(val, int) and PS.is_bool_field(prop_name):
                # Anything other than 0/1 is worth showing loudly rather than calling it true.
                return {0: 'false (0)', 1: 'true (1)'}.get(val, '%d (unexpected for a bool)' % val)
            elif prop_name.endswith('ID'):
                # These hold the same instance-name hash the .forge resource tables use, so the
                # offline name cache turns them into the real thing ("DE3_Terrace" rather than
                # 0xd220800e). Every nonzero ID in the corpus resolves; keep the raw hex alongside
                # it since that's what's actually in the file.
                if val == 0:
                    return '0 (none)'
                name = PS.resolve_instance_name(val)
                return '%s (%#010x)' % (name, val) if name else '%#010x' % val
            else:
                return str(val)
        if prop_name.startswith('0x'):
            return '(unresolved name)'
        return '(value position not yet confirmed)'

    def _insert_property_children(self, node, dec, offset, ptab, record_size=None):
        """The actual per-instance field name -> value pairs -- the only thing that should ever
        populate the Value column. record_size is passed through to decode_property_value for
        classes (e.g. SectionGameData) whose value bytes sit at a size-relative rather than a
        fixed offset -- see its docstring.

        Rows whose byte position is confirmed (pop_save.resolve_property_value_slot returns
        something) are registered in self._editable so double-clicking the Value cell can edit
        them in place -- see on_tree_double_click/_open_edit_dialog."""
        for prop in ptab['properties']:
            nte = ptab.get('name_table_end')
            val = PS.decode_property_value(dec, offset, prop['hash'], record_size=record_size,
                                            name_table_end=nte)
            comps = PS.resolve_multi_component(dec, offset, prop['hash'])
            nested = (PS.decode_achievements_tracking_data(dec, offset)
                      if prop['name'] == 'AchievementsTrackingData' else None)
            shown = self._format_property_value(prop['name'], val)
            if val is None and comps:
                # A vector/quaternion/transform: the row itself summarises, the editable numbers
                # go on the child rows below it.
                shown = ', '.join('%s=%.3f' % (lbl, v) for lbl, _o, _f, v in comps)
            elif val is None and nested:
                # A struct has no value of its own -- the real numbers are on the child rows, so
                # leave the Value column empty rather than putting a label where a value goes.
                shown = ''
            iid = self.detail_tree.insert(node, tk.END, text='  ' + prop['name'], values=(shown,))
            slot = PS.resolve_property_value_slot(dec, offset, prop['hash'],
                                                   record_size=record_size, name_table_end=nte)
            if slot is not None:
                off, fmt = slot
                self._editable[iid] = dict(kind='property', offset=off, fmt=fmt, prop_name=prop['name'])
            elif comps:
                for lbl, coff, cfmt, cval in comps:
                    ciid = self.detail_tree.insert(iid, tk.END, text='    ' + lbl,
                                                    values=('%.4f' % cval,))
                    self._editable[ciid] = dict(kind='property', offset=coff, fmt=cfmt,
                                                 prop_name='%s.%s' % (prop['name'], lbl))
            if prop['name'] == 'AchievementsTrackingData':
                self._insert_achievements_tracking_data(iid, dec, offset)

    def _insert_achievements_tracking_data(self, node, dec, record_offset):
        """AchievementsTrackingData is a nested struct, not a plain property, so its 14 real fields
        never show up in ptab['properties'] (see pop_save.decode_achievements_tracking_data).
        Expand them here as extra child rows under the AchievementsTrackingData row, same editable
        treatment as everything else."""
        fields = PS.decode_achievements_tracking_data(dec, record_offset)
        if not fields:
            return
        for name, off, fmt, val in fields:
            shown = self._format_property_value(name, val)
            iid = self.detail_tree.insert(node, tk.END, text='    ' + name, values=(shown,))
            self._editable[iid] = dict(kind='property', offset=off, fmt=fmt, prop_name=name)

    # ---------------- edit values in place ----------------
    # Edits mutate SaveFile.decompressed_blob1 (a bytearray) directly - there's no write-back-to-
    # disk path yet. Recompressing blob1 needs the checksum that sits between each LZSS block, and
    # that one's still unsolved: it's not plain CRC32 and not the usual Adler-style checksum either
    # way I tried it. A "Save" button that could write bytes the real game rejects or crashes on
    # would be worse than not having the feature, so export-to-.bin is the safe option for now.
    def on_tree_double_click(self, ev):
        if self.detail_tree.identify_region(ev.x, ev.y) == 'heading':
            return
        iid = self.detail_tree.identify_row(ev.y)
        meta = self._editable.get(iid)
        if meta is None:
            return
        self._open_edit_dialog(iid, meta)

    def _open_edit_dialog(self, iid, meta):
        dec = getattr(self, '_sgo_dec', None)
        if dec is None:
            return
        prop_name = meta['prop_name']
        fmt = meta['fmt']
        off = meta['offset']
        cur = struct.unpack_from(fmt, dec, off)[0]
        enum_table = PS.ENUM_NAMES.get(prop_name)
        # Bools get the same readonly-dropdown treatment as enums -- a free-text byte box would
        # accept 255 for a field the game only ever writes 0 or 1 to.
        is_bool = enum_table is None and PS.is_bool_field(prop_name)

        dlg = tk.Toplevel(self)
        dlg.title('Edit %s' % prop_name)
        dlg.transient(self)
        dlg.resizable(False, False)
        ttk.Label(dlg, text='%s  (offset %#x, %s)' % (prop_name, off, fmt)).pack(padx=10, pady=(10, 4))

        result = {}
        if enum_table:
            options = sorted(enum_table.items())
            var = tk.StringVar(value=next((nm for v, nm in options if v == cur), str(cur)))
            box = ttk.Combobox(dlg, textvariable=var, state='readonly',
                                values=[nm for _v, nm in options], width=36)
            box.pack(padx=10, pady=4)
            by_name = {nm: v for v, nm in options}

            def get_value():
                return by_name[var.get()]
        elif is_bool:
            options = [(0, '0 - false'), (1, '1 - true')]
            by_name = {nm: v for v, nm in options}
            # An out-of-range byte already on disk still shows as-is rather than being silently
            # rounded to a lie; picking from the list is what normalises it back to 0/1.
            var = tk.StringVar(value=dict(options).get(cur, '%d - (unexpected)' % cur))
            box = ttk.Combobox(dlg, textvariable=var, state='readonly',
                                values=[nm for _v, nm in options], width=36)
            box.pack(padx=10, pady=4)

            def get_value():
                return by_name[var.get()]
        else:
            var = tk.StringVar(value=str(cur))
            entry = ttk.Entry(dlg, textvariable=var, width=24)
            entry.pack(padx=10, pady=4)
            entry.select_range(0, tk.END)
            entry.focus_set()

            def get_value():
                text = var.get().strip()
                if fmt == '<f':
                    return float(text)
                return int(text, 0)   # base 0: accepts "123", "0x7b", etc.

        err_label = ttk.Label(dlg, text='', foreground='red')
        err_label.pack(padx=10)

        def confirm(event=None):
            try:
                new_val = get_value()
                struct.pack(fmt, new_val)   # validates range/type before touching the buffer
            except (ValueError, KeyError, struct.error) as ex:
                err_label.config(text=str(ex))
                return
            struct.pack_into(fmt, dec, off, new_val)
            self._dirty = True
            shown = self._format_property_value(prop_name, new_val) if meta['kind'] == 'property' else str(new_val)
            self.detail_tree.item(iid, values=(shown,))
            self._report_dirty_state()
            dlg.destroy()

        btns = ttk.Frame(dlg)
        btns.pack(pady=(4, 10))
        ttk.Button(btns, text='OK', command=confirm).pack(side=tk.LEFT, padx=4)
        ttk.Button(btns, text='Cancel', command=dlg.destroy).pack(side=tk.LEFT, padx=4)
        dlg.bind('<Return>', confirm)
        dlg.bind('<Escape>', lambda ev: dlg.destroy())
        dlg.grab_set()

    def _report_dirty_state(self):
        suffix = '  [edited in memory -- not written to disk; use Export to save the change]'
        base = self.title().split('  [edited')[0]
        self.title(base + (suffix if self._dirty else ''))

    # ---------------- copy-to-clipboard context menu ----------------
    # ttk.Treeview has no built-in text selection, so this covers all 6 columns
    # (value/typehash/uid/offset/size/kind), not just 'value'. Derived from DETAIL_COLUMNS (single
    # source of truth, avoids the two lists drifting apart).
    _COL_IDS = tuple(cid for cid, _label, _w in DETAIL_COLUMNS)
    _COL_LABELS = tuple(label for _cid, label, _w in DETAIL_COLUMNS)

    def _row_columns(self, iid):
        """(field_text, {col_id: value_str}) for one tree row, only including columns that
        actually have something in them (leaf/child rows only ever populate 'value')."""
        field = (self.detail_tree.item(iid, 'text') or '').strip()
        values = self.detail_tree.item(iid, 'values') or ()
        cols = {}
        for i, cid in enumerate(self._COL_IDS):
            v = str(values[i]) if i < len(values) else ''
            if v:
                cols[cid] = v
        return field, cols

    def on_tree_right_click(self, ev):
        # Column headers are handled separately (_show_header_menu). Checking identify_region
        # first keeps header clicks in their own branch instead of falling through to
        # identify_row(ev.y), which could otherwise resolve to whatever row sits at that y-offset
        # in row-space and pop the wrong context menu.
        if self.detail_tree.identify_region(ev.x, ev.y) == 'heading':
            self._show_header_menu(ev)
            return
        iid = self.detail_tree.identify_row(ev.y)
        if not iid:
            return
        self.detail_tree.selection_set(iid)
        self.detail_tree.focus(iid)
        field, cols = self._row_columns(iid)
        menu = self._ctx_menu
        menu.delete(0, 'end')
        menu.add_command(label='Copy field name', command=lambda: self._copy_to_clipboard(field))
        for cid, label in zip(self._COL_IDS, self._COL_LABELS):
            if cid in cols:
                v = cols[cid]
                menu.add_command(label='Copy %s (%s)' % (label, v), command=lambda v=v: self._copy_to_clipboard(v))
        menu.add_separator()
        row_text = '\t'.join([field] + [cols.get(c, '') for c in self._COL_IDS])
        menu.add_command(label='Copy row (tab-separated, all columns)',
                          command=lambda: self._copy_to_clipboard(row_text))
        # Copy the whole visible subtree (this row + every descendant), one line per row, indented
        # to match what's on screen -- the fastest way to grab a full record for pasting elsewhere
        # while going through the file manually.
        menu.add_command(label='Copy row + all children', command=lambda: self._copy_subtree(iid))
        try:
            menu.tk_popup(ev.x_root, ev.y_root)
        finally:
            menu.grab_release()

    def _copy_subtree(self, iid, depth=0, lines=None):
        top = lines is None
        if lines is None:
            lines = []
        field, cols = self._row_columns(iid)
        row = '\t'.join([field] + [cols.get(c, '') for c in self._COL_IDS])
        lines.append('%s%s' % ('  ' * depth, row))
        for child in self.detail_tree.get_children(iid):
            self._copy_subtree(child, depth + 1, lines)
        if top:
            self._copy_to_clipboard('\n'.join(lines))
        return lines

    def _copy_to_clipboard(self, text):
        self.clipboard_clear()
        self.clipboard_append(text)

    def _on_select_file(self, event=None):
        sel = self.tree_files.selection()
        if sel:
            self._select_file(sel[0])

    def _select_file(self, path):
        try:
            sf = PS.SaveFile(path)
        except Exception as ex:
            messagebox.showerror('Failed to load', str(ex))
            return
        self.current = sf
        self._dirty = False
        self._populate_details(sf)
        self._report_dirty_state()

    def _populate_details(self, sf):
        self.detail_tree.delete(*self.detail_tree.get_children())
        self._editable = {}   # iid -> {kind, offset, fmt, ...} -- see on_tree_double_click
        h = sf.header

        hdr = self.detail_tree.insert('', tk.END, text='Header', open=True, tags=('section',))
        self.detail_tree.insert(hdr, tk.END, text='magic', values=('%#010x (%s)' % (h['magic'], 'RGMH'),))
        self.detail_tree.insert(hdr, tk.END, text='version', values=(h['version'],))
        self.detail_tree.insert(hdr, tk.END, text='title', values=(h['title'],))
        self.detail_tree.insert(hdr, tk.END, text='level_name', values=(h['level_name'],))
        self.detail_tree.insert(hdr, tk.END, text='forge_name', values=(h['forge_name'] or '(empty)',))
        self.detail_tree.insert(hdr, tk.END, text='reserved_str', values=(h['reserved_str'] or '(empty)',))
        ts = h['timestamp_utc']
        self.detail_tree.insert(hdr, tk.END, text='timestamp (UTC)',
                                 values=(ts.isoformat(sep=' ') if ts else '(invalid)',))
        self.detail_tree.insert(hdr, tk.END, text='checksum (blob1, @0x202C)', values=('%#010x' % h['checksum'],))
        self.detail_tree.insert(hdr, tk.END, text='blob1_size', values=(h['blob1_size'],))
        self.detail_tree.insert(hdr, tk.END, text='blob2_size', values=(h['blob2_size'],))
        self.detail_tree.insert(hdr, tk.END, text='trailer_size (screenshot)', values=(h['trailer_size'],))
        self.detail_tree.insert(hdr, tk.END, text='const1 @0x18', values=('%#018x' % h['const1'],))
        self.detail_tree.insert(hdr, tk.END, text='const2 @0x20', values=('%#018x' % h['const2'],))

        cp = self.detail_tree.insert('', tk.END, text='Checkpoint (blob2)', open=True)
        self.detail_tree.insert(cp, tk.END, text='checkpoint_code', values=(sf.blob2['checkpoint_code'],))
        region = sf.blob2['checkpoint_region']
        self.detail_tree.insert(cp, tk.END, text='resolved region',
                                 values=(region or '(unknown code)',))
        self.detail_tree.insert(cp, tk.END, text='level_name (repeated)', values=(sf.blob2['level_name'],))
        self.detail_tree.insert(cp, tk.END, text='marker', values=(sf.blob2['marker'],))
        self.detail_tree.insert(cp, tk.END, text='raw size', values=(len(sf.blob2['raw']),))

        # Save-persisted field census, straight from POP0.schema's own 0x08000000 flag bit -- a
        # static, whole-game reference (same for every save file). Every class/field here is
        # something the engine can persist to a save; not all of them will actually appear as a
        # record in any one given save (e.g. CurrentTrapSynchroZone is sometimes absent).
        census = self.detail_tree.insert(
            '', tk.END, text='Save-Persisted Field Census (schema, same for every save)', open=False)
        for cls, fields in sorted(PS.save_persisted_census().items()):
            cls_node = self.detail_tree.insert(census, tk.END, text='%s (%d fields)' % (cls, len(fields)))
            for nm, kind, w in fields:
                wtxt = ('%d bytes' % w) if w is not None else 'width unknown (kind=%#x)' % kind
                self.detail_tree.insert(cls_node, tk.END, text='  ' + nm, values=(wtxt,))

        gs = self.detail_tree.insert('', tk.END, text='Game State (blob1)', open=True)
        dec = sf.decompressed_blob1
        if dec is None:
            self.detail_tree.insert(gs, tk.END, text='decompression', values=('FAILED: ' + str(sf._decompress_error),))
        else:
            self.detail_tree.insert(gs, tk.END, text='decompressed size', values=(len(dec),))
            objs = PS.enumerate_savegameobjects(dec)
            self._sgo_objs = objs
            self._sgo_dec = dec
            arr = self.detail_tree.insert(
                gs, tk.END, text='SaveGameObject array (%d instances)' % len(objs), open=False)
            for i, o in enumerate(objs):
                node, ptab = self._insert_record_row(
                    arr, dec, iid='sgo_%d' % i, index=i, offset=o['offset'], uid=o['uid'],
                    kind=o['kind'], size=o['size'], tag='sgo')
                if ptab:
                    self._insert_property_children(node, dec, o['offset'], ptab, record_size=o['size'])
                elif o['size'] == 364:
                    slots = PS.read_slots(dec, o['offset'])
                    if slots:
                        for si, s in enumerate(slots):
                            slot_name = PS.resolve_instance_name(s['uid'])
                            field = 'slot %d%s' % (si, (' %s' % slot_name) if slot_name else '')
                            slot_iid = self.detail_tree.insert(node, tk.END, text='  ' + field, values=(s['state'],))
                            # offset is confirmed (state byte @ local+85 within each 91-byte
                            # sub-block) even though its semantic meaning isn't -- still safe to
                            # make editable.
                            self._editable[slot_iid] = dict(
                                kind='slot', offset=o['offset'] + si * 91 + 85, fmt='B', prop_name=field)
            note = self.detail_tree.insert(
                gs, tk.END, text='(per-instance field decode)',
                values=('not fully cracked yet -- see pop_save.py docstring; click an instance to hex-dump it',))

            # Records enumerate_savegameobjects() structurally can't see (non-4-byte-aligned
            # typehash) -- found via a separate, narrowly-targeted class-signature lookup instead
            # (see pop_save.find_unaligned_records() for why the general scanner isn't safe to
            # widen yet).
            unaligned = PS.find_unaligned_records(dec)
            self._sgo_unaligned = unaligned
            ua_node = self.detail_tree.insert(
                gs, tk.END,
                text='Records missed by the aligned scan (%d found via class-signature lookup)' % len(unaligned),
                open=len(unaligned) > 0)
            if not unaligned:
                self.detail_tree.insert(ua_node, tk.END, text='(none found in this save)')
            for j, e in enumerate(unaligned):
                rec_node, ptab = self._insert_record_row(
                    ua_node, dec, iid='ua_%d' % j, index=None, offset=e['offset'], uid=e['uid'],
                    kind='unaligned', size=None, tag='sgo_unaligned',
                    extra=[('offset mod 4', e['offset'] % 4)])
                if ptab:
                    self._insert_property_children(rec_node, dec, e['offset'], ptab)

        self._show_hex(dec if dec is not None else b'')
        self.status.config(text=os.path.basename(sf.path))

    def _on_select_detail(self, event=None):
        sel = self.detail_tree.selection()
        if not sel:
            return
        dec = getattr(self, '_sgo_dec', None)
        if dec is None:
            return
        if sel[0].startswith('sgo_') and not sel[0].startswith('sgo_unaligned'):
            idx = int(sel[0].split('_', 1)[1])
            objs = getattr(self, '_sgo_objs', None)
            if not objs or idx >= len(objs):
                return
            o = objs[idx]
            self._show_hex(dec[o['offset']:o['end']])
        elif sel[0].startswith('ua_'):
            idx = int(sel[0].split('_', 1)[1])
            unaligned = getattr(self, '_sgo_unaligned', None)
            if not unaligned or idx >= len(unaligned):
                return
            off = unaligned[idx]['offset']
            # true size unknown (see find_unaligned_records docstring) -- show a generous fixed
            # window from the record's own start instead of guessing an end boundary
            self._show_hex(dec[off:off + 512])

    def _show_hex(self, data):
        self.hexbox.delete('1.0', tk.END)
        self.hexbox.insert('1.0', hexdump_lines(data))

    def export_blob1(self):
        if not self.current or self.current.decompressed_blob1 is None:
            messagebox.showinfo('Nothing to export', 'Select a save with a decompressed blob1 first.')
            return
        out = filedialog.asksaveasfilename(defaultextension='.bin',
                                            initialfile=os.path.basename(self.current.path) + '.blob1.bin')
        if out:
            open(out, 'wb').write(self.current.decompressed_blob1)
            self.status.config(text='wrote ' + out)

def main():
    start = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SAVE_DIR
    app = SaveExplorer(start)
    app.mainloop()


if __name__ == '__main__':
    main()
