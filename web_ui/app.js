'use strict';

// ---- mock data, used only when window.pywebview isn't present (e.g. previewing this file in
// a plain browser instead of running it through server.py/pywebview) ----
const MOCK_RESULT = {
  title: '2017-11-26 01h14m24s Desert',
  subtitle: 'Desert',
  summary: {
    current_act: 'Act 2',
    light_seeds: 412,
    light_seeds_max: 1001,
    power_plates: [
      { name: 'Rebound', color: '#e5484d', enabled: true },
      { name: 'Grapple', color: '#3b9eff', enabled: false },
      { name: 'Dash', color: '#30a46c', enabled: true },
      { name: 'FlyOnBeam', color: '#f5c518', enabled: false },
    ],
    corruption_on: 2,
    corruption_total: 5,
  },
  tree: {
    label: 'root', value: '', children: [
      { label: 'Header', value: '', children: [
        { label: 'level_name', value: 'Desert', children: [] },
      ]},
      { label: 'Game State (blob1)', value: '', children: [
        { label: 'Array-container objects', value: '4 traps · 6 powers · 1 portal loaders', children: [
          { label: 'TrapsManager', value: 'Traps[4]', children: [
            { label: '[0]', value: '', children: [
              { label: 'TrapType', value: 'Tremor (0)', mono: true, children: [] },
              { label: 'Enabled', value: 'true', mono: true, children: [] },
              { label: 'ManualActivation', value: 'false', mono: true, children: [] },
            ]},
          ]},
        ]},
      ]},
    ],
  },
};

const hasApi = () => !!window.pywebview && !!window.pywebview.api;

function callApi(name, ...args) {
  if (hasApi()) return window.pywebview.api[name](...args);
  if (name === 'load_save') return Promise.resolve(MOCK_RESULT);
  if (name === 'open_file_dialog') return Promise.resolve('mock-path');
  return Promise.resolve(null);
}

// ---- title bar controls ----
document.getElementById('btn-min').addEventListener('click', () => callApi('minimize'));
document.getElementById('btn-max').addEventListener('click', () => callApi('toggle_maximize'));
document.getElementById('btn-close').addEventListener('click', () => callApi('close'));
document.getElementById('titlebar-drag').addEventListener('dblclick', () => callApi('toggle_maximize'));

// ---- tree rendering ----
// Every expanded section's header row sticks to the top of the tree while you're scrolled
// inside it (so it's always one click away to collapse), stacked by nesting depth -- e.g.
// "Game State" sticks at the very top, "Composite objects" sticks just below it, and so on.
const STICKY_ROW_HEIGHT = 30;

function buildNode(n, depth = 0) {
  const hasChildren = n.children && n.children.length > 0;
  const wrapper = document.createElement(hasChildren ? 'details' : 'div');
  wrapper.className = 'node' + (hasChildren ? '' : ' leaf');

  const row = document.createElement(hasChildren ? 'summary' : 'div');
  row.className = 'node-row';
  if (hasChildren) {
    row.classList.add('sticky-row');
    row.style.top = (depth * STICKY_ROW_HEIGHT) + 'px';
    row.style.zIndex = String(1000 - depth);
  }

  const field = document.createElement('div');
  field.className = 'node-field';
  const caret = document.createElement('span');
  caret.className = 'node-caret';
  caret.textContent = hasChildren ? '▾' : '';
  const label = document.createElement('span');
  label.textContent = n.label;
  field.appendChild(caret);
  field.appendChild(label);

  const value = document.createElement('div');
  value.className = 'node-value' + (n.mono ? ' mono' : '');
  value.textContent = n.value || '';

  row.appendChild(field);
  row.appendChild(value);
  wrapper.appendChild(row);

  if (hasChildren) {
    const childWrap = document.createElement('div');
    childWrap.className = 'node-children';
    for (const child of n.children) childWrap.appendChild(buildNode(child, depth + 1));
    wrapper.appendChild(childWrap);
  }

  wrapper.dataset.label = n.label.toLowerCase();
  wrapper.dataset.value = (n.value || '').toLowerCase();
  return wrapper;
}

function renderTree(root) {
  const container = document.getElementById('tree');
  container.innerHTML = '';
  // root itself is just a wrapper -- render its children as top-level sections, first two open.
  root.children.forEach((child, i) => {
    const el = buildNode(child);
    if (el.tagName === 'DETAILS' && i < 3) el.open = true;
    container.appendChild(el);
  });
}

// ---- filter ----
function nodeMatches(el, text) {
  const self = el.dataset.label.includes(text) || el.dataset.value.includes(text);
  let childMatch = false;
  const childWrap = el.querySelector(':scope > .node-children');
  if (childWrap) {
    for (const child of childWrap.children) {
      if (nodeMatches(child, text)) childMatch = true;
    }
  }
  const visible = !text || self || childMatch;
  el.classList.toggle('hidden', !visible);
  if (visible && text && el.tagName === 'DETAILS') el.open = true;
  return self || childMatch;
}

document.getElementById('search').addEventListener('input', (ev) => {
  const text = ev.target.value.trim().toLowerCase();
  const tree = document.getElementById('tree');
  for (const top of tree.children) nodeMatches(top, text);
});

// ---- summary panel ----
function statCard(label, value) {
  const row = document.createElement('div');
  row.className = 'summary-row';
  row.innerHTML = '<div class="summary-label"></div><div class="summary-value"></div>';
  row.querySelector('.summary-label').textContent = label;
  row.querySelector('.summary-value').textContent = value;
  return row;
}

function seedRingCard(count, max) {
  const card = document.createElement('div');
  card.className = 'summary-row';
  const r = 28;
  const c = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(1, max ? count / max : 0));
  const offset = c * (1 - pct);
  card.innerHTML = `
    <div class="summary-label">Light Seeds</div>
    <div class="seed-ring-wrap">
      <svg width="72" height="72" viewBox="0 0 72 72">
        <defs>
          <linearGradient id="seedGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="#ffffff"/>
            <stop offset="100%" stop-color="#5eb1ff"/>
          </linearGradient>
        </defs>
        <circle cx="36" cy="36" r="${r}" fill="none" stroke="#26262c" stroke-width="6"/>
        <circle cx="36" cy="36" r="${r}" fill="none" stroke="url(#seedGrad)" stroke-width="6"
          stroke-linecap="round" stroke-dasharray="${c}" stroke-dashoffset="${offset}"
          transform="rotate(-90 36 36)"/>
      </svg>
      <div class="seed-ring-text">${count}<span>/${max}</span></div>
    </div>
  `;
  return card;
}

function powerPlatesCard(plates) {
  const card = document.createElement('div');
  card.className = 'summary-row';
  const label = document.createElement('div');
  label.className = 'summary-label';
  label.textContent = 'Power Plates';
  card.appendChild(label);
  const grid = document.createElement('div');
  grid.className = 'plate-grid';
  for (const p of plates) {
    const chip = document.createElement('div');
    chip.className = 'plate-chip' + (p.enabled ? ' enabled' : '');
    const dot = document.createElement('span');
    dot.className = 'plate-dot';
    dot.style.background = p.color;
    const name = document.createElement('span');
    name.textContent = p.name;
    chip.appendChild(dot);
    chip.appendChild(name);
    grid.appendChild(chip);
  }
  card.appendChild(grid);
  return card;
}

function renderSummary(s) {
  const list = document.getElementById('summary-list');
  list.innerHTML = '';
  if (!s) {
    list.innerHTML = '<p id="summary-empty">No save loaded.</p>';
    return;
  }
  list.appendChild(statCard('Current Act', s.current_act));
  list.appendChild(seedRingCard(s.light_seeds, s.light_seeds_max));
  list.appendChild(powerPlatesCard(s.power_plates));
  list.appendChild(statCard('Corruption Zones Set', `${s.corruption_on} / ${s.corruption_total}`));
}

// ---- load save ----
function applyLoadResult(result) {
  if (!result || result.error) {
    document.getElementById('page-title').textContent = 'Failed to load save';
    document.getElementById('page-subtitle').textContent = (result && result.error) || 'unknown error';
    renderSummary([]);
    document.getElementById('tree').innerHTML = '';
    return;
  }
  document.getElementById('page-title').textContent = result.title;
  document.getElementById('page-subtitle').textContent = result.subtitle;
  renderSummary(result.summary);
  renderTree(result.tree);
  document.getElementById('search').value = '';
}

async function loadSave(path) {
  applyLoadResult(await callApi('load_save', path));
}

document.getElementById('btn-load').addEventListener('click', async () => {
  const path = await callApi('open_file_dialog');
  if (path) await loadSave(path);
});

// Called by server.py's setup_drag_drop (via window.evaluate_js) once a real OS drag-and-drop
// resolves to an actual filesystem path -- see that function's docstring for why this can't just
// be a plain JS 'drop' listener.
window.__onSaveDropped = (result) => applyLoadResult(result);

// ---- drag-and-drop visual feedback (path extraction itself happens in server.py) ----
const dropZone = document.getElementById('drop-zone');
['dragenter', 'dragover'].forEach((evt) => {
  dropZone.addEventListener(evt, (e) => {
    e.preventDefault();
    dropZone.classList.add('drag-over');
  });
});
['dragleave', 'drop'].forEach((evt) => {
  dropZone.addEventListener(evt, (e) => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
  });
});

// ---- collapsible search box ----
const searchBox = document.getElementById('search-box');
const searchInput = document.getElementById('search');
document.getElementById('btn-search-toggle').addEventListener('click', () => {
  const expanding = !searchBox.classList.contains('expanded');
  searchBox.classList.toggle('expanded', expanding);
  if (expanding) searchInput.focus();
});
searchInput.addEventListener('blur', () => {
  if (!searchInput.value) searchBox.classList.remove('expanded');
});
