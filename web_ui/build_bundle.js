// Regenerates bundle.js from the ES-module source files in js/ + app.js.
// Run this (`node build_bundle.js`) after editing any of those files -- index.html loads only
// bundle.js as a classic (non-module) script, since desktop Chrome/Edge refuse to fetch ES module
// imports over file:// (CORS), which broke double-click-to-open on a real browser.
'use strict';
const fs = require('fs');
const path = require('path');

const WEB_UI = __dirname;
const JS_DIR = path.join(WEB_UI, 'js');

const order = [
  'binreader.js', 'crc32.js', 'lzss.js', 'popsave_header.js',
  'schema.js', 'popsave.js', 'tree_builder.js',
  'data_schema.js', 'data_forge_names.js',
];

function strip(src) {
  return src
    .split('\n')
    .filter((line) => !/^import .*;\s*$/.test(line))
    .filter((line) => !/^export \{[^}]*\};\s*$/.test(line))
    .map((line) => line.replace(/^export (class|const|function)/, '$1'))
    .join('\n');
}

let out = "'use strict';\n\n";
for (const f of order) {
  out += `// ---- ${f} ----\n`;
  out += strip(fs.readFileSync(path.join(JS_DIR, f), 'utf8'));
  out += '\n\n';
}
out += '// ---- app.js ----\n';
out += strip(fs.readFileSync(path.join(WEB_UI, 'app.js'), 'utf8'));

fs.writeFileSync(path.join(WEB_UI, 'bundle.js'), out);
console.log('wrote', path.join(WEB_UI, 'bundle.js'), out.length, 'bytes');
