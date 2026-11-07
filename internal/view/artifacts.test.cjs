// Runs the real artifacts.js (served to the page) in node with a minimal DOM.
const fs = require('node:fs'), vm = require('node:vm'), path = require('node:path'), assert = require('node:assert/strict');
class El {
  constructor(tag) { this.tagName = tag; this.children = []; this.style = {}; this.textContent = ''; this.parent = null; }
  appendChild(c) { c.parent = this; this.children.push(c); return c; }
  replaceWith(n) { const p = this.parent, i = p.children.indexOf(this); n.parent = p; p.children[i] = n; }
  text() { return this.textContent + this.children.map(c => c.text()).join(' '); }
  find(tag) { if (this.tagName === tag) return this; for (const c of this.children) { const f = c.find(tag); if (f) return f; } return null; }
}
const doc = {createElement: t => new El(t)};
const window = {};
vm.runInNewContext(fs.readFileSync(path.join(__dirname, 'artifacts.js'), 'utf8'), {window, AbortController, setTimeout, clearTimeout, Array});
const A = window.pentrailArtifacts;
const resp = (status, body) => ({ok: status >= 200 && status < 300, status, json: async () => body});
(async () => {
  // HTTP 500: unknown state with retry, never "no files" or "all imported"
  let r = await A.load(async () => resp(500, 'internal'), 7);
  assert.equal(r.ok, false);
  const root = new El('main');
  root.appendChild(A.render(doc, r, async () => A.load(async () => resp(200, [{cmd_index: 1, tool: 'nmap', state: 'imported', path: 'a.xml'}]), 7)));
  let t = root.text();
  assert.match(t, /state unknown/); assert.match(t, /the viewer reported an error, code 500/); assert.doesNotMatch(t, /HTTP/); assert.match(t, /does not mean there are no files/);
  assert.doesNotMatch(t, /all imported/);
  // retry replaces the box with the real list
  await root.find('button').onclick();
  t = root.text();
  assert.match(t, /Tool output files: 1 — all imported/); assert.doesNotMatch(t, /state unknown/);
  // timeout (aborted request) and network error
  r = await A.load((url, opt) => new Promise((_, rej) => opt.signal.addEventListener('abort', () => rej(Object.assign(new Error('x'), {name: 'AbortError'})))), 7, 30);
  assert.equal(r.ok, false); assert.equal(r.error, 'the request timed out');
  r = await A.load(async () => { throw new TypeError('Failed to fetch'); }, 7);
  assert.equal(r.ok, false); assert.equal(r.error, 'connection error');
  r = await A.load(async () => resp(200, {not: 'a list'}), 7);
  assert.equal(r.ok, false);
  // known empty list: nothing shown
  assert.equal(A.render(doc, {ok: true, items: []}, null), null);
  // waiting/pending are not "all imported"; mixed: separate counts
  const pend = [{cmd_index: 1, tool: 'nmap', state: 'imported'}, {cmd_index: 2, tool: 'ffuf', state: 'waiting'}, {cmd_index: 3, tool: 'nuclei', state: 'pending'}];
  assert.equal(A.summaryText(pend), 'Tool output files: 3 — in progress (tool running or waiting for import): 2, imported completely: 1');
  const mixed = pend.concat([{cmd_index: 4, tool: 'nmap', state: 'imported_partial', partial: true}, {cmd_index: 5, tool: 'x', state: 'imported', cleanup_pending: true}, {cmd_index: 6, tool: 'y', state: 'missing'}]);
  assert.equal(JSON.stringify(A.classify(mixed)), JSON.stringify({complete: 1, inProgress: 2, problems: 3}));
  assert.equal(A.summaryText(mixed), 'Tool output files: 6 — needs attention: 3, in progress (tool running or waiting for import): 2, imported completely: 1');
  const box = A.render(doc, {ok: true, items: mixed}, null);
  assert.equal(box.open, true); assert.match(box.text(), /plaintext copy waiting for deletion/);
  assert.equal(A.summaryText([{state: 'imported'}, {state: 'imported'}]), 'Tool output files: 2 — all imported');
  console.log('PASS artifacts: HTTP 500/timeout/network/invalid -> unknown state with retry; retry renders the list; empty list hidden; waiting/pending never "all imported"; mixed counts');
})().catch(e => { console.error(e); process.exit(1); });
