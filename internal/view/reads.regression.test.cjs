// 04BM: the remaining viewer reads in the REAL page code and modules — the
// graph (main read, the detail panel's commands/entities, the output
// preview), the cleanup checklist and database identity, the notes list, the
// tool-output file list and the full session record — against rejected
// fetches, HTTP 401/403/404/500, invalid data, a fetch or body that never
// settles (bounded: a controllable clock), Try again, and stale or retired
// renders. Run: node reads.regression.test.cjs [dir]   (dir: another copy of
// index.html, xref.js, cleanup.js, artifacts.js, notes.js — negative control)
'use strict';
const fs = require('node:fs'), vm = require('node:vm'), path = require('node:path'), assert = require('node:assert/strict');
const DIR = process.argv[2] || __dirname;
const src = f => fs.readFileSync(path.join(DIR, f), 'utf8');
const page = src('index.html');
const cut = (from, to) => { const i = page.indexOf(from), j = page.indexOf(to, i); if (i < 0 || j < 0) throw new Error('region not found: ' + from); return page.slice(i, j); };
const helpers = page.includes('// ---- reads with a bound') ? cut('// ---- reads with a bound', 'let sessionInfo=new Map();') : '';

const unhandled = [];
process.on('unhandledRejection', e => unhandled.push(String(e && e.message || e)));

// ---- controllable clock ----
function clock() {
  let now = 0, id = 0; const ts = new Map();
  return { setTimeout(fn, ms) { ts.set(++id, { fn, at: now + (ms || 0) }); return id; }, clearTimeout(i) { ts.delete(i); },
    async advance(ms) { const end = now + ms; for (;;) { const due = [...ts].filter(([, t]) => t.at <= end).sort((a, b) => a[1].at - b[1].at)[0]; if (!due) break; now = due[1].at; ts.delete(due[0]); due[1].fn(); await flush(); } now = end; await flush(); } };
}
const flush = async () => { for (let i = 0; i < 30; i++) await new Promise(r => setImmediate(r)); };

// ---- responses ----
const SECRET = 'BODY-SECRET-91c2';
const hdr = (h = {}) => ({ get: k => (k in h ? String(h[k]) : null) });
const ok = (v, h) => ({ ok: true, status: 200, headers: hdr(h), json: async () => (typeof v === 'string' ? JSON.parse(v) : v), text: async () => (typeof v === 'string' ? v : JSON.stringify(v)) });
const http = s => ({ ok: false, status: s, headers: hdr(), json: async () => ({ error: SECRET }), text: async () => SECRET });
const never = () => new Promise(() => {});
const bodyHang = () => ({ ok: true, status: 200, headers: hdr(), json: never, text: never });
const down = () => Promise.reject(new TypeError('Failed to fetch'));
function router(routes) {
  const calls = [];
  const fetch = (url, init) => { calls.push({ url, signal: init && init.signal }); const key = Object.keys(routes).filter(k => url.startsWith(k)).sort((a, b) => b.length - a.length)[0]; if (!key) return down(); const r = routes[key]; return typeof r === 'function' ? r(url, init) : Promise.resolve(r); };
  return { fetch, calls };
}
const noSecrets = t => { assert.ok(!t.includes(SECRET) && !t.includes('/api/'), 'leaked: ' + t); };

// ---- minimal DOM ----
class El {
  constructor(tag) { this.tagName = tag; this.children = []; this._html = ''; this._text = ''; this.dataset = {}; this.style = {}; this.attrs = {}; this.sel = new Map(); this.cls = new Set(); this.hidden = false; this.disabled = false;
    const me = this; this.classList = { toggle(c, on) { const v = on === undefined ? !me.cls.has(c) : on; v ? me.cls.add(c) : me.cls.delete(c); return v; }, add(c) { me.cls.add(c); }, remove(c) { me.cls.delete(c); }, contains(c) { return me.cls.has(c); } }; }
  set className(v) { this.cls = new Set(String(v).split(/\s+/).filter(Boolean)); } get className() { return [...this.cls].join(' '); }
  set innerHTML(v) { this._html = String(v); this._text = ''; this.children = []; this.sel = new Map(); } get innerHTML() { return this._html; }
  set textContent(v) { this._text = String(v); this._html = ''; this.children = []; } get textContent() { return this._text + this._html.replace(/<[^>]*>/g, '') + this.children.map(c => c.textContent).join(''); }
  appendChild(c) { this.children.push(c); return c; } append(...cs) { for (const c of cs) this.appendChild(typeof c === 'string' ? Object.assign(new El('#text'), { _text: c }) : c); }
  insertBefore(c) { this.children.push(c); return c; }
  querySelector(s) { if (!this.sel.has(s)) this.sel.set(s, new El('stub')); return this.sel.get(s); } querySelectorAll() { return []; }
  setAttribute(k, v) { this.attrs[k] = String(v); } getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; } removeAttribute(k) { delete this.attrs[k]; }
  remove() {} scrollIntoView() {} focus() {}
  all() { return [this, ...this.children.flatMap(c => c.all())]; }
}
// a click on a button drawn as HTML inside el (data-x="1")
function clickHTML(el, attr) { assert.ok(el.innerHTML.includes(attr + '='), 'no ' + attr + ' button: ' + el.innerHTML.slice(0, 200)); const b = { dataset: {}, classList: { contains: () => false } }; b.dataset[attr.replace(/^data-/, '').replace(/-(\w)/g, (_, c) => c.toUpperCase())] = '1'; el.onclick({ target: { closest: () => b } }); }

// ---- the graph renderer ----
function graphEnv(routes) {
  const c = clock(), net = router(routes), els = {}, graphs = [];
  const el = id => els[id] || (els[id] = new El('div'));
  const ctx = { document: { getElementById: el, querySelector: () => new El('x') }, console, AbortController, setTimeout: c.setTimeout, clearTimeout: c.clearTimeout, fetch: net.fetch,
    esc: v => String(v).replace(/[<>&"]/g, ''), TYPE_LABEL: { host: 'host' }, TYPE_ORDER: [], NODE_COLORS: {}, renderLegend() {}, graph: null,
    fmtTime: ms => 'T' + ms, fmtDur: () => '', fmtBytes: n => n + ' B', strip: s => String(s), pendingNodes: null, showCommand() {},
    loadNotes: never, noteLinksHTML: () => '', noteLinkClick: () => false,
    initGraph: (cv, data, onSelect) => { const g = { data, onSelect, destroyed: false, destroy() { this.destroyed = true; }, select: () => true, fit() {}, resetRoute() {} }; graphs.push(g); return g; } };
  vm.createContext(ctx);
  vm.runInContext(src('xref.js'), ctx);
  if (helpers) vm.runInContext(helpers, ctx);
  vm.runInContext(cut('let graphRequest=0;', '\nloadSessions();') + '\nthis.renderGraph=renderGraph;this.__set=(s,v)=>{activeSession=s;activeView=v;};', ctx);
  return { ctx, c, net, el, graphs, detail: () => el('gdetail'), label: () => el('gcanvas').getAttribute('aria-label') || '' };
}
const G = { '/api/graph': ok({ nodes: [{ id: 'h1', label: '192.0.2.10', type: 'host', cmd_index: 0 }], edges: null }),
  '/api/commands': ok([{ index: 0, command: 'nmap 192.0.2.10', out_start_off: 0, out_end_off: 5, started_ms: 1 }]),
  '/api/entities': ok([{ type: 'host', value: '192.0.2.10', cmd_index: 0 }]), '/api/output': ok('hello', { 'X-Missing-Bytes': '0' }) };

// ---- the cleanup renderer ----
function cleanupEnv(routes) {
  const c = clock(), net = router(routes), main = new El('div');
  const store = new Map();
  const ctx = { document: { getElementById: () => main, createElement: t => new El(t), createTextNode: s => Object.assign(new El('#text'), { _text: String(s) }) }, console, AbortController, setTimeout: c.setTimeout, clearTimeout: c.clearTimeout, fetch: net.fetch,
    esc: v => String(v == null ? '' : v).replace(/[<>&"]/g, ''), fmtTime: ms => 'T' + ms, activeSession: 1, activeView: 'cleanup' };
  ctx.window = ctx; ctx.localStorage = { getItem: k => store.get(k) || null, setItem: (k, v) => store.set(k, v), removeItem: k => store.delete(k) };
  vm.createContext(ctx);
  vm.runInContext(src('cleanup.js'), ctx);
  if (helpers) vm.runInContext(helpers, ctx);
  vm.runInContext(cut('const CLEAN_LABEL', '\n// ---- tabs ----') + '\nthis.renderCleanup=renderCleanup;', ctx);
  return { ctx, c, net, main };
}
const NS = '0123456789abcdef0123456789abcdef';

// ---- the full session record (inside renderTimeline) ----
function recordEnv(routes) {
  const c = clock(), net = router(routes), doc = { els: {}, getElementById(id) { return this.els[id] || (this.els[id] = new El('div')); }, createElement: t => new El(t) };
  const ctx = { document: doc, window: {}, console, AbortController, setTimeout: c.setTimeout, clearTimeout: c.clearTimeout, fetch: net.fetch,
    esc: s => String(s == null ? '' : s), fmtTime: () => 't', fmtDur: () => 'd', fmtBytes: n => n + ' B', strip: s => s, parseDet: () => ({}), detailSuffix: () => '', sevClass: () => '',
    TYPE_ORDER: [], TYPE_LABEL: {}, pendingCmd: null, renderActive() {}, showInGraph() {}, anchorNotes: () => [], noteLinksHTML: () => '', noteLinkClick: () => false,
    loadNotes: async () => ({ ok: true, notes: [] }), pentrailXref: { nodeIds: () => ({ ids: [] }) },
    pentrailArtifacts: { load: async () => ({ ok: true, items: [] }), render: () => null } };
  vm.createContext(ctx);
  const tl = cut('let timelineRequest=0;', '\n// ---- graph ----');
  vm.runInContext((helpers || '') + '\nlet sessionInfo=new Map(),activeSession=1,activeView="timeline";\n' + tl + '\nthis.renderTimeline=renderTimeline;', ctx);
  const raw = () => doc.getElementById('timeline').children.find(e => e.tagName === 'details');
  return { ctx, c, net, raw, open: async () => { ctx.renderTimeline(); await flush(); const r = raw(); assert.ok(r, 'no record section'); return { btn: r.querySelector('button'), warn: r.querySelector('.gapwarn'), pre: r.querySelector('pre') }; } };
}
const EV = { '/api/commands': ok([]), '/api/entities': ok([]), '/api/capture-events': ok([]) };

// ---- modules ----
function load(file, extra = {}) { const c = clock(); const ctx = { window: {}, console, AbortController, setTimeout: c.setTimeout, clearTimeout: c.clearTimeout, Array, ...extra }; vm.createContext(ctx); vm.runInContext(src(file), ctx); return { ctx, c, mod: ctx.window }; }

const tests = [];
const test = (n, f) => tests.push([n, f]);

test('R1 graph: rejected fetch, HTTP 401/403/404/500 and invalid data show an accurate error with Try again', async () => {
  const cases = [[down, /No connection to the Pentrail viewer/], [http(401), /\(401\).*link of this page is no longer valid/], [http(403), /\(403\)/], [http(404), /\(404\)/], [http(500), /internal error \(code 500\)/],
    [ok({ edges: [] }), /not valid/], [ok({ nodes: 'x', edges: [] }), /not valid/], [ok({ nodes: [], edges: 'x' }), /not valid/], [ok('{bad'), /not valid/]];
  for (const [r, re] of cases) {
    const e = graphEnv({ ...G, '/api/graph': r }); e.ctx.__set(1, 'graph'); e.ctx.renderGraph(); await flush();
    const t = e.detail().textContent; assert.match(t, re); noSecrets(t); assert.match(e.label(), /could not be loaded/);
    assert.ok(e.detail().innerHTML.includes('data-gretry'), 'no Try again'); assert.equal(e.graphs.length, 0);
  }
});

test('R2 graph: a read or body that never settles times out after 15 s; Try again draws the graph; edges:null is a valid empty edge list', async () => {
  for (const r of [never, bodyHang]) {
    let mode = 'hang';
    const e = graphEnv({ ...G, '/api/graph': () => mode === 'hang' ? (r === never ? never() : Promise.resolve(bodyHang())) : Promise.resolve(G['/api/graph']) });
    e.ctx.__set(1, 'graph'); e.ctx.renderGraph(); await flush();
    assert.match(e.label(), /loading/); await e.c.advance(15000);
    assert.match(e.detail().textContent, /did not answer within 15 s/);
    mode = 'ok'; clickHTML(e.detail(), 'data-gretry'); await flush();
    assert.equal(e.graphs.length, 1, 'retry did not draw'); assert.equal(e.graphs[0].data.nodes.length, 1);
  }
});

test('R3 graph: a late failure of A after B is drawn, and a retired Try again, change nothing', async () => {
  let rejectA;
  const e = graphEnv({ ...G, '/api/graph?session=1': () => new Promise((_, rj) => { rejectA = rj; }), '/api/graph?session=2': G['/api/graph'] });
  e.ctx.__set(1, 'graph'); e.ctx.renderGraph(); await flush();
  e.ctx.__set(2, 'graph'); e.ctx.renderGraph(); await flush();
  assert.equal(e.graphs.length, 1); const html = e.detail().innerHTML;
  rejectA(new TypeError('Failed to fetch')); await flush();
  assert.equal(e.detail().innerHTML, html, 'A error painted over B'); assert.ok(!e.graphs[0].destroyed);
  const f = graphEnv({ ...G, '/api/graph': down }); f.ctx.__set(1, 'graph'); f.ctx.renderGraph(); await flush();
  const before = f.net.calls.length; f.ctx.__set(1, 'timeline'); clickHTML(f.detail(), 'data-gretry'); await flush();
  assert.equal(f.net.calls.length, before, 'Try again acted outside the Graph view');
});

test('R4 graph detail: commands/entities that fail or hang are reported with Try again; Try again loads the command and its output', async () => {
  let mode = 'down';
  const CMDS = G['/api/commands'];
  const e = graphEnv({ ...G, '/api/commands': () => mode === 'down' ? down() : mode === 'hang' ? never() : Promise.resolve(CMDS) });
  e.ctx.__set(1, 'graph'); e.ctx.renderGraph(); await flush();
  e.graphs[0].onSelect({ id: 'h1', label: '192.0.2.10', type: 'host', cmd_index: 0 }); await flush();
  assert.match(e.detail().textContent, /Could not load the command\. No connection/); assert.ok(e.detail().innerHTML.includes('data-xretry'));
  mode = 'hang'; clickHTML(e.detail(), 'data-xretry'); await flush(); await e.c.advance(15000);
  assert.match(e.detail().textContent, /Could not load the command\. The viewer did not answer within 15 s/);
  mode = 'ok'; clickHTML(e.detail(), 'data-xretry'); await flush();
  assert.match(e.detail().innerHTML, /nmap 192\.0\.2\.10/); assert.match(e.detail().innerHTML, /hello/);
});

test('R5 graph output preview: a body that never arrives times out; 401 explains the expired link; the next selection asks again', async () => {
  let mode = 'hang';
  const e = graphEnv({ ...G, '/api/output': () => Promise.resolve(mode === 'hang' ? bodyHang() : mode === '401' ? http(401) : ok('hello', { 'X-Missing-Bytes': '0' })) });
  e.ctx.__set(1, 'graph'); e.ctx.renderGraph(); await flush();
  const sel = async () => { e.graphs[0].onSelect({ id: 'h1', label: '192.0.2.10', type: 'host', cmd_index: 0 }); await flush(); };
  await sel(); await e.c.advance(15000);
  assert.match(e.detail().textContent, /Could not read the output \(The viewer did not answer within 15 s/);
  mode = '401'; await sel(); assert.match(e.detail().textContent, /Could not read the output \(Access refused \(401\)/); noSecrets(e.detail().textContent);
  mode = 'ok'; await sel(); assert.match(e.detail().innerHTML, /hello/);
});

test('R6 cleanup: a checklist read that fails, hangs or is invalid is reported with Try again; Try again recovers; a retired Try again does nothing', async () => {
  for (const [r, re] of [[down, /No connection/], [http(401), /\(401\)/], [http(500), /code 500/], [ok({}), /not valid/], [never, /did not answer within 15 s/], [bodyHang, /did not answer within 15 s/]]) {
    const e = cleanupEnv({ '/api/changes': typeof r === 'function' && r !== down && r !== never ? () => Promise.resolve(r()) : r, '/api/identity': ok({ view_namespace: NS }) });
    e.ctx.renderCleanup(); await flush(); await e.c.advance(15000);
    const t = e.main.textContent; assert.match(t, /Could not read the checklist/); assert.match(t, re); assert.match(t, /does not mean there were no changes/); noSecrets(t);
    assert.ok(e.main.all().some(x => x.tagName === 'button' && x.textContent === 'Try again'), 'no Try again');
  }
  let fail = true;
  const e = cleanupEnv({ '/api/changes': () => fail ? down() : Promise.resolve(ok([])), '/api/identity': ok({ view_namespace: NS }) });
  e.ctx.renderCleanup(); await flush();
  const retry = e.main.all().find(x => x.tagName === 'button' && x.textContent === 'Try again');
  e.ctx.activeSession = 2; const before = e.net.calls.length; retry.onclick(); await flush();
  assert.equal(e.net.calls.length, before, 'retired Try again fetched');
  e.ctx.activeSession = 1; fail = false; retry.onclick(); await flush();
  assert.match(e.main.textContent, /checklist is empty/);
});

test('R7 cleanup: a database identity whose body never arrives is bounded; the checklist is shown with the state unknown', async () => {
  const e = cleanupEnv({ '/api/changes': ok([{ cmd_index: 0, category: 'service', description: 'synthetic change' }]), '/api/identity': () => Promise.resolve(bodyHang()) });
  e.ctx.renderCleanup(); await flush(); await e.c.advance(10000);
  assert.doesNotMatch(e.main.textContent, /loading…/);
  assert.equal(e.main.all().find(x => x.cls && x.cls.has('clhead')).dataset.state, 'unknown');
});

test('R8 full session record: success keeps offsets and the missing-bytes warning; failures append nothing and the same part loads again', async () => {
  let n = 0; const seen = [];
  const e = recordEnv({ ...EV, '/api/raw': url => { seen.push(url); n++;
    if (n === 1) return Promise.resolve(ok('part1 ', { 'X-Next-Offset': 6, 'X-Raw-Total': 12, 'X-Missing-Bytes': 3 }));
    if (n === 2) return Promise.resolve(http(401));
    if (n === 3) return Promise.resolve(ok('bad', { 'X-Next-Offset': 2, 'X-Raw-Total': 12, 'X-Missing-Bytes': 0 })); // goes backwards
    if (n === 4) return never();
    return Promise.resolve(ok('part2!', { 'X-Next-Offset': 12, 'X-Raw-Total': 12, 'X-Missing-Bytes': 0 })); } });
  const { btn, warn, pre } = await e.open();
  await btn.onclick(); assert.equal(pre.textContent, 'part1 '); assert.match(warn.textContent, /Incomplete record — 3 B missing/); assert.equal(btn.textContent, 'Load the next part');
  await btn.onclick(); assert.equal(pre.textContent, 'part1 '); assert.match(warn.textContent, /\(401\).*Nothing was added/); assert.equal(btn.disabled, false); noSecrets(warn.textContent);
  await btn.onclick(); assert.equal(pre.textContent, 'part1 '); assert.match(warn.textContent, /not valid session data/);
  const p = btn.onclick(); await flush(); await e.c.advance(15000); await p; assert.match(warn.textContent, /did not answer within 15 s/); assert.equal(pre.textContent, 'part1 ');
  await btn.onclick(); assert.equal(pre.textContent, 'part1 part2!'); assert.equal(btn.disabled, true); assert.equal(btn.textContent, 'Current record loaded');
  assert.ok(seen.slice(1).every(u => u.includes('start=6')), 'a failed part was skipped: ' + seen.join(' '));
});

test('R9 modules: notes list, tool-output file list, cleanup identity and the output preview settle when the body never arrives', async () => {
  const hang = async () => bodyHang();
  { const { mod, c } = load('notes.js'); const p = mod.pentrailNotes.api(hang).list(1); await flush(); await c.advance(15000); const r = await p; assert.equal(r.ok, false); assert.match(r.error, /timed out/); }
  { const { mod, c } = load('notes.js'); const r = await mod.pentrailNotes.api(async () => ok([{ nope: 1 }])).list(1); assert.equal(r.ok, false, 'a list of non-notes accepted'); void c; }
  { const { mod, c } = load('artifacts.js'); const p = mod.pentrailArtifacts.load(hang, 1); await flush(); await c.advance(10000); const r = await p; assert.equal(r.ok, false); assert.match(r.error, /timed out/); }
  { const { mod, c } = load('cleanup.js'); const p = mod.pentrailCleanup.namespace(hang); await flush(); await c.advance(10000); const r = await p; assert.equal(r.ok, false); assert.match(r.error, /timed out/); }
  { const { ctx, c } = load('xref.js'); const p = ctx.window.pentrailXref.loadOutput(hang, 1, { out_start_off: 0, out_end_off: 9 }, 100); await flush(); await c.advance(15000); const r = await p; assert.equal(r.ok, false); assert.equal(r.kind, 'timeout'); }
});

test('R10 full session record: a reply whose offset headers are missing, empty or not plain numbers is invalid; nothing is appended', async () => {
  const bad = [{}, { 'X-Next-Offset': '', 'X-Raw-Total': '', 'X-Missing-Bytes': '' }, { 'X-Raw-Total': 6, 'X-Missing-Bytes': 0 }, { 'X-Next-Offset': 6, 'X-Raw-Total': 6 },
    { 'X-Next-Offset': '6e0', 'X-Raw-Total': 6, 'X-Missing-Bytes': 0 }, { 'X-Next-Offset': ' 6', 'X-Raw-Total': 6, 'X-Missing-Bytes': 0 }, { 'X-Next-Offset': 6, 'X-Raw-Total': 6, 'X-Missing-Bytes': '-1' },
    { 'X-Next-Offset': '6.5', 'X-Raw-Total': 7, 'X-Missing-Bytes': 0 }, { 'X-Next-Offset': 6, 'X-Raw-Total': '0x6', 'X-Missing-Bytes': 0 }];
  let n = 0;
  const e = recordEnv({ ...EV, '/api/raw': () => Promise.resolve(n < bad.length ? ok('junk!!', bad[n++]) : ok('good!!', { 'X-Next-Offset': 6, 'X-Raw-Total': 6, 'X-Missing-Bytes': 0 })) });
  const { btn, warn, pre } = await e.open();
  for (let i = 0; i < bad.length; i++) {
    await btn.onclick();
    assert.equal(pre.textContent, '', 'headers ' + JSON.stringify(bad[i]) + ' were accepted');
    assert.match(warn.textContent, /not valid session data.*Nothing was added/); assert.equal(btn.disabled, false);
  }
  await btn.onclick(); assert.equal(pre.textContent, 'good!!'); assert.equal(btn.textContent, 'Current record loaded');
});

test('R11 graph detail: Try again after a failed command read shows the command that was asked for, not the first one found', async () => {
  let mode = 'down';
  const CMDS = ok([{ index: 0, command: 'host portal.example.com', out_start_off: 0, out_end_off: 0, started_ms: 1 }, { index: 2, command: 'nmap portal.example.com', out_start_off: 0, out_end_off: 0, started_ms: 2 }]);
  const e = graphEnv({ ...G, '/api/entities': ok([{ type: 'host', value: '192.0.2.10', cmd_index: 0 }, { type: 'host', value: '192.0.2.10', cmd_index: 2 }]),
    '/api/commands': () => mode === 'down' ? down() : Promise.resolve(CMDS) });
  e.ctx.__set(1, 'graph'); e.ctx.renderGraph(); await flush();
  e.graphs[0].onSelect({ id: 'host:192.0.2.10', label: '192.0.2.10', type: 'host', cmd_index: 2 }); await flush();
  assert.match(e.detail().textContent, /Could not load the command/);
  mode = 'ok'; clickHTML(e.detail(), 'data-xretry'); await flush();
  assert.match(e.detail().innerHTML, /nmap portal\.example\.com/, 'Try again showed another command: ' + e.detail().innerHTML.slice(0, 300));
  assert.match(e.detail().innerHTML, /data-cmd="2" aria-pressed="true"/); assert.match(e.detail().innerHTML, /data-cmd="0" aria-pressed="false"/);
});

test('R12 full session record: a known gap stays visible after a failed part and its retry, is not counted twice, and starts again for a new render', async () => {
  const replies = [ok('abc', { 'X-Next-Offset': 6, 'X-Raw-Total': 12, 'X-Missing-Bytes': 3 }), http(500), never,
    ok('defghi', { 'X-Next-Offset': 12, 'X-Raw-Total': 12, 'X-Missing-Bytes': 0 })];
  let n = 0;
  const e = recordEnv({ ...EV, '/api/raw': () => { const r = replies[n++]; return r === never ? never() : Promise.resolve(r); } });
  const { btn, warn, pre } = await e.open();
  await btn.onclick(); assert.equal(pre.textContent, 'abc'); assert.match(warn.textContent, /Incomplete record — 3 B missing/);
  await btn.onclick(); assert.equal(pre.textContent, 'abc');
  assert.match(warn.textContent, /3 B missing.*Could not load this part.*code 500.*Nothing was added/, 'the known gap was hidden by the error: ' + warn.textContent);
  const p = btn.onclick(); await flush(); await e.c.advance(15000); await p;
  assert.match(warn.textContent, /3 B missing.*did not answer within 15 s/);
  await btn.onclick();
  assert.equal(pre.textContent, 'abcdefghi');
  assert.match(warn.textContent, /^Incomplete record — 3 B missing/, 'the gap was lost after recovery: "' + warn.textContent + '"');
  assert.doesNotMatch(warn.textContent, /Could not load|[^0-9]6 B/, 'failed or retried parts were counted');
  assert.equal(btn.disabled, true); assert.equal(btn.textContent, 'Current record loaded');
  // A new render (another session or a reload) has its own record and count.
  replies.push(ok('xyz', { 'X-Next-Offset': 3, 'X-Raw-Total': 3, 'X-Missing-Bytes': 0 }));
  const again = await e.open();
  await again.btn.onclick(); assert.equal(again.pre.textContent, 'xyz'); assert.equal(again.warn.textContent, '', 'a gap of the previous render leaked');
});

test('R13 full session record: gaps of several parts add up; a valid empty record and Unicode stay correct', async () => {
  const replies = [ok('', { 'X-Next-Offset': 0, 'X-Raw-Total': 0, 'X-Missing-Bytes': 0 })];
  let n = 0;
  const e = recordEnv({ ...EV, '/api/raw': () => Promise.resolve(replies[n++]) });
  let r = await e.open();
  await r.btn.onclick(); assert.equal(r.pre.textContent, ''); assert.equal(r.warn.textContent, ''); assert.equal(r.btn.textContent, 'Current record loaded');
  replies.push(ok('żółć ', { 'X-Next-Offset': 9, 'X-Raw-Total': 30, 'X-Missing-Bytes': 2 }), ok('日本語', { 'X-Next-Offset': 30, 'X-Raw-Total': 30, 'X-Missing-Bytes': 5 }));
  r = await e.open();
  await r.btn.onclick(); assert.match(r.warn.textContent, /— 2 B missing/);
  await r.btn.onclick(); assert.equal(r.pre.textContent, 'żółć 日本語'); assert.match(r.warn.textContent, /— 7 B missing/);
});

test('R14 graph: nodes or edges that are not usable (null, primitives, missing/duplicate/non-string ids, wrong field types) are reported with Try again, never drawn or called empty', async () => {
  const bad = [{ nodes: [null], edges: [] }, { nodes: [1] }, { nodes: ['host:a'] }, { nodes: [{}] }, { nodes: [{ id: '' }] }, { nodes: [{ id: 5 }] },
    { nodes: [{ id: 'a' }, { id: 'a' }] }, { nodes: [{ id: 'a', cmd_index: '0' }] }, { nodes: [{ id: 'a', details: [] }] }, { nodes: [{ id: 'a', label: {} }] },
    { nodes: [{ id: 'a' }], edges: [null] }, { nodes: [{ id: 'a' }], edges: [{ source: 1, target: 'a' }] }, { nodes: [{ id: 'a' }], edges: 'x' }, { nodes: {} }, [{ id: 'a' }]];
  for (const v of bad) {
    let mode = 'bad';
    const e = graphEnv({ ...G, '/api/graph': () => Promise.resolve(mode === 'bad' ? ok(v) : G['/api/graph']) });
    e.ctx.__set(1, 'graph'); e.ctx.renderGraph(); await flush();
    const what = JSON.stringify(v);
    assert.equal(e.graphs.length, 0, what + ' was drawn');
    assert.equal(e.label(), 'Relationship graph: could not be loaded', what + ': label ' + e.label());
    assert.match(e.detail().textContent, /Could not load the graph.*not valid session data/, what);
    assert.doesNotMatch(e.detail().textContent, /No entities/, what + ' described as empty');
    mode = 'ok'; clickHTML(e.detail(), 'data-gretry'); await flush();
    assert.equal(e.graphs.length, 1, what + ': Try again did not draw the valid graph');
  }
});

test('R15 graph: legitimate data stays valid (null optional fields, numeric label, edge to an absent element, no edges, empty graph); a renderer failure is reported', async () => {
  const fine = { nodes: [{ id: 'host:a', label: null, type: 'host', confidence: null, tool: null, cmd_index: null, offset: null, details: null }, { id: 'port:a:22', label: 22, type: 'port', cmd_index: 0, details: { host: 'a' } }],
    edges: [{ source: 'port:a:22', target: 'host:a', type: 'on' }, { source: 'url:x', target: 'host:a', type: 'on' }] };
  for (const v of [fine, { nodes: fine.nodes, edges: null }, { nodes: fine.nodes }]) {
    const e = graphEnv({ ...G, '/api/graph': ok(v) });
    e.ctx.__set(1, 'graph'); e.ctx.renderGraph(); await flush();
    assert.equal(e.graphs.length, 1, JSON.stringify(v) + ' not drawn'); assert.doesNotMatch(e.detail().textContent, /Could not load/);
  }
  { const e = graphEnv({ ...G, '/api/graph': ok({ nodes: [], edges: null }) }); e.ctx.__set(1, 'graph'); e.ctx.renderGraph(); await flush();
    assert.match(e.detail().textContent, /No entities/); assert.equal(e.label(), 'Relationship graph: no entities in this session'); }
  { const e = graphEnv({ ...G, '/api/graph': ok(fine) }); let calls = 0;
    const real = e.ctx.initGraph; e.ctx.initGraph = (...a) => { if (++calls === 1) throw new TypeError("Cannot read properties of undefined (reading 'x')"); return real(...a); };
    e.ctx.__set(1, 'graph'); e.ctx.renderGraph(); await flush();
    assert.equal(e.label(), 'Relationship graph: could not be loaded'); assert.match(e.detail().textContent, /Could not load the graph/);
    clickHTML(e.detail(), 'data-gretry'); await flush(); assert.equal(e.graphs.length, 1); assert.doesNotMatch(e.detail().textContent, /Could not load/); }
});

(async () => {
  let failCount = 0;
  for (const [n, f] of tests) {
    const u = unhandled.length;
    try { await Promise.race([f(), new Promise((_, rj) => setTimeout(() => rj(new Error('test did not finish (stuck)')), 4000))]);
      if (unhandled.length > u) throw new Error('unhandled rejection: ' + unhandled.slice(u).join('; '));
      console.log('PASS | ' + n); }
    catch (e) { failCount++; console.log('FAIL | ' + n + ' | ' + String(e && e.message || e).replace(/\s+/g, ' ').slice(0, 240)); }
  }
  console.log(failCount ? 'FAIL reads ' + failCount : 'PASS reads ' + tests.length);
  process.exit(failCount ? 1 : 0);
})();
