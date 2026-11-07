// 04BL: read failures in the REAL index.html code (the session list and the
// timeline renderer, extracted from the page) with a minimal DOM, a
// controllable fetch and a controllable clock. Every mandatory read must
// leave "loading…" on a rejected fetch, an HTTP error, invalid data, or a
// fetch/body that never settles (bounded), show an accurate message and a
// Try again that only acts while its render is current.
// Run: node loading.regression.test.cjs [path/to/index.html]  (negative control: pass an older page)
'use strict';
const fs = require('node:fs'), vm = require('node:vm'), path = require('node:path'), assert = require('node:assert/strict');
const page = fs.readFileSync(process.argv[2] || path.join(__dirname, 'index.html'), 'utf8');
const cut = (from, to) => { const i = page.indexOf(from), j = page.indexOf(to, i); if (i < 0 || j < 0) throw new Error('region not found: ' + from); return page.slice(i, j); };
const startR1 = page.includes('// ---- reads with a bound') ? '// ---- reads with a bound' : 'let sessionInfo=new Map();';
const code = cut(startR1, '\nfunction renderActive(') + '\n' + cut('let timelineRequest=0;', '\n// ---- graph ----') +
  '\nglobalThis.__T={set(s,v){activeSession=s;if(v)activeView=v;},sessions:()=>sessionInfo};';

const unhandled = [];
process.on('unhandledRejection', e => unhandled.push(String(e && e.message || e)));

// ---- a minimal DOM ----
class El {
  constructor(tag) { this.tagName = tag; this.children = []; this._html = ''; this._text = ''; this.dataset = {}; this.style = {}; this.attrs = {}; this.sel = new Map(); this.cls = new Set();
    const self = this; this.classList = { toggle(c, on) { const v = on === undefined ? !self.cls.has(c) : on; v ? self.cls.add(c) : self.cls.delete(c); return v; }, add(c) { self.cls.add(c); }, remove(c) { self.cls.delete(c); }, contains(c) { return self.cls.has(c); } }; }
  set className(v) { this.cls = new Set(String(v).split(/\s+/).filter(Boolean)); } get className() { return [...this.cls].join(' '); }
  set innerHTML(v) { this._html = String(v); this._text = ''; this.children = []; this.sel = new Map(); } get innerHTML() { return this._html; }
  set textContent(v) { this._text = String(v); this._html = ''; this.children = []; } get textContent() { return this._text + this._html.replace(/<[^>]*>/g, '') + this.children.map(c => c.textContent).join(''); }
  appendChild(c) { this.children.push(c); return c; }
  append(...cs) { for (const c of cs) this.appendChild(typeof c === 'string' ? Object.assign(new El('#text'), { _text: c }) : c); }
  insertBefore(c) { this.children.push(c); return c; }
  querySelector(s) { if (!this.sel.has(s)) this.sel.set(s, new El('stub')); return this.sel.get(s); }
  querySelectorAll() { return []; }
  setAttribute(k, v) { this.attrs[k] = v; } getAttribute(k) { return this.attrs[k]; }
  remove() {} scrollIntoView() {}
  all() { return [this, ...this.children.flatMap(c => c.all())]; }
}

// ---- a controllable clock ----
function clock() {
  let now = 0, id = 0; const ts = new Map();
  return { setTimeout(fn, ms) { ts.set(++id, { fn, at: now + (ms || 0) }); return id; }, clearTimeout(i) { ts.delete(i); },
    async advance(ms) { const end = now + ms; for (;;) { const due = [...ts].filter(([, t]) => t.at <= end).sort((a, b) => a[1].at - b[1].at)[0]; if (!due) break; now = due[1].at; ts.delete(due[0]); due[1].fn(); await flush(); } now = end; await flush(); },
    pending: () => ts.size };
}
const flush = async () => { for (let i = 0; i < 30; i++) await new Promise(r => setImmediate(r)); };

// ---- responses ----
const SECRET = 'BODY-SECRET-7f3a';
const hdr = (h = {}) => ({ get: k => (k in h ? h[k] : null) });
const json = (v, status = 200) => ({ ok: status >= 200 && status < 300, status, headers: hdr(), json: async () => JSON.parse(typeof v === 'string' ? v : JSON.stringify(v)), text: async () => (typeof v === 'string' ? v : JSON.stringify(v)) });
const errResp = status => ({ ok: false, status, headers: hdr(), json: async () => ({ error: SECRET }), text: async () => SECRET + ' /home/user/.pentrail/db token=abcdef' });
const never = () => new Promise(() => {});
const hangBody = () => ({ ok: true, status: 200, headers: hdr(), json: never, text: never });

function setup(routes, opt = {}) {
  const c = clock(), doc = { els: {}, getElementById(id) { return this.els[id] || (this.els[id] = new El('div')); }, createElement: t => new El(t) };
  const calls = [];
  const fetch = (url, init) => { calls.push({ url, signal: init && init.signal }); const key = Object.keys(routes).filter(k => url.startsWith(k)).sort((a, b) => b.length - a.length)[0]; if (!key) return Promise.reject(new TypeError('Failed to fetch')); const r = routes[key]; return typeof r === 'function' ? r(url, init) : Promise.resolve(r); };
  const notes = opt.notes || (() => Promise.resolve({ ok: true, notes: [] }));
  const ctx = {
    document: doc, window: {}, fetch, console, AbortController, setTimeout: c.setTimeout, clearTimeout: c.clearTimeout, Promise, Array, JSON, Math, Number, String, Map, Set, Object, TypeError,
    esc: s => String(s == null ? '' : s).replace(/[&<>"]/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[ch]),
    fmtTime: () => 't', fmtDur: () => 'd', fmtBytes: n => n + ' B', strip: s => s, parseDet: () => ({}), detailSuffix: () => '', sevClass: () => '',
    TYPE_ORDER: [], TYPE_LABEL: {}, pendingCmd: null, renderActive: () => {}, showInGraph: () => {},
    anchorNotes: () => [], noteLinksHTML: () => '', noteLinkClick: () => false,
    loadNotes: sid => notes(sid), pentrailXref: { nodeIds: () => ({ ids: [] }) },
    pentrailArtifacts: { load: async () => (opt.arts || { ok: true, items: [] }), render: (d, r) => { if (r.ok) return null; const e = new El('details'); e.textContent = 'Tool output files: state unknown — could not read (' + r.error + ')'; return e; } },
  };
  vm.createContext(ctx);
  vm.runInContext(code, ctx);
  return { ctx, c, doc, calls, T: ctx.__T, main: () => doc.getElementById('timeline'), list: () => doc.getElementById('sessions') };
}
const EV = { '/api/commands': json([]), '/api/entities': json([]), '/api/capture-events': json([]) };
const box = el => el.all().find(e => e.cls.has('readerr'));
const retryBtn = el => box(el).children.find(e => e.tagName === 'button');
const text = el => el.textContent;
const okTimeline = el => /No split into commands/.test(text(el)) && !box(el);
async function timeline(env, sid = 1) { env.T.set(sid, 'timeline'); env.ctx.renderTimeline(); await flush(); } // not awaited: a stuck render must not stall the test

const tests = [];
const test = (n, f) => tests.push([n, f]);

test('L1 rejected fetch (server stopped): error with Try again, not loading forever', async () => {
  const env = setup({ ...EV, '/api/entities': () => Promise.reject(new TypeError('Failed to fetch')) });
  await timeline(env);
  assert.ok(box(env.main()), 'no error box; page shows: ' + text(env.main()).slice(0, 80));
  assert.doesNotMatch(text(env.main()), /loading…/);
  assert.match(text(env.main()), /No connection to the Pentrail viewer.*pentrail open/);
  assert.ok(retryBtn(env.main()));
});

test('L2 HTTP 401/403/404/500: accurate message; no token, path or response body shown', async () => {
  const want = { 401: /\(401\).*link of this page is no longer valid.*printed by pentrail open/, 403: /\(403\)/, 404: /\(404\).*session may not be/, 500: /internal error \(code 500\)/ };
  for (const s of [401, 403, 404, 500]) {
    const env = setup({ ...EV, '/api/commands': errResp(s) });
    await timeline(env);
    const t = text(env.main());
    assert.ok(box(env.main()), s + ': no error box'); assert.match(t, want[s]);
    assert.ok(!t.includes(SECRET) && !t.includes('token=') && !t.includes('/api/') && !t.includes('.pentrail'), s + ': leaked: ' + t);
  }
});

test('L3 invalid JSON and wrong schema are errors, never an empty timeline', async () => {
  for (const bad of ['{not json', { commands: [] }, [1, 2], null]) {
    const env = setup({ ...EV, '/api/capture-events': json(bad) });
    await timeline(env);
    assert.ok(box(env.main()), 'accepted ' + JSON.stringify(bad)); assert.match(text(env.main()), /not valid session data/);
    assert.doesNotMatch(text(env.main()), /No split into commands/);
  }
});

test('L4 a fetch that never settles (ignores abort) times out with a message; the request is aborted', async () => {
  const env = setup({ ...EV, '/api/commands': never });
  await timeline(env);
  assert.match(text(env.main()), /loading…/);
  await env.c.advance(15000);
  assert.ok(box(env.main()), 'still loading after the bound'); assert.match(text(env.main()), /did not answer within 15 s/);
  assert.equal(env.calls.find(c => c.url.startsWith('/api/commands')).signal.aborted, true);
});

test('L5 a body that never arrives times out too', async () => {
  const env = setup({ ...EV, '/api/entities': hangBody() });
  await timeline(env); await env.c.advance(15000);
  assert.ok(box(env.main())); assert.match(text(env.main()), /did not answer/);
});

test('L6 Try again recovers once the viewer answers', async () => {
  let fail = true;
  const env = setup({ ...EV, '/api/commands': () => fail ? Promise.reject(new TypeError('Failed to fetch')) : Promise.resolve(json([])) });
  await timeline(env);
  assert.ok(box(env.main())); fail = false;
  retryBtn(env.main()).onclick(); await flush();
  assert.ok(okTimeline(env.main()), 'retry did not render: ' + text(env.main()).slice(0, 100));
  assert.equal(env.c.pending(), 0, 'timers left behind');
});

test('L7 a late failure of session A never paints over session B', async () => {
  let rejectA;
  const env = setup({ ...EV, '/api/commands?session=1': () => new Promise((_, rj) => { rejectA = rj; }), '/api/commands?session=2': json([]) });
  await timeline(env, 1);
  await timeline(env, 2);
  assert.ok(okTimeline(env.main()));
  rejectA(new TypeError('Failed to fetch')); await flush();
  assert.ok(okTimeline(env.main()), 'A error painted over B');
});

test('L8 a late failure after a view change paints nothing', async () => {
  let rejectA;
  const env = setup({ ...EV, '/api/commands': () => new Promise((_, rj) => { rejectA = rj; }) });
  await timeline(env, 1);
  env.T.set(1, 'graph');
  rejectA(new TypeError('Failed to fetch')); await flush();
  assert.ok(!box(env.main()), 'error painted into the hidden timeline');
});

test('L9 a retired Try again (old session) does nothing', async () => {
  const env = setup({ ...EV, '/api/commands?session=1': () => Promise.reject(new TypeError('Failed to fetch')), '/api/commands?session=2': json([]) });
  await timeline(env, 1);
  const oldRetry = retryBtn(env.main());
  await timeline(env, 2);
  const before = env.calls.length;
  oldRetry.onclick(); await flush();
  assert.equal(env.calls.length, before, 'the retired retry fetched again');
  assert.ok(okTimeline(env.main()));
});

test('L10 optional notes that hang are bounded: evidence shows, notes say "could not be read" with Try again', async () => {
  const env = setup(EV, { notes: never, arts: { ok: false, error: 'connection error' } });
  await timeline(env);
  await env.c.advance(10000);
  const t = text(env.main());
  assert.ok(/No split into commands/.test(t), 'evidence held back by notes: ' + t.slice(0, 80));
  assert.match(t, /Operator notes: could not be read \(the request timed out\)\. This does not mean there are none/);
  assert.match(t, /Tool output files: state unknown/);
});

test('L11 session list: rejected, 401, invalid and hanging reads fail visibly; Try again recovers', async () => {
  for (const [r, re] of [[() => Promise.reject(new TypeError('Failed to fetch')), /No connection/], [errResp(401), /\(401\)/], [json({}), /not valid/], [never, /did not answer/]]) {
    const env = setup({ '/api/sessions': r });
    env.ctx.loadSessions(); await flush(); await env.c.advance(15000);
    assert.ok(box(env.list()), 'no error for the session list'); assert.match(text(env.list()), re);
    assert.doesNotMatch(text(env.list()), /loading…|No sessions/);
  }
  let ok = false;
  const env = setup({ '/api/sessions': () => ok ? Promise.resolve(json([{ id: 4, shell: 'bash', started_ms: 1, commands: 2, raw_bytes: 3 }])) : Promise.reject(new TypeError('Failed to fetch')) });
  env.ctx.loadSessions(); await flush();
  ok = true; retryBtn(env.list()).onclick(); await flush();
  assert.ok(!box(env.list())); assert.equal(env.list().children.length, 1); assert.equal(env.T.sessions().size, 1);
});

test('L12 a retired session-list retry does nothing', async () => {
  let n = 0;
  const env = setup({ '/api/sessions': () => (++n === 1 ? Promise.reject(new TypeError('Failed to fetch')) : Promise.resolve(json([]))) });
  env.ctx.loadSessions(); await flush();
  const old = retryBtn(env.list());
  env.ctx.loadSessions(); await flush();
  const before = env.calls.length; old.onclick(); await flush();
  assert.equal(env.calls.length, before);
});

test('L13 a command output that cannot be read says so and loads on the next open', async () => {
  let fail = true;
  const cmd = { index: 0, command: 'echo hi', started_ms: 1, ended_ms: 2, out_start_off: 0, out_end_off: 5, complete: true, exit_code: 0, cwd: '' };
  const env = setup({ ...EV, '/api/commands': json([cmd]), '/api/output': () => fail ? Promise.resolve(errResp(401)) : Promise.resolve({ ...json('hello'), headers: hdr({ 'X-Missing-Bytes': '0' }) }) });
  await timeline(env);
  const wrap = env.main().children.find(e => e.cls.has('cmd'));
  assert.ok(wrap, 'no command row');
  const row = wrap.querySelector('.row'), warn = wrap.querySelector('.gapwarn'), pre = wrap.querySelector('.body');
  await row.onclick(); await flush();
  assert.match(warn.textContent, /Could not load this output.*\(401\)/); assert.ok(!pre.textContent.includes(SECRET), 'error body shown as output');
  fail = false; await row.onclick(); await row.onclick(); await flush(); // close, open
  assert.equal(pre.textContent, 'hello'); assert.equal(warn.textContent, '');
});

(async () => {
  let failCount = 0;
  for (const [n, f] of tests) {
    const u = unhandled.length;
    try { await Promise.race([f(), new Promise((_, rj) => setTimeout(() => rj(new Error('test did not finish (stuck)')), 3000))]);
      if (unhandled.length > u) throw new Error('unhandled rejection: ' + unhandled.slice(u).join('; '));
      console.log('PASS | ' + n); }
    catch (e) { failCount++; console.log('FAIL | ' + n + ' | ' + String(e && e.message || e).replace(/\s+/g, ' ').slice(0, 220)); }
  }
  console.log(failCount ? 'FAIL loading ' + failCount : 'PASS loading ' + tests.length);
  process.exit(failCount ? 1 : 0);
})();
