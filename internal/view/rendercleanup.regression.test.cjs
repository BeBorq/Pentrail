// Runs the REAL renderCleanup of index.html (the part from "const CLEAN_LABEL"
// to "// ---- tabs ----", extracted by cleanup_render_test.go) with the real
// cleanup.js, a small DOM stand-in and a fetch whose replies the test releases
// one by one. Synthetic data only.
// usage: node rendercleanup.regression.test.cjs <extracted renderer file>
const fs = require('node:fs'), vm = require('node:vm'), path = require('node:path'), assert = require('node:assert/strict');
const file = process.argv[2];
const NS_A = 'a'.repeat(32);
const unhandled = [];
process.on('unhandledRejection', e => unhandled.push(String(e && e.message || e)));

function dom() {
  const make = tag => {
    const e = {
      tag, children: [], className: '', dataset: {}, _text: '', _html: '', _input: null, type: '', onclick: null,
      classList: { s: new Set(), add(c) { this.s.add(c); }, remove(c) { this.s.delete(c); }, contains(c) { return this.s.has(c); }, toggle(c, v) { (v === undefined ? !this.s.has(c) : v) ? this.s.add(c) : this.s.delete(c); } },
      appendChild(c) { this.children.push(c); return c; },
      attrs: {}, setAttribute(k, v) { this.attrs[k] = String(v); }, // 04BM: the error head carries role=alert
      get textContent() { return this._text + this.children.map(c => c.textContent).join(''); },
      set textContent(v) { this._text = String(v); this.children = []; this._html = ''; },
      get innerHTML() { return this._html; },
      set innerHTML(v) { this._html = String(v); this._text = ''; this.children = []; this._input = null; },
      querySelector(sel) {
        if (sel !== 'input') return null;
        if (!this._input) { const m = /<input type="checkbox" ([^>]*)>/.exec(this._html); if (!m) return null; this._input = { checked: /\bchecked\b/.test(m[1]), disabled: /\bdisabled\b/.test(m[1]), onchange: null }; }
        return this._input;
      },
    };
    return e;
  };
  const main = make('div');
  return { main, document: { getElementById: id => { assert.equal(id, 'cleanpane'); return main; }, createElement: make, createTextNode: s => ({ textContent: String(s), children: [] }) } };
}

// What the user sees in the Cleanup pane.
function view(main) {
  const rows = main.children.filter(c => /^clitem/.test(c.className));
  const head = main.children.find(c => c.className === 'clhead');
  return {
    loading: /loading…/.test(main.innerHTML) && !main.children.length,
    head: head ? head.textContent : '',
    rows: rows.map(r => (/<span class="cldesc">([^<]*)<\/span>/.exec(r.innerHTML) || [])[1]),
    checked: rows.map(r => r.querySelector('input').checked),
    disabled: rows.map(r => r.querySelector('input').disabled),
    retry: head ? head.children.find(c => c.textContent === 'Try again') : undefined,
  };
}

function setup() {
  const { main, document } = dom();
  const map = new Map(); let failWrites = false;
  const storage = { getItem: k => map.has(k) ? map.get(k) : null, setItem: (k, v) => { if (failWrites) throw new Error('quota'); map.set(k, String(v)); }, removeItem: k => map.delete(k) };
  const pending = [];
  const ctxt = {
    document, console, setTimeout, clearTimeout, AbortController,
    esc: s => String(s == null ? '' : s).replace(/[&<>"]/g, ''), fmtTime: ms => 'T' + ms,
    activeSession: 1, activeView: 'cleanup',
    fetch: (url, opt) => new Promise((res, rej) => pending.push({ url, res, rej, used: false })),
  };
  ctxt.window = ctxt; ctxt.localStorage = storage;
  // 04BM: the renderer reads through the page's bounded read helpers; load the real ones from index.html.
  if (!ctxt.setTimeout) Object.assign(ctxt, {setTimeout, clearTimeout});
  if (!ctxt.AbortController) ctxt.AbortController = AbortController;
  vm.createContext(ctxt);
  vm.runInContext(fs.readFileSync(path.join(__dirname, 'cleanup.js'), 'utf8'), ctxt);
  {const page = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8'), i = page.indexOf('// ---- reads with a bound'), j = page.indexOf('let sessionInfo=new Map();');
   if (i >= 0 && j > i) vm.runInContext(page.slice(i, j), ctxt);}
  vm.runInContext(fs.readFileSync(file, 'utf8') + '\nthis.renderCleanup=renderCleanup;', ctxt);
  const take = url => { const p = pending.find(p => p.url === url && !p.used); assert.ok(p, 'no pending request ' + url + ' in ' + pending.filter(p => !p.used).map(p => p.url).join(', ')); p.used = true; return p; };
  const json = (p, body) => p.res({ ok: true, status: 200, json: async () => body });
  return { ctxt, main, map, pending, take, json, failWrites: v => { failWrites = v; } };
}
const settle = async () => { for (let i = 0; i < 8; i++) await new Promise(r => setImmediate(r)); };
const items = tag => [
  { cmd_index: 1, category: 'file', description: tag + ' write to a file', command: 'echo x > /tmp/' + tag, cwd: '/w', offset: 1, detected_ms: 1 },
  { cmd_index: 2, category: 'account', description: tag + ' account operation', command: 'net user ' + tag, cwd: '/w', offset: 2, detected_ms: 2 }];

const results = [];
async function check(name, fn) {
  unhandled.length = 0;
  try { await fn(); await settle(); assert.deepEqual(unhandled, [], 'unhandled rejection: ' + unhandled.join('; ')); results.push(['PASS', name]); }
  catch (e) { results.push(['FAIL', name, String(e && e.message || e).split('\n')[0].slice(0, 170)]); }
}

// Render session B (2) completely, with the given checklist.
async function showB(h, list) {
  h.ctxt.activeSession = 2; h.ctxt.renderCleanup();
  h.json(h.take('/api/changes?session=2'), list);
  // a renderer that does not share the identity request asks again: answer it too
  for (const p of h.pending.filter(p => p.url === '/api/identity' && !p.used)) { p.used = true; h.json(p, { view_namespace: NS_A }); }
  await settle();
  const v = view(h.main); assert.ok(!v.loading, 'B not rendered');
  return JSON.stringify(v, (k, x) => k === 'retry' ? undefined : x);
}
const snap = h => JSON.stringify(view(h.main), (k, x) => k === 'retry' ? undefined : x);

(async () => {
  await check('K1 a delayed successful checklist of session A, resolved after B shows its (empty) checklist, changes nothing', async () => {
    const h = setup();
    h.ctxt.renderCleanup();
    const a = h.take('/api/changes?session=1');
    h.json(h.take('/api/identity'), { view_namespace: NS_A });
    const b = await showB(h, []);
    assert.match(view(h.main).head, /No target state changes were detected/);
    h.json(a, items('SESSION-A')); await settle();
    assert.equal(snap(h), b, 'session A checklist replaced session B');
    assert.equal(h.pending.filter(p => p.url === '/api/identity').length, 1, 'the identity was requested twice');
  });

  for (const [kind, fail] of [
    ['HTTP 500', p => p.res({ ok: false, status: 500, json: async () => ({}) })],
    ['network error', p => p.rej(new TypeError('Failed to fetch'))],
    ['invalid JSON', p => p.res({ ok: true, status: 200, json: async () => { throw new SyntaxError('Unexpected token'); } })],
  ]) {
    await check(`K2 a delayed ${kind} of session A after B is shown neither replaces nor appends to B's checklist`, async () => {
      for (const bList of [[], items('SESSION-B')]) {
        const h = setup();
        h.ctxt.renderCleanup();
        const a = h.take('/api/changes?session=1');
        h.json(h.take('/api/identity'), { view_namespace: NS_A });
        const b = await showB(h, bList);
        fail(a); await settle();
        assert.equal(snap(h), b, `${kind} of A changed B (B ${bList.length ? 'with' : 'without'} changes)`);
      }
    });
  }

  await check('K3 a slow response.json() of session A, resolved after B is shown, changes nothing', async () => {
    const h = setup();
    h.ctxt.renderCleanup();
    let finish;
    h.take('/api/changes?session=1').res({ ok: true, status: 200, json: () => new Promise(r => { finish = r; }) });
    h.json(h.take('/api/identity'), { view_namespace: NS_A }); await settle();
    const b = await showB(h, items('SESSION-B'));
    finish(items('SESSION-A')); await settle();
    assert.equal(snap(h), b);
  });

  await check('K4 the current session\'s own errors are still reported in plain words', async () => {
    for (const [fail, text] of [
      // 04BM: the shared read messages (index.html readMessage), plus a Try again button
      [p => p.res({ ok: false, status: 500, json: async () => ({}) }), /Could not read the checklist\. The viewer reported an internal error \(code 500\).*This does not mean there were no changes/],
      [p => p.rej(new TypeError('x')), /Could not read the checklist\. No connection to the Pentrail viewer.*This does not mean there were no changes/],
      [p => p.res({ ok: true, status: 200, json: async () => { throw new SyntaxError('x'); } }), /not valid session data/]]) {
      const h = setup(); h.ctxt.renderCleanup();
      fail(h.take('/api/changes?session=1')); h.json(h.take('/api/identity'), { view_namespace: NS_A }); await settle();
      assert.match(view(h.main).head, text, JSON.stringify(view(h.main).head));
    }
  });

  await check('K5 leaving Cleanup before the reply: the reply draws nothing; after returning only the new render draws', async () => {
    const h = setup();
    h.ctxt.renderCleanup();
    const a1 = h.take('/api/changes?session=1');
    h.ctxt.activeView = 'timeline';
    h.json(h.take('/api/identity'), { view_namespace: NS_A });
    h.json(a1, items('OLD')); await settle();
    assert.equal(view(h.main).loading, true, 'drawn while the Cleanup view was not shown');
    h.ctxt.activeView = 'cleanup'; h.ctxt.renderCleanup();
    const a2 = h.take('/api/changes?session=1');
    h.json(a2, items('NEW')); await settle();
    assert.deepEqual(view(h.main).rows, ['NEW write to a file', 'NEW account operation']);
  });

  await check('K6 A -> B -> A: replies of the first A render and of B are ignored after A returns', async () => {
    const h = setup();
    h.ctxt.renderCleanup(); const a1 = h.take('/api/changes?session=1');
    h.json(h.take('/api/identity'), { view_namespace: NS_A });
    h.ctxt.activeSession = 2; h.ctxt.renderCleanup(); const b = h.take('/api/changes?session=2');
    h.ctxt.activeSession = 1; h.ctxt.renderCleanup(); const a3 = h.take('/api/changes?session=1');
    h.json(a3, items('CURRENT')); await settle();
    const now = snap(h);
    h.json(a1, items('FIRST')); h.json(b, items('B')); await settle();
    assert.equal(snap(h), now);
    assert.deepEqual(view(h.main).rows, ['CURRENT write to a file', 'CURRENT account operation']);
  });

  await check('K7 a checkbox of a retired render writes no tick, under any session or database; current ticks work and persist per session', async () => {
    const h = setup();
    h.ctxt.renderCleanup(); h.json(h.take('/api/changes?session=1'), items('A')); h.json(h.take('/api/identity'), { view_namespace: NS_A }); await settle();
    const old = view(h.main);
    const oldBox = h.main.children.filter(c => /^clitem/.test(c.className))[0].querySelector('input');
    // a newer render (session B) starts; the old checkbox still fires
    h.ctxt.activeSession = 2; h.ctxt.renderCleanup();
    oldBox.checked = true; oldBox.onchange();
    assert.equal(h.map.size, 0, 'a retired render wrote a tick: ' + [...h.map.keys()].join(','));
    assert.equal(oldBox.checked, false, 'the retired checkbox kept its new state');
    h.json(h.take('/api/changes?session=2'), items('B'));
    for (const p of h.pending.filter(p => p.url === '/api/identity' && !p.used)) { p.used = true; h.json(p, { view_namespace: NS_A }); }
    await settle();
    // a tick in B, then back to A: A has none, B keeps its own
    const boxB = h.main.children.filter(c => /^clitem/.test(c.className))[0].querySelector('input');
    boxB.checked = true; boxB.onchange();
    assert.deepEqual([...h.map.keys()], [`pentrail:clean:v2:${NS_A}:2:1:file`]);
    assert.match(view(h.main).head, /1 ticked/);
    h.ctxt.activeSession = 1; h.ctxt.renderCleanup(); h.json(h.take('/api/changes?session=1'), items('A')); await settle();
    assert.deepEqual(view(h.main).checked, [false, false]);
    h.ctxt.activeSession = 2; h.ctxt.renderCleanup(); h.json(h.take('/api/changes?session=2'), items('B')); await settle();
    assert.deepEqual(view(h.main).checked, [true, false], 'tick of B lost');
    assert.ok(old.rows.length === 2);
  });

  await check('K8 unknown identity: ticks hidden and locked, "Try again" asks again; a retired "Try again" does nothing', async () => {
    const h = setup();
    h.ctxt.renderCleanup(); h.json(h.take('/api/changes?session=1'), items('A'));
    h.take('/api/identity').res({ ok: false, status: 500, json: async () => ({}) }); await settle();
    let v = view(h.main);
    assert.match(v.head, /Tick state: unknown — could not determine which evidence database this checklist belongs to \(the viewer reported an error, code 500\)/);
    assert.deepEqual(v.disabled, [true, true]);
    const oldRetry = v.retry; assert.ok(oldRetry, 'no Try again button');
    // a newer render for B starts; the old "Try again" must not start another render
    h.ctxt.activeSession = 2; h.ctxt.renderCleanup();
    const before = h.pending.length;
    oldRetry.onclick();
    assert.equal(h.pending.length, before, 'a retired Try again started a request');
    // B's render retries the identity itself (the failure was not kept)
    h.json(h.take('/api/changes?session=2'), items('B')); h.json(h.take('/api/identity'), { view_namespace: NS_A }); await settle();
    v = view(h.main); assert.deepEqual(v.disabled, [false, false]); assert.match(v.head, /0 ticked/);
    // the current "Try again" (after a later failure) still works: none needed now, the namespace is known
    h.ctxt.renderCleanup(); h.json(h.take('/api/changes?session=2'), items('B')); await settle();
    assert.equal(h.pending.filter(p => p.url === '/api/identity').length, 2, 'a known namespace was requested again');
  });

  await check('K9 a current "Try again" re-renders and retries the identity; storage failure is reported, the tick reverted', async () => {
    const h = setup();
    h.ctxt.renderCleanup(); h.json(h.take('/api/changes?session=1'), items('A'));
    h.take('/api/identity').rej(new TypeError('x')); await settle();
    assert.match(view(h.main).head, /\(connection error\)/);
    view(h.main).retry.onclick();
    h.json(h.take('/api/changes?session=1'), items('A')); h.json(h.take('/api/identity'), { view_namespace: NS_A }); await settle();
    assert.match(view(h.main).head, /0 ticked/);
    h.failWrites(true);
    const box = h.main.children.filter(c => /^clitem/.test(c.className))[0].querySelector('input');
    box.checked = true; box.onchange();
    assert.equal(box.checked, false); assert.match(view(h.main).head, /Could not save the tick in this browser \(browser storage unavailable\)/);
  });

  for (const r of results) console.log(r.join(' | '));
  if (results.some(r => r[0] !== 'PASS')) process.exitCode = 1;
})();
