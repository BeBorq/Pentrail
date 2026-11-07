// Runs the real cleanup.js (served to the page) in node against REAL viewer
// servers (Go test cleanup_ui_test.go: two synthetic databases with the same
// session/command/category, the first one restarted between phases, and one
// whose /api/identity fails). localStorage is simulated by a Map persisted
// in a JSON file between phases (a browser keeps it across a restart).
// usage: node cleanup.test.cjs <phase 1|2> <storage.json> <token> <urlA> <urlB> <urlBad>
const fs = require('node:fs'), vm = require('node:vm'), path = require('node:path'), assert = require('node:assert/strict');
const [phase, storeFile, token, urlA, urlB, urlBad] = process.argv.slice(2);
const window = {};
vm.runInNewContext(fs.readFileSync(path.join(__dirname, 'cleanup.js'), 'utf8'), {window, AbortController, setTimeout, clearTimeout});
const C = window.pentrailCleanup;
const saved = fs.existsSync(storeFile) ? JSON.parse(fs.readFileSync(storeFile, 'utf8')) : {items: {}, meta: {}};
const map = new Map(Object.entries(saved.items));
const storage = {getItem: k => map.has(k) ? map.get(k) : null, setItem: (k, v) => map.set(k, String(v)), removeItem: k => map.delete(k)};
// the page's fetch: same-origin relative URLs; the token as the page's cookie would carry it
const fetchFor = base => (u, opt) => fetch(base + u + (u.includes('?') ? '&' : '?') + 't=' + token, opt);
const changes = async base => { const r = await fetchFor(base)('/api/changes?session=1'); assert.equal(r.status, 200); return r.json(); };
const pairs = items => items.map(i => i.cmd_index + ':' + i.category).join(',');
(async () => {
  const nsA = await C.namespace(fetchFor(urlA)), nsB = await C.namespace(fetchFor(urlB));
  assert.ok(nsA.ok && nsB.ok, JSON.stringify([nsA, nsB]));
  assert.match(nsA.ns, /^[0-9a-f]{32}$/); assert.notEqual(nsA.ns, nsB.ns);
  const itA = await changes(urlA), itB = await changes(urlB);
  assert.ok(itA.length >= 2); assert.equal(pairs(itA), pairs(itB)); // the same session/command/category in both
  const stA = C.state(storage, nsA, 1), stB = C.state(storage, nsB, 1);
  if (phase === '1') {
    // keys of the earlier version (session:index:category) exist in this browser
    for (const it of itA) storage.setItem(`pentrail:clean:1:${it.cmd_index}:${it.category}`, '1');
    assert.equal(itA.filter(stA.done).length, 0, 'legacy keys mark new evidence');
    assert.equal(itB.filter(stB.done).length, 0, 'legacy keys mark new evidence');
    assert.equal(stA.set(itA[0], true), true);
    assert.equal(stA.done(itA[0]), true);
    assert.equal(stB.done(itB[0]), false, 'database B inherited a tick of database A');
    assert.equal(stA.done(itA[1]), false);
    assert.match(C.headText(itA.length, 1, stA, nsA), /1 ticked/);
    // unknown database: no tick shown, none possible, said in plain words
    const bad = await C.namespace(fetchFor(urlBad));
    assert.equal(JSON.stringify(bad), JSON.stringify({ok: false, error: 'the viewer reported an error, code 500'})); // objects from the vm realm
    const stBad = C.state(storage, bad, 1);
    assert.equal(stBad.known, false); assert.equal(stBad.done(itA[0]), false); assert.equal(stBad.set(itA[0], true), false);
    const h = C.headText(itA.length, 0, stBad, bad);
    assert.match(h, /Tick state: unknown/); assert.match(h, /code 500/); assert.doesNotMatch(h, /HTTP|namespace|localStorage/); assert.doesNotMatch(h, /ticked\./);
    const slow = await C.namespace((u, opt) => new Promise((_, rej) => opt.signal.addEventListener('abort', () => rej(Object.assign(new Error('x'), {name: 'AbortError'})))), 30);
    assert.equal(JSON.stringify(slow), JSON.stringify({ok: false, error: 'the request timed out'}));
    assert.throws(() => C.key('', 1, itA[0]));
    saved.meta.nsA = nsA.ns; saved.meta.nsB = nsB.ns;
  } else {
    // database A after a restart of its viewer (new server, store reopened)
    assert.equal(nsA.ns, saved.meta.nsA, 'the same database got another namespace after restart');
    assert.equal(nsB.ns, saved.meta.nsB);
    assert.equal(stA.done(itA[0]), true, 'tick lost after restart');
    assert.equal(stA.done(itA[1]), false);
    assert.equal(stB.done(itB[0]), false);
  }
  // nothing but namespaced keys (and the legacy ones put there above);
  // no URL, token, path or key material in localStorage
  for (const k of map.keys()) {
    assert.match(k, /^pentrail:clean:(v2:[0-9a-f]{32}:)?\d+:\d+:[a-z]+$/, k);
    for (const bad of [token, urlA, '127.0.0.1', 'synthetic', '\\', '/']) assert.ok(!k.includes(bad), k + ' contains ' + bad);
  }
  saved.items = Object.fromEntries(map);
  fs.writeFileSync(storeFile, JSON.stringify(saved));
  console.log('PASS cleanup phase ' + phase + ': A=' + nsA.ns.slice(0, 6) + '… B=' + nsB.ns.slice(0, 6) + '…, keys ' + map.size);
})().catch(e => { console.error(e); process.exit(1); });
