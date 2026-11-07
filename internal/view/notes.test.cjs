// Tests of notes.js (the real module, loaded into a VM): autosave with
// debounce, one request per draft at a time, slow/out-of-order/failed saves,
// revision conflicts, archive/restore, unsaved-close warning and the API
// client's headers. Run: node notes.test.cjs  (notes_ui_test.go runs it).
'use strict';
const fs = require('node:fs'), vm = require('node:vm'), path = require('node:path'), assert = require('node:assert/strict');

function load() {
  const ctx = { console, setTimeout, clearTimeout, AbortController }; vm.createContext(ctx);
  // NOTES_JS: run these tests against another copy (negative control of 04BJ).
  vm.runInContext(fs.readFileSync(process.env.NOTES_JS || path.join(__dirname, 'notes.js'), 'utf8'), ctx);
  return ctx.pentrailNotes;
}
const N = load();

// Manual timers: run() fires due timers in order.
function clock() {
  let now = 0, id = 0; const ts = new Map();
  return {
    setTimeout(fn, ms) { ts.set(++id, { fn, at: now + ms }); return id; },
    clearTimeout(i) { ts.delete(i); },
    advance(ms) { now += ms; for (const [i, t] of [...ts].sort((a, b) => a[1].at - b[1].at)) if (t.at <= now) { ts.delete(i); t.fn(); } },
    count: () => ts.size,
  };
}
// A fake API whose replies the test releases one by one.
function fakeAPI() {
  const calls = [];
  const call = (kind, args) => new Promise(res => calls.push({ kind, args, res }));
  return {
    calls,
    create: (s, a, t, b) => call('create', { s, a, t, b }),
    update: (d, t, b) => call('update', { id: d.id, rev: d.revision, t, b }),
    archive: (d, archived) => call('archive', { id: d.id, rev: d.revision, archived }),
  };
}
const note = (o) => Object.assign({ id: 'a'.repeat(32), session_id: 1, anchor_kind: '', anchor_label: 'session', title: '', body: '', masked_bytes: 0, created_ms: 1, updated_ms: 2, revision: 1, archived: false }, o);
const tick = () => new Promise(r => setImmediate(r));
async function settle() { for (let i = 0; i < 6; i++) await tick(); }

const tests = [];
const test = (name, fn) => tests.push([name, fn]);

test('N1 debounce: several quick edits produce one save, only after the pause', async () => {
  const c = clock(), api = fakeAPI(), D = N.drafts({ api, setTimeout: c.setTimeout, clearTimeout: c.clearTimeout });
  const d = D.create(1, { kind: '' }, 'session');
  D.edit(d.key, { title: 'a' }); c.advance(300); D.edit(d.key, { title: 'ab' }); c.advance(300); D.edit(d.key, { body: 'x' });
  assert.equal(d.state, 'unsaved'); await settle(); assert.equal(api.calls.length, 0, 'saved before the pause');
  c.advance(N.DEBOUNCE_MS); await settle();
  assert.equal(api.calls.length, 1); assert.equal(api.calls[0].kind, 'create'); assert.equal(api.calls[0].args.t, 'ab'); assert.equal(d.state, 'saving');
  assert.notEqual(N.statusText(d).slice(0, 5), 'Saved');
  api.calls[0].res({ ok: true, note: note({ title: 'ab', body: 'x' }) }); await settle();
  assert.equal(d.state, 'saved'); assert.equal(d.id, 'a'.repeat(32)); assert.equal(d.revision, 1);
});

test('N2 edits during a slow save wait for it; the next save is based on the revision it returned', async () => {
  const c = clock(), api = fakeAPI(), D = N.drafts({ api, setTimeout: c.setTimeout, clearTimeout: c.clearTimeout });
  const d = D.sync(note({ title: 't', revision: 4 }));
  D.edit(d.key, { body: 'one' }); c.advance(N.DEBOUNCE_MS); await settle();
  assert.equal(api.calls.length, 1); assert.equal(api.calls[0].args.rev, 4);
  D.edit(d.key, { body: 'one two' }); c.advance(N.DEBOUNCE_MS); D.flush(d.key); await settle();
  assert.equal(api.calls.length, 1, 'a second request was sent while the first was in flight');
  api.calls[0].res({ ok: true, note: note({ title: 't', body: 'one', revision: 5 }) }); await settle();
  assert.equal(d.body, 'one two', 'the newer draft was overwritten by the older reply');
  // The save queued meanwhile goes out only now, based on revision 5.
  assert.equal(api.calls.length, 2); assert.equal(api.calls[1].args.rev, 5); assert.equal(d.state, 'saving');
  c.advance(N.DEBOUNCE_MS); await settle(); assert.equal(api.calls.length, 2, 'a duplicate save was sent'); assert.equal(api.calls[1].args.b, 'one two');
  api.calls[1].res({ ok: true, note: note({ title: 't', body: 'one two', revision: 6 }) }); await settle();
  assert.equal(d.state, 'saved'); assert.equal(d.revision, 6);
});

test('N3 masked text from the server replaces the draft only if it was not edited since the send', async () => {
  const c = clock(), api = fakeAPI(), D = N.drafts({ api, setTimeout: c.setTimeout, clearTimeout: c.clearTimeout });
  const d = D.sync(note({ revision: 1 }));
  D.edit(d.key, { body: 'password=hunter2' }); D.flush(d.key); await settle();
  api.calls[0].res({ ok: true, note: note({ body: 'password=*******', masked_bytes: 7, revision: 2 }) }); await settle();
  assert.equal(d.body, 'password=*******'); assert.equal(d.masked, 7);
  assert.match(N.statusText(d), /^Saved \(revision 2\) · 7 bytes were masked/);
  D.edit(d.key, { body: 'token=abc' }); D.flush(d.key); await settle();
  D.edit(d.key, { body: 'token=abc and more' });
  api.calls[1].res({ ok: true, note: note({ body: 'token=***', masked_bytes: 3, revision: 3 }) }); await settle();
  assert.equal(d.body, 'token=abc and more', 'typing after the send was lost');
  assert.equal(d.state, 'unsaved');
});

test('N4 a failed save keeps the draft, says "Not saved" and Retry sends it again', async () => {
  const c = clock(), api = fakeAPI(), D = N.drafts({ api, setTimeout: c.setTimeout, clearTimeout: c.clearTimeout });
  const d = D.sync(note({ revision: 2 }));
  D.edit(d.key, { title: 'new' }); D.flush(d.key); await settle();
  api.calls[0].res({ ok: false, status: 0, error: 'connection error' }); await settle();
  assert.equal(d.state, 'error'); assert.equal(d.title, 'new'); assert.match(N.statusText(d), /^Not saved: connection error/);
  assert.equal(D.pending().length, 1);
  D.retry(d.key); await settle();
  assert.equal(api.calls.length, 2); assert.equal(api.calls[1].args.t, 'new'); assert.equal(api.calls[1].args.rev, 2);
  api.calls[1].res({ ok: true, note: note({ title: 'new', revision: 3 }) }); await settle();
  assert.equal(d.state, 'saved'); assert.equal(D.pending().length, 0);
});

test('N5 conflict (409): the draft is kept, autosave stops, and only an explicit choice resolves it', async () => {
  const c = clock(), api = fakeAPI(), D = N.drafts({ api, setTimeout: c.setTimeout, clearTimeout: c.clearTimeout });
  const d = D.sync(note({ title: 'base', revision: 3 }));
  D.edit(d.key, { body: 'mine' }); D.flush(d.key); await settle();
  const theirs = note({ title: 'base', body: 'theirs', revision: 4 });
  api.calls[0].res({ ok: false, status: 409, conflict: true, current: theirs, error: 'the note was changed in another tab or viewer' }); await settle();
  assert.equal(d.state, 'conflict'); assert.equal(d.body, 'mine'); assert.equal(d.current.body, 'theirs');
  D.edit(d.key, { body: 'mine 2' }); c.advance(N.DEBOUNCE_MS * 3); await settle();
  assert.equal(api.calls.length, 1, 'autosave continued in conflict (last-write-wins)');
  assert.equal(d.state, 'conflict'); assert.match(N.statusText(d), /Your text is kept/);
  // A list reload must not replace the conflicted draft either.
  D.sync(note({ title: 'base', body: 'theirs', revision: 4 })); assert.equal(d.body, 'mine 2');
  D.resolve(d.key, 'overwrite'); await settle();
  assert.equal(api.calls.length, 2); assert.equal(api.calls[1].args.rev, 4, 'overwrite must name the newer revision'); assert.equal(api.calls[1].args.b, 'mine 2');
  api.calls[1].res({ ok: true, note: note({ title: 'base', body: 'mine 2', revision: 5 }) }); await settle();
  assert.equal(d.state, 'saved'); assert.equal(d.revision, 5);
  // Second conflict, resolved by loading the saved version.
  D.edit(d.key, { body: 'again' }); D.flush(d.key); await settle();
  api.calls[2].res({ ok: false, status: 409, conflict: true, current: note({ body: 'server', revision: 7 }), error: 'x' }); await settle();
  D.resolve(d.key, 'reload'); await settle();
  assert.equal(d.body, 'server'); assert.equal(d.revision, 7); assert.equal(d.state, 'saved'); assert.equal(api.calls.length, 3);
});

test('N6 A→B→A: drafts survive switching; a list reload never replaces a draft with work in it', async () => {
  const c = clock(), api = fakeAPI(), D = N.drafts({ api, setTimeout: c.setTimeout, clearTimeout: c.clearTimeout });
  const a = D.sync(note({ id: '1'.repeat(32), session_id: 1, body: 'saved A', revision: 2 }));
  const b = D.sync(note({ id: '2'.repeat(32), session_id: 2, body: 'saved B', revision: 1 }));
  D.edit(a.key, { body: 'draft A' });
  D.sync(note({ id: '1'.repeat(32), session_id: 1, body: 'saved A', revision: 2 })); // returning to A reloads its list
  assert.equal(D.get(a.key).body, 'draft A');
  D.edit(b.key, { body: 'draft B' }); c.advance(N.DEBOUNCE_MS); await settle();
  assert.equal(api.calls.length, 2, 'each draft saves on its own');
  const byId = id => api.calls.find(x => x.args.id === id);
  byId('2'.repeat(32)).res({ ok: true, note: note({ id: '2'.repeat(32), session_id: 2, body: 'draft B', revision: 2 }) });
  byId('1'.repeat(32)).res({ ok: true, note: note({ id: '1'.repeat(32), session_id: 1, body: 'draft A', revision: 3 }) }); await settle();
  assert.equal(a.body, 'draft A'); assert.equal(a.revision, 3); assert.equal(b.body, 'draft B'); assert.equal(b.revision, 2);
  // An older list reply (revision 2) arriving late does not roll A back.
  D.sync(note({ id: '1'.repeat(32), session_id: 1, body: 'saved A', revision: 2 }));
  assert.equal(a.body, 'draft A'); assert.equal(a.revision, 3);
  // A newer revision from another tab is taken while A is clean.
  D.sync(note({ id: '1'.repeat(32), session_id: 1, body: 'other tab', revision: 4 }));
  assert.equal(a.body, 'other tab');
});

test('N7 archive waits for a save in flight, uses the newest revision; a second click is a no-op; restore works', async () => {
  const c = clock(), api = fakeAPI(), D = N.drafts({ api, setTimeout: c.setTimeout, clearTimeout: c.clearTimeout });
  const d = D.sync(note({ revision: 1 }));
  D.edit(d.key, { body: 'x' }); D.flush(d.key); await settle();
  const p1 = D.setArchived(d.key, true), p2 = D.setArchived(d.key, true); await settle();
  assert.equal(api.calls.length, 1, 'archive overtook the save');
  api.calls[0].res({ ok: true, note: note({ body: 'x', revision: 2 }) }); await settle();
  assert.equal(api.calls.length, 2); assert.equal(api.calls[1].kind, 'archive'); assert.equal(api.calls[1].args.rev, 2);
  api.calls[1].res({ ok: true, note: note({ body: 'x', revision: 3, archived: true }) }); await settle();
  assert.equal((await p1).ok, true); assert.equal((await p2).unchanged, true); assert.equal(api.calls.length, 2);
  assert.equal(d.archived, true); assert.equal(d.body, 'x', 'archiving changed the text');
  // Editing an archived note does not send anything.
  D.edit(d.key, { body: 'y' }); c.advance(N.DEBOUNCE_MS); await settle(); assert.equal(api.calls.length, 2);
  d.body = 'x'; d.dirty = false; d.state = 'saved';
  const p3 = D.setArchived(d.key, false); await settle();
  assert.equal(api.calls[2].kind, 'archive'); assert.equal(api.calls[2].args.archived, false); assert.equal(api.calls[2].args.rev, 3);
  api.calls[2].res({ ok: true, note: note({ body: 'x', revision: 4 }) }); await p3;
  assert.equal(d.archived, false); assert.equal(d.revision, 4);
});

test('N8 a stale archive (409) keeps the text and reports the conflict instead of retrying blindly', async () => {
  const c = clock(), api = fakeAPI(), D = N.drafts({ api, setTimeout: c.setTimeout, clearTimeout: c.clearTimeout });
  const d = D.sync(note({ body: 'keep', revision: 2 }));
  const p = D.setArchived(d.key, true); await settle();
  api.calls[0].res({ ok: false, status: 409, conflict: true, current: note({ body: 'newer', revision: 5 }), error: 'changed' }); await p;
  assert.equal(d.state, 'conflict'); assert.equal(d.archived, false); assert.equal(d.body, 'keep'); assert.equal(api.calls.length, 1);
});

test('N9 closing the page warns while anything is unsaved, saving, failed or in conflict; never when all is saved', async () => {
  const c = clock(), api = fakeAPI(), D = N.drafts({ api, setTimeout: c.setTimeout, clearTimeout: c.clearTimeout });
  const d = D.sync(note({ revision: 1 }));
  const ev = () => ({ prevented: false, returnValue: undefined, preventDefault() { this.prevented = true; } });
  let e = ev(); assert.equal(D.beforeUnload(e), undefined); assert.equal(e.prevented, false);
  D.edit(d.key, { body: 'unsent' });
  e = ev(); assert.ok(D.beforeUnload(e)); assert.equal(e.prevented, true); assert.equal(e.returnValue, '');
  await settle(); assert.equal(api.calls.length, 1, 'closing did not try to send the unsaved draft');
  e = ev(); assert.ok(D.beforeUnload(e), 'no warning while saving'); assert.equal(d.state, 'saving');
  api.calls[0].res({ ok: false, status: 500, error: 'boom' }); await settle();
  e = ev(); assert.ok(D.beforeUnload(e), 'no warning after a failure'); assert.equal(api.calls.length, 1, 'an error draft is not resent on close');
  D.retry(d.key); await settle(); api.calls[1].res({ ok: true, note: note({ body: 'unsent', revision: 2 }) }); await settle();
  e = ev(); assert.equal(D.beforeUnload(e), undefined);
  // An empty new draft is nothing to lose.
  D.create(1, { kind: '' }, 'session'); e = ev(); assert.equal(D.beforeUnload(e), undefined);
});

test('N10 status texts never call an unconfirmed draft saved', () => {
  for (const state of ['unsaved', 'saving', 'error', 'conflict', 'empty']) assert.ok(!/^Saved/.test(N.statusText({ state, error: 'e', revision: 1 })), state);
  assert.ok(/^Saved/.test(N.statusText({ state: 'saved', revision: 1 })));
});

test('N11 search covers title, text and the anchor snapshot; Unicode and markup are plain text', () => {
  const d = { title: 'Zażółć gęślą', body: '<script>alert(1)</script> **bold**', anchorLabel: 'command #2: nmap -sV 10.0.0.5' };
  assert.ok(N.matches(d, 'GĘŚLĄ')); assert.ok(N.matches(d, '<script>')); assert.ok(N.matches(d, 'nmap')); assert.ok(!N.matches(d, 'absent')); assert.ok(N.matches(d, ' '));
  assert.equal(N.anchorKey({ kind: 'command', cmd_index: 3 }), 'command:3'); assert.equal(N.anchorKey({ kind: 'node', node_id: 'host:1' }), 'node:host:1'); assert.equal(N.anchorKey({ kind: '' }), 'session');
});

test('N12 API client: JSON content type, write-token header, same-origin credentials; a 403 refreshes the token; 409 carries the current note', async () => {
  const seen = []; const T1 = '1'.repeat(64), T2 = '2'.repeat(64); let tok = T1;
  const replies = [];
  const fetchFn = async (url, init) => {
    seen.push({ url, init });
    if (url === '/api/notes/token') return { ok: true, status: 200, json: async () => ({ write_token: tok }) };
    const r = replies.shift(); return r;
  };
  const A = N.api(fetchFn);
  replies.push({ ok: true, status: 201, json: async () => note({}) });
  let r = await A.create(1, { kind: 'command', cmd_index: 2 }, 't', 'b');
  assert.equal(r.ok, true);
  const w = seen[1];
  assert.equal(w.url, '/api/notes'); assert.equal(w.init.method, 'POST'); assert.equal(w.init.credentials, 'same-origin');
  assert.equal(w.init.headers['Content-Type'], 'application/json'); assert.equal(w.init.headers['X-Pentrail-Write'], T1);
  assert.deepEqual(JSON.parse(w.init.body), { session: 1, anchor: { kind: 'command', cmd_index: 2 }, title: 't', body: 'b' });
  replies.push({ ok: false, status: 403, text: async () => 'missing or wrong write token' });
  r = await A.update({ id: 'a'.repeat(32), session: 1, revision: 1 }, 't', 'b');
  assert.equal(r.ok, false); assert.match(r.error, /403/);
  tok = T2;
  replies.push({ ok: false, status: 409, json: async () => ({ error: 'conflict', current: note({ revision: 9 }) }) });
  r = await A.archive({ id: 'a'.repeat(32), session: 1, revision: 1 }, true);
  assert.equal(r.conflict, true); assert.equal(r.current.revision, 9);
  const last = seen[seen.length - 1];
  assert.equal(last.url, '/api/notes/' + 'a'.repeat(32) + '/archive'); assert.equal(last.init.headers['X-Pentrail-Write'], T2, 'the token was not re-read after 403');
  assert.equal(seen.filter(s => s.url === '/api/notes/token').length, 2);
  // No storage API is touched by the module.
  const src = fs.readFileSync(path.join(__dirname, 'notes.js'), 'utf8').replace(/\/\/.*$/gm, '');
  assert.ok(!/localStorage|sessionStorage|indexedDB|document\.cookie/.test(src), 'notes.js uses browser storage');
});

// ---- 04BK: archive/restore never marks unsent text as saved ----
const ID = 'a'.repeat(32);
const waitCall = async (api, k) => { for (let i = 0; i < 50 && api.calls.length <= k; i++) await tick(); assert.ok(api.calls.length > k, 'request #' + k + ' was not sent'); return api.calls[k]; };
// What the fake server stored last: replies are built from the request.
function server() {
  const s = { rev: 1, title: 't', body: 'saved', archived: false, masked: 0 };
  s.reply = (c, mask) => {
    if (c.kind === 'update') { assert.equal(c.args.rev, s.rev, 'stale revision sent'); assert.equal(s.archived, false, 'text sent to an archived note'); s.title = c.args.t; s.body = mask ? mask(c.args.b) : c.args.b; s.masked = mask ? 7 : 0; }
    if (c.kind === 'archive') { assert.equal(c.args.rev, s.rev, 'stale revision sent'); s.archived = c.args.archived; }
    s.rev++;
    c.res({ ok: true, note: note({ id: ID, title: s.title, body: s.body, revision: s.rev, archived: s.archived, masked_bytes: s.masked }) });
  };
  return s;
}

test('N13 (review repro) an edit during the archive pre-save is saved before archiving; never "Saved" with unsent text', async () => {
  const c = clock(), api = fakeAPI(), D = N.drafts({ api, setTimeout: c.setTimeout, clearTimeout: c.clearTimeout }), srv = server();
  const d = D.sync(note({ id: ID, title: 't', body: 'saved', revision: 1 }));
  D.edit(d.key, { body: 'first draft' });
  const p = D.setArchived(d.key, true);
  const c0 = await waitCall(api, 0); assert.equal(c0.kind, 'update'); assert.equal(c0.args.b, 'first draft');
  assert.equal(d.state, 'saving', 'the pre-save does not show Saving');
  D.edit(d.key, { body: 'NEWER TEXT WHILE ARCHIVING' });
  srv.reply(c0); await settle();
  assert.notEqual(d.state, 'saved'); assert.ok(D.pending().length > 0, 'unsent text not pending');
  const c1 = await waitCall(api, 1); assert.equal(c1.kind, 'update', 'archived before the newer text was saved'); assert.equal(c1.args.b, 'NEWER TEXT WHILE ARCHIVING');
  srv.reply(c1);
  const c2 = await waitCall(api, 2); assert.equal(c2.kind, 'archive'); srv.reply(c2);
  const r = await p;
  assert.equal(r.ok, true); assert.equal(srv.body, 'NEWER TEXT WHILE ARCHIVING', 'the newer text never reached the server');
  assert.equal(srv.archived, true); assert.equal(d.archived, true); assert.equal(d.state, 'saved'); assert.equal(d.dirty, false);
  assert.equal(d.body, 'NEWER TEXT WHILE ARCHIVING'); assert.equal(D.pending().length, 0); assert.equal(api.calls.length, 3);
});

test('N14 an edit while the archive request itself runs: restored, saved and archived again with the latest text', async () => {
  const c = clock(), api = fakeAPI(), D = N.drafts({ api, setTimeout: c.setTimeout, clearTimeout: c.clearTimeout }), srv = server();
  const d = D.sync(note({ id: ID, title: 't', body: 'saved', revision: 1 }));
  const p = D.setArchived(d.key, true);
  const c0 = await waitCall(api, 0); assert.equal(c0.kind, 'archive');
  assert.equal(D.edit(d.key, { body: 'typed during the archive request' }), true, 'the edit was dropped');
  srv.reply(c0); await settle();
  assert.notEqual(d.state, 'saved'); assert.ok(D.pending().length > 0);
  const c1 = await waitCall(api, 1); assert.deepEqual([c1.kind, c1.args.archived], ['archive', false]); srv.reply(c1);
  const c2 = await waitCall(api, 2); assert.equal(c2.kind, 'update'); assert.equal(c2.args.b, 'typed during the archive request'); srv.reply(c2);
  const c3 = await waitCall(api, 3); assert.deepEqual([c3.kind, c3.args.archived], ['archive', true]); srv.reply(c3);
  await p;
  assert.equal(srv.body, 'typed during the archive request'); assert.equal(srv.archived, true);
  assert.equal(d.state, 'saved'); assert.equal(d.archived, true); assert.equal(D.pending().length, 0);
});

test('N15 the masked text of the archive pre-save is adopted and reported', async () => {
  const c = clock(), api = fakeAPI(), D = N.drafts({ api, setTimeout: c.setTimeout, clearTimeout: c.clearTimeout }), srv = server();
  const d = D.sync(note({ id: ID, title: 't', body: 'saved', revision: 1 }));
  D.edit(d.key, { body: 'password=Secret1' });
  const p = D.setArchived(d.key, true);
  srv.reply(await waitCall(api, 0), b => b.replace('Secret1', '*******'));
  srv.reply(await waitCall(api, 1));
  await p;
  assert.equal(d.body, 'password=*******', 'the secret stays in the page without a mask warning');
  assert.equal(d.masked, 7); assert.match(N.statusText(d), /^Archived \(revision 3\) · 7 bytes were masked/);
});

test('N16 a failed archive says "Not saved", stays pending, and Retry archives', async () => {
  const c = clock(), api = fakeAPI(), D = N.drafts({ api, setTimeout: c.setTimeout, clearTimeout: c.clearTimeout }), srv = server();
  const d = D.sync(note({ id: ID, title: 't', body: 'saved', revision: 1 }));
  const p = D.setArchived(d.key, true);
  (await waitCall(api, 0)).res({ ok: false, status: 0, error: 'connection error' });
  await p;
  assert.equal(d.state, 'error'); assert.equal(d.archived, false); assert.ok(D.pending().length > 0); assert.match(N.statusText(d), /^Not saved/);
  const q = D.retry(d.key);
  const c1 = await waitCall(api, 1); assert.deepEqual([c1.kind, c1.args.archived], ['archive', true]); srv.reply(c1); await q;
  assert.equal(d.archived, true); assert.equal(d.state, 'saved'); assert.equal(D.pending().length, 0);
});

test('N17 a duplicate click during an archive sends one archive request', async () => {
  const c = clock(), api = fakeAPI(), D = N.drafts({ api, setTimeout: c.setTimeout, clearTimeout: c.clearTimeout }), srv = server();
  const d = D.sync(note({ id: ID, title: 't', body: 'saved', revision: 1 }));
  const p1 = D.setArchived(d.key, true), p2 = D.setArchived(d.key, true);
  srv.reply(await waitCall(api, 0)); await p1; await p2; await settle();
  assert.equal(api.calls.length, 1); assert.equal(d.archived, true); assert.equal(d.state, 'saved');
});

test('N18 restore: text typed while restoring is saved after it; the restored note keeps the latest text', async () => {
  const c = clock(), api = fakeAPI(), D = N.drafts({ api, setTimeout: c.setTimeout, clearTimeout: c.clearTimeout }), srv = server();
  srv.archived = true;
  const d = D.sync(note({ id: ID, title: 't', body: 'saved', revision: 1, archived: true }));
  const p = D.setArchived(d.key, false);
  const c0 = await waitCall(api, 0); assert.deepEqual([c0.kind, c0.args.archived], ['archive', false]);
  D.edit(d.key, { body: 'typed while restoring' });
  srv.reply(c0);
  const c1 = await waitCall(api, 1); assert.equal(c1.kind, 'update'); assert.equal(c1.args.b, 'typed while restoring'); srv.reply(c1);
  await p;
  assert.equal(srv.body, 'typed while restoring'); assert.equal(srv.archived, false);
  assert.equal(d.state, 'saved'); assert.equal(d.archived, false); assert.equal(D.pending().length, 0);
});

test('N19 an archived note without a running restore is read-only: an edit is refused and nothing is pending', async () => {
  const c = clock(), api = fakeAPI(), D = N.drafts({ api, setTimeout: c.setTimeout, clearTimeout: c.clearTimeout });
  const d = D.sync(note({ id: ID, title: 't', body: 'kept', revision: 4, archived: true }));
  assert.equal(D.edit(d.key, { body: 'x' }), false); assert.equal(d.body, 'kept');
  c.advance(N.DEBOUNCE_MS * 2); await settle();
  assert.equal(api.calls.length, 0); assert.equal(D.pending().length, 0); assert.equal(d.state, 'saved');
});

test('N20 a conflict during the archive pre-save keeps the text; "Save my text over it" saves it and archives', async () => {
  const c = clock(), api = fakeAPI(), D = N.drafts({ api, setTimeout: c.setTimeout, clearTimeout: c.clearTimeout }), srv = server();
  const d = D.sync(note({ id: ID, title: 't', body: 'saved', revision: 1 }));
  D.edit(d.key, { body: 'mine' });
  const p = D.setArchived(d.key, true);
  srv.rev = 2; srv.body = 'theirs';
  (await waitCall(api, 0)).res({ ok: false, status: 409, conflict: true, current: note({ id: ID, body: 'theirs', revision: 2 }), error: 'changed' });
  await p;
  assert.equal(d.state, 'conflict'); assert.equal(d.body, 'mine'); assert.equal(d.archived, false); assert.ok(D.pending().length > 0);
  const q = D.resolve(d.key, 'overwrite');
  const c1 = await waitCall(api, 1); assert.equal(c1.kind, 'update'); assert.equal(c1.args.b, 'mine'); srv.reply(c1);
  srv.reply(await waitCall(api, 2)); await q;
  assert.equal(srv.body, 'mine'); assert.equal(srv.archived, true); assert.equal(d.state, 'saved'); assert.equal(D.pending().length, 0);
});

// ---- 04BN: the write-token read is bounded; a failed token read sends no write ----
const TOK = 'c'.repeat(64);
// A fetch for the token whose behaviour each test sets; writes are recorded.
function tokenServer() {
  const t = { mode: 'ok', writes: [], tokenReads: 0, aborted: 0 };
  t.fetch = (url, init) => {
    if (url === '/api/notes/token') {
      t.tokenReads++;
      const sig = init && init.signal; if (sig) sig.addEventListener('abort', () => t.aborted++);
      const m = t.mode;
      if (m === 'hang') return new Promise(() => {});
      if (m === 'reject') return Promise.reject(new TypeError('Failed to fetch'));
      if (m === 'bodyhang') return Promise.resolve({ ok: true, status: 200, json: () => new Promise(() => {}) });
      if (typeof m === 'number') return Promise.resolve({ ok: false, status: m, json: async () => ({}) });
      if (m === 'short') return Promise.resolve({ ok: true, status: 200, json: async () => ({ write_token: 'T1' }) });
      if (m === 'missing') return Promise.resolve({ ok: true, status: 200, json: async () => ({ token: TOK }) });
      if (m === 'notjson') return Promise.resolve({ ok: true, status: 200, json: async () => { throw new SyntaxError('Unexpected token <'); } });
      return Promise.resolve({ ok: true, status: 200, json: async () => ({ write_token: TOK }) });
    }
    t.writes.push({ url, init });
    const b = JSON.parse(init.body);
    return Promise.resolve({ ok: true, status: url === '/api/notes' ? 201 : 200, json: async () => note({ id: ID, title: b.title, body: b.body, revision: (b.revision || 0) + 1 }) });
  };
  return t;
}

test('N21 token read that never answers, or whose body never arrives: times out after 15 s, is aborted, sends no write; the draft keeps its text', async () => {
  for (const mode of ['hang', 'bodyhang']) {
    const c = clock(), srv = tokenServer(); srv.mode = mode;
    const A = N.api(srv.fetch, { setTimeout: c.setTimeout, clearTimeout: c.clearTimeout });
    const D = N.drafts({ api: A, setTimeout: c.setTimeout, clearTimeout: c.clearTimeout });
    const d = D.create(1, { kind: '' }, 'session');
    D.edit(d.key, { title: 't', body: 'my unsaved text' });
    c.advance(N.DEBOUNCE_MS); await settle();
    assert.equal(d.state, 'saving', mode + ': not waiting for the token');
    c.advance(14999); await settle();
    assert.equal(d.state, 'saving', mode + ': gave up before 15 s');
    c.advance(1); await settle();
    assert.equal(d.state, 'error', mode + ': still saving after the bound');
    assert.match(N.statusText(d), /^Not saved: no write permission \(the request timed out\); nothing was sent/);
    assert.equal(srv.writes.length, 0, mode + ': a write was sent without a token');
    assert.equal(srv.aborted, 1, mode + ': the token request was not aborted');
    assert.equal(d.body, 'my unsaved text'); assert.equal(d.id, null); assert.ok(D.pending().length > 0, 'the draft is not reported as pending');
  }
});

test('N22 token read errors (connection, 401, 403, 500, invalid or short token, not JSON) are reported and send no write', async () => {
  const cases = [['reject', /connection error/], [401, /link has expired/], [403, /code 403/], [500, /code 500/], ['short', /invalid response/], ['missing', /invalid response/], ['notjson', /connection error|invalid/]];
  for (const [mode, re] of cases) {
    const srv = tokenServer(); srv.mode = mode;
    const A = N.api(srv.fetch);
    const r = await A.create(1, { kind: '' }, 't', 'b');
    assert.equal(r.ok, false, String(mode)); assert.equal(r.status, 0); assert.match(r.error, re, String(mode)); assert.match(r.error, /nothing was sent/);
    assert.equal(srv.writes.length, 0, mode + ': a write was sent');
  }
});

test('N23 Retry after a failed token read asks for the token again and saves the kept text exactly once', async () => {
  const c = clock(), srv = tokenServer(); srv.mode = 500;
  const A = N.api(srv.fetch, { setTimeout: c.setTimeout, clearTimeout: c.clearTimeout });
  const D = N.drafts({ api: A, setTimeout: c.setTimeout, clearTimeout: c.clearTimeout });
  const d = D.create(1, { kind: 'command', cmd_index: 4 }, 'command #4');
  D.edit(d.key, { title: 'scan', body: 'keep me' });
  c.advance(N.DEBOUNCE_MS); await settle();
  assert.equal(d.state, 'error'); assert.equal(srv.writes.length, 0); assert.equal(srv.tokenReads, 1);
  srv.mode = 'ok';
  await D.retry(d.key); await settle();
  assert.equal(srv.tokenReads, 2, 'Retry did not ask for the token again');
  assert.equal(srv.writes.length, 1, 'not exactly one write');
  assert.equal(srv.writes[0].init.headers['X-Pentrail-Write'], TOK);
  assert.deepEqual(JSON.parse(srv.writes[0].init.body), { session: 1, anchor: { kind: 'command', cmd_index: 4 }, title: 'scan', body: 'keep me' });
  assert.equal(d.state, 'saved'); assert.equal(d.body, 'keep me'); assert.equal(D.pending().length, 0);
  // The token is reused afterwards: an edit saves without a new token read.
  D.edit(d.key, { body: 'keep me 2' }); c.advance(N.DEBOUNCE_MS); await settle();
  assert.equal(srv.tokenReads, 2); assert.equal(srv.writes.length, 2); assert.equal(d.state, 'saved');
});

test('N24 concurrent saves share one token read; a token that arrives after the bound sends nothing late', async () => {
  const c = clock(); let release; const writes = []; let reads = 0;
  const fetchFn = (url, init) => {
    if (url === '/api/notes/token') { reads++; return new Promise(res => { release = () => res({ ok: true, status: 200, json: async () => ({ write_token: TOK }) }); }); }
    writes.push(url); return Promise.resolve({ ok: true, status: 201, json: async () => note({}) });
  };
  const A = N.api(fetchFn, { setTimeout: c.setTimeout, clearTimeout: c.clearTimeout });
  const p1 = A.create(1, { kind: '' }, 'a', 'a'), p2 = A.create(1, { kind: '' }, 'b', 'b');
  await settle();
  assert.equal(reads, 1, 'two token reads for concurrent saves');
  c.advance(15000);
  const [r1, r2] = await Promise.all([p1, p2]);
  assert.equal(r1.ok, false); assert.equal(r2.ok, false); assert.match(r1.error, /timed out/);
  release(); await settle();
  assert.equal(writes.length, 0, 'a late token sent a write nobody asked for any more');
  // The next save reads the token again and succeeds.
  const p3 = A.create(1, { kind: '' }, 'c', 'c'); await settle(); release(); const r3 = await p3;
  assert.equal(reads, 2); assert.equal(r3.ok, true); assert.deepEqual(writes, ['/api/notes']);
});

(async () => {
  let fail = 0;
  for (const [name, fn] of tests) {
    try { await fn(); console.log('PASS | ' + name); }
    catch (e) { fail++; console.log('FAIL | ' + name + ' | ' + String(e && e.message || e).replace(/\s+/g, ' ').slice(0, 300)); }
  }
  console.log(fail ? 'FAIL notes ' + fail : 'PASS notes ' + tests.length);
  process.exitCode = fail ? 1 : 0;
})();
