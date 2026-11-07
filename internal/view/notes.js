// Operator notes in the viewer: the API client and the drafts with autosave.
// Notes are the operator's own annotations, NOT captured evidence. They are
// kept in the encrypted database (the viewer's /api/notes); drafts live only
// in this page's memory — never in localStorage, cookies or files.
//
// Autosave: an edit marks the draft "unsaved" and schedules a save after a
// short pause (debounce). One request per draft at a time (a queue), so a
// reply can never be overtaken by an older one. Every save names the revision
// it is based on; a 409 reply means another tab or viewer changed the note:
// the draft is kept and the user chooses (load the saved version, or save this
// text over it). Nothing is called "saved" before the server confirmed it.
(function (global) {
  const DEBOUNCE_MS = 800;

  function api(fetchFn, opts) {
    const tokenTimeoutMs = (opts && opts.tokenTimeoutMs) || 15000;
    const st = (opts && opts.setTimeout) || ((f, ms) => setTimeout(f, ms));
    const ct = (opts && opts.clearTimeout) || (i => clearTimeout(i));
    let token = null;
    let pendingToken = null; // one token read at a time, shared by concurrent saves
    // The write token is a READ that happens before any write is sent, so it is
    // bounded like the other reads (request and body together) and settles
    // with {ok, token} or {ok:false, error}; it never rejects. A failure here
    // means that no write was sent: the draft stays "Not saved" with Retry,
    // and the next save asks for the token again.
    function readToken() {
      const ctl = typeof AbortController === 'function' ? new AbortController() : null;
      let timer;
      const timeout = new Promise(res => { timer = st(() => { res({ ok: false, error: 'the request timed out' }); try { ctl && ctl.abort(); } catch (e) { /* done */ } }, tokenTimeoutMs); });
      const work = (async () => {
        try {
          const r = await fetchFn('/api/notes/token', ctl ? { signal: ctl.signal } : undefined);
          if (!r.ok) {
            const why = r.status === 401 ? 'the viewer link has expired; open the newly printed link' : 'the viewer reported an error, code ' + r.status;
            return { ok: false, error: why };
          }
          const v = await r.json();
          if (!v || typeof v.write_token !== 'string' || !/^[0-9a-f]{64}$/.test(v.write_token)) return { ok: false, error: 'invalid response' };
          return { ok: true, token: v.write_token };
        } catch (e) { return { ok: false, error: 'connection error' }; }
      })();
      return Promise.race([work, timeout]).finally(() => ct(timer));
    }
    async function writeToken() {
      if (token) return { ok: true, token };
      if (!pendingToken) pendingToken = readToken().finally(() => { pendingToken = null; });
      const r = await pendingToken;
      if (r.ok) token = r.token;
      return r;
    }
    async function send(method, url, body) {
      const w = await writeToken();
      if (!w.ok) return { ok: false, status: 0, error: 'no write permission (' + w.error + '); nothing was sent' };
      const t = w.token;
      let r;
      try {
        r = await fetchFn(url, { method, credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-Pentrail-Write': t }, body: JSON.stringify(body) });
      } catch (e) {
        return { ok: false, status: 0, error: 'connection error' };
      }
      if (r.status === 409) {
        let v = null; try { v = await r.json(); } catch (e) { /* reported below */ }
        return { ok: false, status: 409, conflict: true, current: v && v.current, error: 'the note was changed in another tab or viewer' };
      }
      if (r.status === 403) token = null; // e.g. the viewer was restarted: ask for a new write token next time
      if (!r.ok) {
        let msg = ''; try { msg = String(await r.text()).trim().slice(0, 200); } catch (e) { /* none */ }
        return { ok: false, status: r.status, error: 'the viewer reported an error, code ' + r.status + (msg ? ': ' + msg : '') };
      }
      try { return { ok: true, status: r.status, note: await r.json() }; } catch (e) { return { ok: false, status: r.status, error: 'invalid response' }; }
    }
    return {
      // A read: bounded (request and body together), never rejects. Writes
      // below are NOT bounded or retried: a write's outcome must never be guessed.
      async list(session, timeoutMs) {
        const ctl = typeof AbortController === 'function' ? new AbortController() : null;
        let timer;
        const timeout = new Promise(res => { timer = setTimeout(() => { res({ ok: false, error: 'the request timed out' }); try { ctl && ctl.abort(); } catch (e) { /* done */ } }, timeoutMs || 15000); });
        const work = (async () => {
          try {
            const r = await fetchFn('/api/notes?session=' + encodeURIComponent(session), ctl ? { signal: ctl.signal } : undefined);
            if (!r.ok) return { ok: false, error: 'the viewer reported an error, code ' + r.status };
            const v = await r.json();
            return Array.isArray(v) && v.every(n => n && typeof n === 'object' && typeof n.id === 'string') ? { ok: true, notes: v } : { ok: false, error: 'invalid response' };
          } catch (e) { return { ok: false, error: 'connection error' }; }
        })();
        try { return await Promise.race([work, timeout]); } finally { clearTimeout(timer); }
      },
      create: (session, anchor, title, body) => send('POST', '/api/notes', { session, anchor, title, body }),
      update: (d, title, body) => send('PUT', '/api/notes/' + d.id, { session: d.session, revision: d.revision, title, body }),
      archive: (d, archived) => send('POST', '/api/notes/' + d.id + '/archive', { session: d.session, revision: d.revision, archived }),
    };
  }

  // anchorKey: one string per anchor (for filtering and for new drafts).
  function anchorKey(a) {
    if (!a || !a.kind) return 'session';
    return a.kind === 'command' ? 'command:' + a.cmd_index : 'node:' + a.node_id;
  }
  function anchorOf(note) {
    if (note.anchor_kind === 'command') return { kind: 'command', cmd_index: note.cmd_index };
    if (note.anchor_kind === 'node') return { kind: 'node', node_id: note.node_id };
    return { kind: '' };
  }

  // drafts({api, onChange, setTimeout, clearTimeout}): all drafts of this page.
  //
  // Every edit increments the draft's generation (gen). Every request records
  // the generation of the text it carries; its reply marks the draft clean and
  // adopts the stored (masked) text ONLY if no edit happened meanwhile —
  // otherwise the newer text stays dirty and is sent next. So no reply of any
  // kind (save, archive, restore) can mark unsent text as saved.
  function drafts(o) {
    const st = o.setTimeout || global.setTimeout, ct = o.clearTimeout || global.clearTimeout;
    const all = new Map();
    let seq = 0;
    const changed = d => { try { o.onChange && o.onChange(d); } catch (e) { /* a rendering error must not stop saving */ } };
    const enqueue = (d, fn) => (d.queue = d.queue.then(fn, fn));

    function fromNote(n, key) {
      return { key: key || n.id, id: n.id, session: n.session_id, anchor: anchorOf(n), anchorLabel: n.anchor_label,
        title: n.title, body: n.body, revision: n.revision, archived: !!n.archived, createdMs: n.created_ms, updatedMs: n.updated_ms,
        masked: n.masked_bytes || 0, state: 'saved', error: '', current: null, dirty: false, inFlight: false, timer: null,
        gen: 0, op: null, wantArchived: null, queue: Promise.resolve() };
    }
    // A note from the server: a draft with work in it is never replaced.
    function sync(n) {
      const d = [...all.values()].find(x => x.id === n.id);
      if (d) {
        if (d.state === 'saved' && !d.dirty && !d.inFlight && !d.op && d.wantArchived == null && n.revision >= d.revision)
          Object.assign(d, fromNote(n, d.key), { queue: d.queue, gen: d.gen });
        return d;
      }
      const nd = fromNote(n);
      all.set(nd.key, nd);
      return nd;
    }
    function create(session, anchor, anchorLabel) {
      const d = fromNote({ id: null, session_id: session, anchor_kind: anchor && anchor.kind || '', cmd_index: anchor && anchor.cmd_index, node_id: anchor && anchor.node_id,
        anchor_label: anchorLabel || '', title: '', body: '', revision: 0, archived: false }, 'new:' + (++seq));
      d.state = 'empty';
      all.set(d.key, d);
      return d;
    }
    // Adopt a successful reply. g: the generation of the text the request
    // carried, or null for an archive/restore request, which carries no text.
    function apply(d, n, g) {
      d.id = n.id; d.revision = n.revision; d.archived = !!n.archived; d.updatedMs = n.updated_ms; d.createdMs = n.created_ms;
      d.anchorLabel = n.anchor_label; d.masked = n.masked_bytes || 0;
      if (g !== null && d.gen === g) { d.title = n.title; d.body = n.body; d.dirty = false; } // the stored text, recognized secrets masked
      else if (g === null && !d.dirty) { d.title = n.title; d.body = n.body; } // nothing unsent: the stored text is ours
      else d.dirty = true; // edited meanwhile, or unsent text: not saved yet
    }
    function fail(d, r) {
      if (r.conflict) { d.state = 'conflict'; d.current = r.current || null; d.error = r.error; }
      else { d.state = 'error'; d.error = r.error || 'not saved'; }
    }
    async function sendText(d) {
      const g = d.gen, t = d.title, b = d.body;
      d.inFlight = true; d.state = 'saving'; changed(d);
      const r = d.id ? await o.api.update(d, t, b) : await o.api.create(d.session, d.anchor, t, b);
      d.inFlight = false;
      if (r.ok) apply(d, r.note, g);
      return r;
    }
    async function sendArchive(d, archived) {
      d.inFlight = true; d.state = 'saving'; changed(d);
      const r = await o.api.archive(d, archived);
      d.inFlight = false;
      if (r.ok) apply(d, r.note, null);
      return r;
    }
    // Edits are accepted unless the note is archived and no archive/restore is
    // running (an archived note is read-only until it is restored).
    function edit(key, fields) {
      const d = all.get(key);
      if (!d || (d.archived && !d.op)) return false;
      if (fields.title != null) d.title = String(fields.title);
      if (fields.body != null) d.body = String(fields.body);
      d.gen++; d.dirty = true;
      if (!d.op) {
        d.wantArchived = null; // a failed archive/restore was reported; typing moves on
        if (d.state !== 'conflict') { d.state = 'unsaved'; d.error = ''; }
        ct(d.timer);
        if (d.state !== 'conflict') d.timer = st(() => flush(key), DEBOUNCE_MS);
      } // during an archive/restore the running operation saves the newer text
      changed(d);
      return true;
    }
    function flush(key) {
      const d = all.get(key);
      if (!d) return Promise.resolve();
      ct(d.timer); d.timer = null;
      return enqueue(d, async () => {
        if (!d.dirty || d.state === 'conflict' || d.archived || d.op) return;
        if (!d.id && !d.title.trim() && !d.body.trim()) { d.dirty = false; d.state = 'empty'; changed(d); return; }
        const r = await sendText(d);
        if (!r.ok) fail(d, r);
        else if (d.dirty) { d.state = 'unsaved'; d.error = ''; ct(d.timer); d.timer = st(() => flush(key), DEBOUNCE_MS); }
        else { d.state = 'saved'; d.error = ''; }
        changed(d);
      });
    }
    // Archive or restore. The operation ends only when the server holds the
    // LATEST text in the wanted state: unsent text is saved first; text typed
    // while the archive request ran is saved by restoring, saving and
    // archiving again. Each step is revision-guarded; a failure stops it with
    // a truthful status and Retry repeats it.
    async function runArchive(d) {
      const want = d.wantArchived;
      if (want == null) return { ok: true, unchanged: true };
      if (d.state === 'conflict') return { ok: false, conflict: true };
      d.op = want ? 'archive' : 'restore'; d.error = ''; changed(d);
      try {
        for (let i = 0; i < 8; i++) {
          if (d.archived === want && !d.dirty) { d.wantArchived = null; d.state = 'saved'; return { ok: true, unchanged: i === 0 }; }
          let r;
          if (!d.archived && d.dirty) r = await sendText(d);              // the latest text first
          else if (d.archived && d.dirty) r = await sendArchive(d, false); // archived with newer text: restore to save it
          else r = await sendArchive(d, want);
          if (!r.ok) { fail(d, r); return r; }
        }
        d.state = 'error'; d.error = 'the note kept changing during ' + (want ? 'archiving' : 'restoring') + '; try again';
        return { ok: false };
      } finally { d.op = null; changed(d); }
    }
    function setArchived(key, archived) {
      const d = all.get(key);
      if (!d || !d.id) return Promise.resolve({ ok: false });
      ct(d.timer); d.timer = null;
      d.wantArchived = !!archived;
      return enqueue(d, () => runArchive(d));
    }
    function retry(key) {
      const d = all.get(key);
      if (!d || d.state !== 'error') return Promise.resolve();
      if (d.wantArchived != null) { d.error = ''; return enqueue(d, () => runArchive(d)); }
      d.dirty = true; d.state = 'unsaved'; changed(d);
      return flush(key);
    }
    // Conflict: 'reload' takes the saved version (the draft is dropped only on
    // this explicit choice); 'overwrite' repeats this draft's change (its text,
    // and an archive/restore if one was asked for) over the newer revision.
    function resolve(key, how) {
      const d = all.get(key);
      if (!d || d.state !== 'conflict' || !d.current) return Promise.resolve();
      const c = d.current;
      d.current = null;
      if (how === 'reload') {
        Object.assign(d, { title: c.title, body: c.body, revision: c.revision, archived: !!c.archived, masked: c.masked_bytes || 0, updatedMs: c.updated_ms, dirty: false, wantArchived: null, state: 'saved', error: '' });
        d.gen++;
        changed(d);
        return Promise.resolve();
      }
      d.revision = c.revision; d.archived = !!c.archived; d.error = '';
      if (d.wantArchived != null) { d.state = 'saving'; changed(d); return enqueue(d, () => runArchive(d)); }
      if (d.archived) { // saved over an archived note: restore it so the text can be saved
        d.wantArchived = false; d.dirty = true; d.state = 'saving'; changed(d); return enqueue(d, () => runArchive(d));
      }
      d.dirty = true; d.state = 'unsaved';
      changed(d);
      return flush(key);
    }
    const pending = () => [...all.values()].filter(d => d.dirty || d.inFlight || d.op || ['error', 'conflict', 'unsaved', 'saving'].includes(d.state));
    // Leaving the page: start what can be sent and warn when anything is not
    // confirmed by the server (the browser shows its own generic question).
    function beforeUnload(e) {
      const p = pending();
      if (!p.length) return undefined;
      for (const d of p) if (d.state === 'unsaved') flush(d.key);
      if (e) { e.preventDefault(); e.returnValue = ''; }
      return 'Some operator notes are not saved.';
    }
    return { all, get: k => all.get(k), sync, create, edit, flush, retry, resolve, setArchived, pending, beforeUnload,
      byId: id => [...all.values()].find(d => d.id === id) };
  }

  // Status text of a draft for the editor (never "Saved" before the server said so).
  function statusText(d) {
    switch (d.state) {
      case 'empty': return 'Nothing to save yet.';
      case 'unsaved': return 'Unsaved changes…';
      case 'saving': return d.op === 'archive' ? 'Archiving… (the latest text is saved first)' : d.op === 'restore' ? 'Restoring…' : 'Saving…';
      case 'saved': return (d.archived ? 'Archived' : 'Saved') + (d.revision ? ' (revision ' + d.revision + ')' : '') + (d.masked ? ' · ' + d.masked + ' bytes were masked as possible secrets' : '') + '.' + (d.archived ? ' Restore it to edit; nothing was deleted.' : '');
      case 'error': return 'Not saved: ' + d.error;
      case 'conflict': return 'Not saved: ' + (d.error || 'the note was changed elsewhere') + '. Your text is kept below.';
    }
    return '';
  }

  // Search over what the operator sees: title, text and the anchor snapshot.
  function matches(d, q) {
    q = String(q || '').trim().toLowerCase();
    if (!q) return true;
    return [d.title, d.body, d.anchorLabel].some(s => String(s || '').toLowerCase().includes(q));
  }

  global.pentrailNotes = { api, drafts, statusText, matches, anchorKey, anchorOf, DEBOUNCE_MS };
})(typeof window !== 'undefined' ? window : globalThis);
