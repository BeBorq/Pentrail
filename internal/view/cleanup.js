// Cleanup checklist state (Codex 04J). Ticks are kept per browser in
// localStorage, under a key that names the DATABASE by its random view
// namespace (from /api/identity) — never by session id alone: after the
// database changes, session and command numbers repeat, and a tick for one
// piece of evidence must not appear on another. The namespace carries no
// path, key or token. Keys of earlier versions (without a namespace) are
// never read, so they cannot mark new evidence as cleaned. While the
// namespace is unknown the checklist shows its items without any tick and
// cannot be ticked.
(function (global) {
  const NS = /^[0-9a-f]{32}$/;
  const PREFIX = 'pentrail:clean:v2:';

  // namespace never rejects and always settles (the request and its body
  // are bounded together): {ok:true, ns} or {ok:false, error}
  async function namespace(fetchFn, timeoutMs) {
    const ctl = typeof AbortController === 'function' ? new AbortController() : null;
    let timer;
    const timeout = new Promise(res => { timer = setTimeout(() => { res({ok: false, error: 'the request timed out'}); try { ctl && ctl.abort(); } catch (e) { /* done */ } }, timeoutMs || 10000); });
    const work = (async () => {
      try {
        const r = await fetchFn('/api/identity', ctl ? {signal: ctl.signal} : undefined);
        if (!r.ok) return {ok: false, error: 'the viewer reported an error, code ' + r.status};
        const v = await r.json();
        if (!v || typeof v.view_namespace !== 'string' || !NS.test(v.view_namespace)) return {ok: false, error: 'invalid response'};
        return {ok: true, ns: v.view_namespace};
      } catch (e) {
        return {ok: false, error: e && e.name === 'AbortError' ? 'the request timed out' : 'connection error'};
      }
    })();
    try { return await Promise.race([work, timeout]); } finally { clearTimeout(timer); }
  }

  function key(ns, session, it) {
    if (!NS.test(ns)) throw new Error('no database namespace');
    return PREFIX + ns + ':' + Number(session) + ':' + Number(it.cmd_index) + ':' + String(it.category);
  }

  // state(storage, nsResult, session): done(it) / set(it, v) -> saved?
  function state(storage, nsResult, session) {
    const known = !!(nsResult && nsResult.ok);
    return {
      known,
      done(it) {
        if (!known) return false;
        try { return storage.getItem(key(nsResult.ns, session, it)) === '1'; } catch (e) { return false; }
      },
      set(it, v) {
        if (!known) return false;
        try {
          const k = key(nsResult.ns, session, it);
          if (v) storage.setItem(k, '1'); else storage.removeItem(k);
          return true;
        } catch (e) { return false; }
      },
    };
  }

  // headText: the checklist summary in plain words.
  function headText(total, doneCount, st, nsResult) {
    if (!st.known) {
      return 'Cleanup checklist — ' + total + ' change(s) to review. Tick state: unknown — could not determine ' +
        'which evidence database this checklist belongs to (' + (nsResult && nsResult.error || 'no response') + '). ' +
        'Ticks are hidden and locked so that ticks of another database are not shown.';
    }
    return 'Cleanup checklist — ' + total + ' change(s) to review at the end of the test · ' + doneCount + ' ticked. ' +
      'Ticks are stored only in this browser, separately for this evidence database.';
  }

  global.pentrailCleanup = {namespace, key, state, headText};
})(window);
