// Tool output files (artifacts) in the session view. Codex 04H: a failed or
// timed-out /api/artifacts request is shown as "unknown — could not read",
// with a retry, never as an empty list; and the summary counts complete,
// in-progress and problem files separately ("all imported" only when every
// file is complete).
(function (global) {
  const LABEL = {waiting: 'tool still running', pending: 'waiting for import', imported: 'imported (complete)',
    imported_partial: 'imported PARTIALLY', rejected_invalid: 'rejected — invalid document', skipped_too_large: 'skipped — too large',
    missing: 'file missing', unreadable: 'unreadable', unsafe: 'skipped — unsafe file type', legacy_unverified: 'plaintext copy from an older version'};

  function problem(a) {
    return !!(a.partial || a.cleanup_pending || a.cleanup_detail) || !['imported', 'waiting', 'pending'].includes(a.state);
  }

  // complete / in progress / needing attention: every file in exactly one
  function classify(arts) {
    const c = {complete: 0, inProgress: 0, problems: 0};
    for (const a of arts) {
      if (problem(a)) c.problems++;
      else if (a.state === 'imported') c.complete++;
      else c.inProgress++; // waiting, pending
    }
    return c;
  }

  function summaryText(arts) {
    const c = classify(arts);
    let s = 'Tool output files: ' + arts.length;
    if (c.problems === 0 && c.inProgress === 0) return s + ' — all imported';
    const parts = [];
    if (c.problems) parts.push('needs attention: ' + c.problems);
    if (c.inProgress) parts.push('in progress (tool running or waiting for import): ' + c.inProgress);
    parts.push('imported completely: ' + c.complete);
    return s + ' — ' + parts.join(', ');
  }

  // load never rejects and always settles (the request and its body are
  // bounded together): {ok:true, items} or {ok:false, error}
  async function load(fetchFn, session, timeoutMs) {
    const ctl = typeof AbortController === 'function' ? new AbortController() : null;
    let timer;
    const timeout = new Promise(res => { timer = setTimeout(() => { res({ok: false, error: 'the request timed out'}); try { ctl && ctl.abort(); } catch (e) { /* done */ } }, timeoutMs || 10000); });
    const work = (async () => {
      try {
        const r = await fetchFn('/api/artifacts?session=' + session, ctl ? {signal: ctl.signal} : undefined);
        if (!r.ok) return {ok: false, error: 'the viewer reported an error, code ' + r.status};
        const items = await r.json();
        if (!Array.isArray(items)) return {ok: false, error: 'invalid response'};
        return {ok: true, items};
      } catch (e) {
        return {ok: false, error: e && e.name === 'AbortError' ? 'the request timed out' : 'connection error'};
      }
    })();
    try { return await Promise.race([work, timeout]); } finally { clearTimeout(timer); }
  }

  // render returns the element to show (null: a known, empty list). reload
  // returns a new load() result; the retry button replaces the element.
  function render(doc, result, reload) {
    const box = doc.createElement('details');
    box.className = 'summary';
    const sum = doc.createElement('summary');
    box.appendChild(sum);
    if (!result.ok) {
      box.open = true;
      sum.textContent = 'Tool output files: state unknown';
      sum.style.color = '#f85149';
      const msg = doc.createElement('div');
      msg.textContent = 'Could not read the file list (' + result.error + '). This does not mean there are no files.';
      const btn = doc.createElement('button');
      btn.type = 'button';
      btn.textContent = 'Try again';
      btn.onclick = async () => {
        btn.disabled = true;
        const next = render(doc, await reload(), reload);
        if (next) box.replaceWith(next);
        else box.replaceWith(doc.createElement('div'));
      };
      box.appendChild(msg);
      box.appendChild(btn);
      return box;
    }
    const arts = result.items;
    if (!arts.length) return null;
    const c = classify(arts);
    if (c.problems) box.open = true;
    sum.textContent = summaryText(arts);
    if (c.problems) sum.style.color = '#f85149';
    for (const a of arts) {
      const row = doc.createElement('div');
      row.style.margin = '6px 0';
      const head = doc.createElement('div');
      head.textContent = '#' + a.cmd_index + ' ' + a.tool + ': ' + (LABEL[a.state] || a.state) + (a.cleanup_pending ? ' · plaintext copy waiting for deletion' : '');
      if (problem(a)) head.style.color = '#f85149';
      const det = doc.createElement('div');
      det.className = 'det';
      det.style.fontSize = '11px';
      det.textContent = [a.detail, a.cleanup_detail, a.path].filter(Boolean).join(' · ');
      row.appendChild(head);
      row.appendChild(det);
      box.appendChild(row);
    }
    return box;
  }

  global.pentrailArtifacts = {load, render, summaryText, classify};
})(window);
