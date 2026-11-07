// Cross-references between the timeline (commands and their output) and the
// graph (entities). Pure functions only: the page supplies fetch and the DOM.
//
// Node identifiers follow internal/store/graph.go: "<type>:<value>", a
// finding uses its value, template, host and matched location. A port or a
// host name with a "host" detail also names that host (the graph creates the
// host node from it), so the host is listed as mentioned by that command too.
//
// Two kinds of command per element:
//  - recorded: the element's own value was extracted from that command;
//  - related: an element extracted from that command names it through a
//    relationship (a port "on" it, a host name that "resolves" to it, a URL
//    "on" it, an e-mail "at" it, a finding that "affects" it).
// A related command is credited per OBSERVATION: the entity row's own host
// reference (details.host, the URL's host, the e-mail's domain) selects the
// graph edge of that row's element whose target is the same host. The graph
// links relationships to an existing equivalent spelling of a host (IPv6
// notation, DNS letter case, trailing dot: canonicalGraphHost in
// internal/store/graph.go), so the comparison uses the same canonical form.
// Graph edges are deduplicated and keep only their first command; they are
// used to find the target, never to limit which commands are credited.
(function (global) {
  const TYPES = ['host', 'port', 'hostname', 'domain', 'url', 'endpoint', 'email', 'finding'];

  function parse(details) {
    if (details && typeof details === 'object') return details;
    try { const d = details ? JSON.parse(details) : {}; return d && typeof d === 'object' ? d : {}; } catch (e) { return {}; }
  }

  // Candidate graph node ids for one extracted entity: the first existing
  // candidate is the node itself ("domain" may have become a host name).
  // `implied` are other nodes the same output line names.
  function nodeIds(entity) {
    const type = String(entity.type || ''), value = String(entity.value == null ? '' : entity.value), det = parse(entity.details);
    if (!TYPES.includes(type)) return { ids: [], implied: [] };
    const implied = (type === 'port' || type === 'hostname') && det.host ? ['host:' + det.host] : [];
    if (type === 'finding') return { ids: ['finding:' + value + '\x1f' + (det.template || '') + '\x1f' + (det.host || '') + '\x1f' + (det.matched || '')], implied };
    if (type === 'domain') return { ids: ['domain:' + value, 'hostname:' + value], implied };
    return { ids: [type + ':' + value], implied };
  }

  // canonicalGraphHost (internal/store/graph.go): an IP address in the form
  // Go's netip.Addr.String() prints; anything else lower-cased without one
  // trailing dot. Scoped (zone) addresses keep the zone's spelling.
  function canonicalHost(h) {
    h = String(h);
    const v4 = s => { const p = s.split('.'); if (p.length !== 4) return null; const b = [];
      for (const x of p) { if (!/^(0|[1-9][0-9]{0,2})$/.test(x) || +x > 255) return null; b.push(+x); } return b; };
    if (v4(h)) return h;
    const v6 = (() => {
      let s = h, zone = '';
      const z = s.indexOf('%'); if (z >= 0) { zone = s.slice(z); s = s.slice(0, z); if (zone.length < 2) return null; }
      if (!s.includes(':')) return null;
      // an embedded IPv4 tail becomes two hex groups
      const lastColon = s.lastIndexOf(':'), last = s.slice(lastColon + 1);
      if (last.includes('.')) { const b = v4(last); if (!b) return null;
        s = s.slice(0, lastColon + 1) + ((b[0] << 8) | b[1]).toString(16) + ':' + ((b[2] << 8) | b[3]).toString(16); }
      const halves = s.split('::'); if (halves.length > 2) return null;
      const grp = part => part === '' ? [] : part.split(':');
      const head = grp(halves[0]), back = halves.length === 2 ? grp(halves[1]) : [];
      for (const g of head.concat(back)) if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
      const n = head.length + back.length;
      if (halves.length === 2 ? n > 7 : n !== 8) return null;
      const words = head.map(g => parseInt(g, 16)).concat(Array(8 - n).fill(0), back.map(g => parseInt(g, 16)));
      if (words.slice(0, 5).every(w => w === 0) && words[5] === 0xffff)
        return '::ffff:' + [words[6] >> 8, words[6] & 255, words[7] >> 8, words[7] & 255].join('.') + zone;
      let best = -1, len = 0;
      for (let i = 0; i < 8;) { if (words[i]) { i++; continue; } let j = i; while (j < 8 && !words[j]) j++; if (j - i > len && j - i >= 2) { best = i; len = j - i; } i = j; }
      const hex = w => w.toString(16);
      const out = best < 0 ? words.map(hex).join(':') : words.slice(0, best).map(hex).join(':') + '::' + words.slice(best + len).map(hex).join(':');
      return out + zone;
    })();
    if (v6) return v6;
    return h.toLowerCase().replace(/\.$/, '');
  }

  // urlHost (internal/store/graph.go): the host of a URL, without port,
  // brackets or user information; '' when there is none.
  function urlHost(u) {
    u = String(u);
    let rest = u.includes('://') ? u.slice(u.indexOf('://') + 3) : u.startsWith('//') ? u.slice(2) : u;
    rest = rest.split(/[/?#]/)[0];
    const at = rest.lastIndexOf('@'); if (at >= 0) rest = rest.slice(at + 1);
    if (rest.startsWith('[')) { const end = rest.indexOf(']'); return end > 0 ? rest.slice(1, end).replace('%25', '%') : ''; }
    const colon = rest.indexOf(':'); return colon >= 0 ? rest.slice(0, colon) : rest;
  }

  // The relationship one observation draws, as BuildGraph pass 2 does:
  // [edge type, host reference] or null.
  function reference(entity) {
    const type = String(entity.type || ''), value = String(entity.value == null ? '' : entity.value), det = parse(entity.details);
    if ((type === 'port' || type === 'hostname' || type === 'finding') && det.host) return [type === 'port' ? 'on' : type === 'hostname' ? 'resolves' : 'affects', String(det.host)];
    if (type === 'url' || type === 'endpoint') { const h = urlHost(value); return h ? ['on', h] : null; }
    if (type === 'email') { const at = value.lastIndexOf('@'); return at >= 0 && at + 1 < value.length ? ['at', value.slice(at + 1)] : null; }
    return null;
  }
  const hostValue = id => { const m = /^(host|hostname|domain):/.exec(id); return m ? id.slice(m[0].length) : null; };

  // nodeId -> sorted command indexes (recorded and related); `how` on the
  // result: nodeId -> Map(command -> 'recorded' | 'related').
  function commandIndex(entities, edges) {
    const how = new Map(), out = new Map(), bySource = new Map();
    const add = (id, cmd, kind) => { if (!how.has(id)) how.set(id, new Map()); const m = how.get(id); if (m.get(cmd) !== 'recorded') m.set(cmd, kind); };
    for (const e of edges || []) { if (!bySource.has(e.source)) bySource.set(e.source, []); bySource.get(e.source).push(e); }
    for (const e of entities || []) {
      const cmd = e.cmd_index; // null/undefined is "unknown", not command 0
      if (typeof cmd !== 'number' || !Number.isSafeInteger(cmd) || cmd < 0) continue;
      const r = nodeIds(e);
      for (const id of r.ids) add(id, cmd, 'recorded');
      // the host node BuildGraph creates from this row's own spelling
      for (const id of r.implied) add(id, cmd, 'related');
      // the edge of this row's element to the host this row names
      const ref = reference(e);
      if (!ref) continue;
      const want = canonicalHost(ref[1]);
      for (const id of r.ids) for (const g of bySource.get(id) || []) {
        const v = hostValue(g.target);
        if (g.type === ref[0] && v !== null && canonicalHost(v) === want) add(g.target, cmd, 'related');
      }
    }
    for (const [id, m] of how) out.set(id, [...m.keys()].sort((a, b) => a - b));
    out.how = how;
    return out;
  }

  // [{cmd, how}] of a graph node, sorted. The node's own provenance
  // (cmd_index) is included even when the entity list lacks it; it is
  // "recorded" unless the rows show it came from a related element.
  function provenanceOf(node, index) {
    const m = new Map((index && index.how && index.how.get(node.id)) || []);
    const own = node.cmd_index;
    if (typeof own === 'number' && Number.isSafeInteger(own) && own >= 0 && !m.has(own)) m.set(own, 'recorded');
    return [...m].map(([cmd, how]) => ({ cmd, how })).sort((a, b) => a.cmd - b.cmd);
  }

  // Commands of a graph node: every command it was found in; the node's own
  // provenance (cmd_index) is included even when the entity list lacks it.
  function commandsOf(node, index) {
    const list = (index && index.get(node.id)) || [];
    const own = node.cmd_index;
    if (typeof own === 'number' && Number.isSafeInteger(own) && own >= 0 && !list.includes(own)) return [own, ...list].sort((a, b) => a - b);
    return list.slice();
  }

  const END = {
    session_end: 'end not observed: the session ended while it ran',
    recording_paused: 'end not observed: recording was paused while it ran',
    capture_interrupted: 'end not observed: capture was interrupted',
  };
  function status(c) {
    if (c.end_reason) return { cls: 'wait', text: '?', title: (END[c.end_reason] || 'end not observed (' + c.end_reason + ')') + ', exit code unknown' };
    if (!c.complete) return { cls: 'wait', text: '…', title: 'still running or not finished' };
    return c.exit_code === 0 ? { cls: 'ok', text: '0', title: 'exit code 0' } : { cls: 'bad', text: String(c.exit_code), title: 'exit code ' + c.exit_code };
  }

  // The two explicit parts of a command: what the user typed and what the
  // terminal printed. The output is loaded on demand (data-* attributes).
  // `out` (optional): {state:'loading'|'ok'|'error', text, missing, truncated, error};
  // h.openOutput opens the output part.
  function commandHTML(c, h, out) {
    const esc = h.esc, bytes = Math.max(0, (c.out_end_off || 0) - (c.out_start_off || 0)), st = status(c);
    const typed = c.command ? `<pre class="typed">${esc(String(c.command))}</pre>` : '<pre class="typed"><span class="none">(no command text recorded)</span></pre>';
    const meta = [c.cwd ? 'in ' + esc(String(c.cwd)) : '', h.time ? 'started ' + h.time(c.started_ms) : '', h.dur ? 'took ' + h.dur(c.started_ms, c.ended_ms) : ''].filter(Boolean).join(' · ');
    return `<div class="xcmd" data-cmd="${c.index}">` +
      `<div class="xhead"><span class="badge ${st.cls}" title="${esc(st.title)}">${esc(st.text)}</span><span>command #${c.index}</span></div>` +
      `<details class="sec user" open><summary>Command — typed by the user</summary>${typed}${meta ? `<div class="xmeta">${meta}</div>` : ''}</details>` +
      `<details class="sec term"${h.openOutput ? ' open' : ''} data-start="${c.out_start_off}" data-end="${c.out_end_off}"><summary>Terminal output — printed by the programs · ${h.bytes ? h.bytes(bytes) : bytes + ' B'}</summary>` +
      outputHTML(bytes, out, h) + `</details>` +
      `</div>`;
  }

  function outputHTML(bytes, out, h) {
    const esc = h.esc;
    if (bytes <= 0) return '<pre class="output"><span class="none">(no output)</span></pre>';
    if (!out || out.state === 'loading') return '<pre class="output"><span class="none">loading…</span></pre>';
    if (out.state === 'error') return `<div class="gapwarn">Could not read the output (${esc(out.error || 'error')}).</div>`;
    const warn = out.missing > 0 ? `<div class="gapwarn">⚠ Incomplete output: ${out.missing} B missing in the raw log — the text below is NOT complete</div>` : '';
    const text = h.clean ? h.clean(out.text) : out.text;
    const more = out.truncated ? '<div class="xmeta">preview: the beginning of the output — open the command in the timeline for all of it</div>' : '';
    return warn + (text ? `<pre class="output">${esc(text)}</pre>` : '<pre class="output"><span class="none">(only control characters)</span></pre>') + more;
  }

  // Load at most `limit` bytes of a command's output for a preview. Never
  // rejects and always settles: the request and its body are bounded together
  // by timeoutMs (default 15 s). A failure carries kind/status so the page can
  // explain it (connection, HTTP status, timeout, invalid response).
  async function loadOutput(fetch, session, c, limit, timeoutMs) {
    const start = c.out_start_off, end = Math.min(c.out_end_off, start + limit);
    if (!(end > start)) return { text: '', missing: 0, truncated: false, ok: true };
    const ms = timeoutMs || 15000;
    const ctl = typeof AbortController === 'function' ? new AbortController() : null;
    let timer;
    const timeout = new Promise(res => { timer = setTimeout(() => { res({ ok: false, kind: 'timeout', ms, error: 'the request timed out' }); try { ctl && ctl.abort(); } catch (e) { /* done */ } }, ms); });
    const work = (async () => {
      let r;
      try { r = await fetch(`/api/output?session=${session}&start=${start}&end=${end}`, ctl ? { signal: ctl.signal } : undefined); }
      catch (e) { return { ok: false, kind: 'network', error: 'connection error' }; }
      if (!r || !r.ok) return { ok: false, kind: 'http', status: r ? r.status : 0, error: 'the viewer reported an error, code ' + (r ? r.status : 0) };
      const missing = parseInt((r.headers && r.headers.get && r.headers.get('X-Missing-Bytes')) || '0', 10) || 0;
      let text;
      try { text = await r.text(); } catch (e) { return { ok: false, kind: 'network', error: 'connection error' }; }
      if (typeof text !== 'string') return { ok: false, kind: 'invalid', error: 'invalid response' };
      return { ok: true, text, missing, truncated: end < c.out_end_off };
    })();
    try { return await Promise.race([work, timeout]); } finally { clearTimeout(timer); }
  }

  global.pentrailXref = { nodeIds, commandIndex, commandsOf, provenanceOf, canonicalHost, urlHost, commandHTML, loadOutput, status };
})(typeof window !== 'undefined' ? window : globalThis);
