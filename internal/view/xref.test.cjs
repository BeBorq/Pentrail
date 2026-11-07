// Runs the real xref.js (served to the page) in node.
const fs = require('node:fs'), vm = require('node:vm'), path = require('node:path'), assert = require('node:assert/strict');
const ctx = { setTimeout, clearTimeout, AbortController };
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(path.join(__dirname, 'xref.js'), 'utf8'), ctx);
const X = ctx.pentrailXref;
const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const results = [];
async function check(name, fn) { try { await fn(); results.push(['PASS', name]); } catch (e) { results.push(['FAIL', name, String(e.message).split('\n')[0]]); } }
const same = (a, b, m) => assert.equal(JSON.stringify(a), JSON.stringify(b), m);

(async () => {
  await check('X1 entity → graph node ids follow internal/store/graph.go', () => {
    same(X.nodeIds({ type: 'host', value: '10.0.0.1' }).ids, ['host:10.0.0.1']);
    same(X.nodeIds({ type: 'port', value: '10.0.0.1:22/tcp', details: '{"host":"10.0.0.1"}' }), { ids: ['port:10.0.0.1:22/tcp'], implied: ['host:10.0.0.1'] });
    same(X.nodeIds({ type: 'hostname', value: 'www.x', details: { host: '10.0.0.2' } }).implied, ['host:10.0.0.2']);
    same(X.nodeIds({ type: 'domain', value: 'x.test' }).ids, ['domain:x.test', 'hostname:x.test'], 'a domain may be shown as a host name');
    same(X.nodeIds({ type: 'url', value: 'https://a/b' }).ids, ['url:https://a/b']);
    same(X.nodeIds({ type: 'finding', value: 'CVE-1', details: '{"template":"t","host":"h","matched":"m"}' }).ids, ['finding:CVE-1\x1ft\x1fh\x1fm']);
    same(X.nodeIds({ type: 'finding', value: 'CVE-1' }).ids, ['finding:CVE-1\x1f\x1f\x1f']);
    same(X.nodeIds({ type: 'unknown', value: 'x' }).ids, []);
    same(X.nodeIds({ type: 'port', value: 'p', details: '{broken' }).implied, [], 'broken details must not throw');
  });

  await check('X2 commands of an element: every command it was found in, own provenance included, sorted, no unknown index', () => {
    const idx = X.commandIndex([
      { type: 'host', value: 'h', cmd_index: 4 }, { type: 'host', value: 'h', cmd_index: 1 }, { type: 'host', value: 'h', cmd_index: 4 },
      { type: 'port', value: 'h:22', cmd_index: 2, details: '{"host":"h"}' }, { type: 'host', value: 'x', cmd_index: -1 }]);
    same(X.commandsOf({ id: 'host:h', cmd_index: 1 }, idx), [1, 2, 4]);
    same(X.commandsOf({ id: 'host:h', cmd_index: 0 }, idx), [0, 1, 2, 4], 'own provenance missing from the list');
    same(X.commandsOf({ id: 'host:x', cmd_index: -1 }, idx), []);
    same(X.commandsOf({ id: 'host:none', cmd_index: null }, idx), []);
  });

  const cmd = { index: 3, command: 'nmap -sV <target> && echo "done"', cwd: '/tmp/a&b', started_ms: 1, ended_ms: 2, exit_code: 0, complete: true, out_start_off: 100, out_end_off: 160 };
  const h = { esc, time: ms => 'T' + ms, dur: () => '1s', bytes: n => n + ' B', clean: s => s.replace(/\x1b\[[0-9;]*m/g, '') };

  await check('X3 a command is shown in two explicit parts: typed by the user / printed by the terminal, escaped', () => {
    const html = X.commandHTML(cmd, h, { state: 'ok', text: '\x1b[32mopen\x1b[0m <port>', missing: 0, truncated: false });
    assert.match(html, /<details class="sec user" open><summary>Command — typed by the user<\/summary><pre class="typed">nmap -sV &lt;target&gt; &amp;&amp; echo &quot;done&quot;<\/pre>/);
    assert.match(html, /<summary>Terminal output — printed by the programs · 60 B<\/summary><pre class="output">open &lt;port&gt;<\/pre>/);
    assert.ok(html.indexOf('typed by the user') < html.indexOf('printed by the programs'), 'order');
    assert.match(html, /in \/tmp\/a&amp;b/);
    assert.match(html, /class="badge ok"[^>]*>0</);
    assert.doesNotMatch(html, /<target>|undefined|NaN/);
  });

  await check('X4 output states: loading, none, error, missing bytes, preview of a longer output, unknown end', () => {
    assert.match(X.commandHTML(cmd, h), /loading…/);
    assert.match(X.commandHTML({ ...cmd, out_end_off: 100 }, h), /\(no output\)/);
    assert.match(X.commandHTML(cmd, h, { state: 'error', error: 'connection error' }), /Could not read the output \(connection error\)/);
    assert.match(X.commandHTML(cmd, h, { state: 'ok', text: 'x', missing: 7 }), /7 B missing in the raw log — the text below is NOT complete/);
    assert.match(X.commandHTML(cmd, h, { state: 'ok', text: 'x', truncated: true }), /preview: the beginning of the output/);
    assert.match(X.commandHTML({ ...cmd, command: '' }, h), /\(no command text recorded\)/);
    assert.match(X.commandHTML({ ...cmd, end_reason: 'session_end' }, h), /class="badge wait" title="end not observed: the session ended while it ran, exit code unknown"/);
    assert.match(X.commandHTML(cmd, { ...h, openOutput: true }), /<details class="sec term" open/);
  });

  await check('X5 the preview loads at most the limit, reports missing bytes, truncation and errors', async () => {
    let url = '';
    const ok = await X.loadOutput(async u => { url = u; return { ok: true, status: 200, headers: { get: k => k === 'X-Missing-Bytes' ? '5' : null }, text: async () => 'abc' }; }, 9, cmd, 16);
    assert.equal(url, '/api/output?session=9&start=100&end=116');
    same([ok.ok, ok.text, ok.missing, ok.truncated], [true, 'abc', 5, true]);
    const full = await X.loadOutput(async () => ({ ok: true, headers: { get: () => null }, text: async () => '' }), 9, cmd, 1000);
    assert.equal(full.truncated, false);
    const bad = await X.loadOutput(async () => ({ ok: false, status: 500 }), 9, cmd, 16);
    same([bad.ok, bad.error], [false, 'the viewer reported an error, code 500']);
    const down = await X.loadOutput(async () => { throw new Error('x'); }, 9, cmd, 16);
    assert.equal(down.error, 'connection error');
    const none = await X.loadOutput(async () => { throw new Error('must not fetch'); }, 9, { ...cmd, out_end_off: 100 }, 16);
    same([none.ok, none.text], [true, '']);
  });

  await check('X6 a relationship the graph resolved to an equivalent spelling counts for its target', () => {
    const ents = [{ type: 'host', value: '2001:db8::1', cmd_index: 0 },
      { type: 'port', value: '[2001:DB8:0:0::1]:443/tcp', cmd_index: 3, details: '{"host":"2001:DB8:0:0::1"}' }];
    const edges = [{ source: 'port:[2001:DB8:0:0::1]:443/tcp', target: 'host:2001:db8::1', type: 'on' }];
    same(X.commandsOf({ id: 'host:2001:db8::1', cmd_index: 0 }, X.commandIndex(ents)), [0], 'precondition: without edges the later command is lost');
    const idx = X.commandIndex(ents, edges);
    same(X.commandsOf({ id: 'host:2001:db8::1', cmd_index: 0 }, idx), [0, 3]);
    same(X.commandsOf({ id: 'host:2001:DB8:0:0::1', cmd_index: 3 }, idx), [3], 'the element with its own spelling keeps its command');
    same(X.commandsOf({ id: 'port:[2001:DB8:0:0::1]:443/tcp', cmd_index: 3 }, idx), [3]);
  });

  const prov = (idx, id, own) => JSON.stringify(X.provenanceOf({ id, cmd_index: own }, idx).map(p => p.cmd + ':' + p.how));

  await check('X7 a host name observed with a different host per command credits each host only with its own command', () => {
    const ents = [{ type: 'hostname', value: 'rotating.example.test', cmd_index: 0, details: '{"host":"192.0.2.1"}' },
      { type: 'hostname', value: 'rotating.example.test', cmd_index: 2, details: '{"host":"192.0.2.2"}' }];
    const edges = [{ source: 'hostname:rotating.example.test', target: 'host:192.0.2.1', type: 'resolves', cmd_index: 0 },
      { source: 'hostname:rotating.example.test', target: 'host:192.0.2.2', type: 'resolves', cmd_index: 2 }];
    const idx = X.commandIndex(ents, edges);
    same(X.commandsOf({ id: 'host:192.0.2.1', cmd_index: 0 }, idx), [0], 'the first host was credited with the command that saw the second');
    same(X.commandsOf({ id: 'host:192.0.2.2', cmd_index: 2 }, idx), [2], 'the second host was credited with the command that saw the first');
    assert.equal(prov(idx, 'host:192.0.2.1', 0), '["0:related"]');
    assert.equal(prov(idx, 'host:192.0.2.2', 2), '["2:related"]');
    assert.equal(prov(idx, 'hostname:rotating.example.test', 0), '["0:recorded","2:recorded"]');
  });

  await check('X8 the same relationship observed again in later commands keeps every command, though the graph edge keeps only the first', () => {
    const ents = [0, 1, 2].map(c => ({ type: 'hostname', value: 'stable.example.test', cmd_index: c, details: '{"host":"192.0.2.10"}' }))
      .concat([{ type: 'port', value: '192.0.2.10:22/tcp', cmd_index: 1, details: '{"host":"192.0.2.10"}' }, { type: 'host', value: '192.0.2.10', cmd_index: 2 }]);
    const edges = [{ source: 'hostname:stable.example.test', target: 'host:192.0.2.10', type: 'resolves', cmd_index: 0 },
      { source: 'port:192.0.2.10:22/tcp', target: 'host:192.0.2.10', type: 'on', cmd_index: 1 }];
    const idx = X.commandIndex(ents, edges);
    assert.equal(prov(idx, 'host:192.0.2.10', 2), '["0:related","1:related","2:recorded"]');
  });

  await check('X9 canonical aliases are credited per observation; a standalone different spelling stays its own element', () => {
    const ents = [{ type: 'host', value: '2001:db8::1', cmd_index: 0 }, { type: 'host', value: '2001:DB8::0:1', cmd_index: 1 },
      { type: 'port', value: '[2001:DB8:0:0::1]:443/tcp', cmd_index: 2, details: '{"host":"2001:DB8:0:0::1"}' },
      { type: 'hostname', value: 'Mail.Example.Test', cmd_index: 0, details: '{"host":"192.0.2.3"}' },
      { type: 'url', value: 'https://user@MAIL.EXAMPLE.TEST.:8443/login', cmd_index: 2 },
      { type: 'email', value: 'ops@mail.example.test.', cmd_index: 1 }];
    const edges = [{ source: 'port:[2001:DB8:0:0::1]:443/tcp', target: 'host:2001:db8::1', type: 'on', cmd_index: 2 },
      { source: 'hostname:Mail.Example.Test', target: 'host:192.0.2.3', type: 'resolves', cmd_index: 0 },
      { source: 'url:https://user@MAIL.EXAMPLE.TEST.:8443/login', target: 'hostname:Mail.Example.Test', type: 'on', cmd_index: 2 },
      { source: 'email:ops@mail.example.test.', target: 'hostname:Mail.Example.Test', type: 'at', cmd_index: 1 }];
    const idx = X.commandIndex(ents, edges);
    assert.equal(prov(idx, 'host:2001:db8::1', 0), '["0:recorded","2:related"]');
    assert.equal(prov(idx, 'host:2001:DB8::0:1', 1), '["1:recorded"]', 'a standalone spelling borrowed commands');
    assert.equal(prov(idx, 'host:2001:DB8:0:0::1', 2), '["2:related"]');
    assert.equal(prov(idx, 'hostname:Mail.Example.Test', 0), '["0:recorded","1:related","2:related"]');
    assert.equal(prov(idx, 'host:192.0.2.3', 0), '["0:related"]', 'a URL of the host name credited the host behind it');
  });

  await check('X10 canonicalHost matches Go netip / canonicalGraphHost on IPv4, IPv6, embedded IPv4, zones and DNS names', () => {
    const cases = { '192.0.2.1': '192.0.2.1', '01.2.3.4': '01.2.3.4', '2001:DB8:0:0::1': '2001:db8::1', '2001:db8:0:0:1:0:0:1': '2001:db8::1:0:0:1',
      '1:0:0:1:0:0:0:1': '1:0:0:1::1', '::FFFF:C000:0201': '::ffff:192.0.2.1', '::1.2.3.4': '::102:304', 'fe80::1%Eth0': 'fe80::1%Eth0',
      '1:2:3:4:5:6:7:8': '1:2:3:4:5:6:7:8', '::': '::', 'WWW.Example.TEST.': 'www.example.test', '1.2.3.4%x': '1.2.3.4%x', '1::2::3': '1::2::3' };
    for (const [k, v] of Object.entries(cases)) assert.equal(X.canonicalHost(k), v, k);
    assert.equal(X.urlHost('https://u:p@[2001:DB8::1%25eth0]:8443/x'), '2001:DB8::1%eth0');
    assert.equal(X.urlHost('https://WWW.Example.TEST./login?a=1'), 'WWW.Example.TEST.');
  });

  for (const r of results) console.log(r.join(' | '));
  if (results.some(r => r[0] !== 'PASS')) process.exitCode = 1;
  else console.log('PASS xref ' + results.length);
})();
