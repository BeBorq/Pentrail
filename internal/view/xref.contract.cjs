// Contract between xref.js and internal/store/graph.go, on real API replies
// (written by TestTimelineGraphCrossReference): every extracted entity maps to
// an existing graph element, and every graph element gets the commands it was
// found in, starting with its own provenance.
const fs = require('node:fs'), vm = require('node:vm'), path = require('node:path'), assert = require('node:assert/strict');
const dir = process.argv[2];
const read = n => JSON.parse(fs.readFileSync(path.join(dir, n), 'utf8'));
const ctx = { setTimeout, clearTimeout, AbortController }; vm.createContext(ctx);
vm.runInContext(fs.readFileSync(path.join(__dirname, 'xref.js'), 'utf8'), ctx);
const X = ctx.pentrailXref, graph = read('graph.json'), ents = read('entities.json'), cmds = read('commands.json');
const ids = new Set(graph.nodes.map(n => n.id)), byId = new Map(graph.nodes.map(n => [n.id, n]));
assert.ok(ents.length >= 10 && graph.nodes.length >= 9, 'synthetic data missing');
for (const e of ents) {
  const r = X.nodeIds(e);
  assert.ok(r.ids.some(id => ids.has(id)), `entity ${e.type} ${e.value} has no graph element (tried ${JSON.stringify(r.ids)})`);
  for (const id of r.implied) assert.ok(ids.has(id), `implied element ${id} missing`);
}
const index = X.commandIndex(ents, graph.edges), known = new Set(cmds.map(c => c.index));
for (const n of graph.nodes) {
  const list = X.commandsOf(n, index);
  assert.ok(list.length > 0, `no command for ${n.id}`);
  assert.equal(list[0] <= n.cmd_index, true, `own provenance of ${n.id} not first`);
  for (const i of list) assert.ok(known.has(i), `command #${i} of ${n.id} not in /api/commands`);
}
// Exact expectations (cmd:how) from the Go test, including a host name seen
// with a different address per command, a repeated relationship, canonical
// aliases and a standalone spelling.
const expected = read('expected.json');
for (const [id, want] of Object.entries(expected))
  assert.equal(JSON.stringify(X.commandsOf(byId.get(id) || { id }, index)), JSON.stringify(want.map(w => Number(w.split(':')[0]))), 'commands of ' + id);
for (const [id, want] of Object.entries(expected)) {
  assert.ok(byId.has(id), `precondition: element ${id} missing from /api/graph`);
  assert.equal(JSON.stringify(X.provenanceOf(byId.get(id), index).map(p => p.cmd + ':' + p.how)), JSON.stringify(want), id);
}
// Every extracted (entity, command) pair is a "recorded" command of its own element.
for (const e of ents) {
  if (!(e.cmd_index >= 0)) continue;
  const own = X.nodeIds(e).ids.filter(id => ids.has(id));
  for (const id of own) assert.ok(X.provenanceOf(byId.get(id), index).some(p => p.cmd === e.cmd_index && p.how === 'recorded'), `${id} lost recorded command #${e.cmd_index}`);
}
const rot = graph.edges.filter(g => g.source === 'hostname:rotating.example.test').map(g => g.target + '@' + g.cmd_index).sort();
assert.equal(JSON.stringify(rot), '["host:192.0.2.1@0","host:192.0.2.2@2"]', 'precondition: the store keeps both resolutions');
const stable = graph.edges.filter(g => g.source === 'hostname:stable.example.test').map(g => g.cmd_index);
assert.equal(JSON.stringify(stable), '[0]', 'precondition: the repeated relationship is one edge with the first command');
assert.ok(graph.edges.some(g => g.source === 'port:[2001:DB8:0:0::1]:443/tcp' && g.target === 'host:2001:db8::1'), 'precondition: the store links the other IPv6 spelling');
// The canonical host form, against Go's netip (canonicalGraphHost).
for (const [h, want] of Object.entries(read('canonical.json'))) assert.equal(X.canonicalHost(h), want, 'canonicalHost(' + h + ')');
console.log(`PASS xref contract ${ents.length} entities, ${graph.nodes.length} elements`);
