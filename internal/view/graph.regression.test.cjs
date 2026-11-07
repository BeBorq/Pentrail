// Reproductions for the 04BC review of graph.js. Each case asserts the CORRECT
// behaviour; run against a directory: node repro.test.cjs <dir-with-graph.js>
const fs = require('node:fs'), vm = require('node:vm'), path = require('node:path'), assert = require('node:assert/strict');
const dir = process.argv[2];
const src = fs.readFileSync(path.join(dir, 'graph.js'), 'utf8');

function harness(opts = {}) {
  const calls = { clearRect: 0, fillText: [], arcs: [], raf: 0 };
  const ctx = new Proxy({}, { get(_, k) {
    return (...a) => { if (k === 'arc') calls.arcs.push(a); else if (k === 'clearRect') calls.clearRect++; else if (k === 'fillText') calls.fillText.push(a[0]); };
  }, set() { return true; } });
  const listeners = new Map();
  let ro = null, raf = null;
  const window = { devicePixelRatio: 1, addEventListener: (k, fn) => listeners.set(k, fn), removeEventListener: (k) => listeners.delete(k) };
  const env = { window, ResizeObserver: class { constructor(cb) { ro = cb; } observe() {} disconnect() {} },
    requestAnimationFrame: fn => { raf = fn; calls.raf++; }, Set, Map, Math };
  vm.runInNewContext(src, env);
  let rect = opts.rect || { width: 800, height: 600 };
  // Attributes are stored like on a real <canvas>, so accessibility state can be asserted.
  const attrs = new Map();
  const canvas = { style: {}, width: 0, height: 0, getContext: () => ctx, getBoundingClientRect: () => rect,
    setAttribute: (k, v) => attrs.set(k, String(v)), getAttribute: k => attrs.has(k) ? attrs.get(k) : null,
    removeAttribute: k => attrs.delete(k), hasAttribute: k => attrs.has(k) };
  return { window, canvas, calls, listeners, setRect: r => { rect = r; }, resizeObserver: () => ro && ro(),
    raf: () => { const f = raf; raf = null; f && f(); }, pending: () => raf !== null };
}
const nodesOf = (n, f = i => ({ id: 'n' + i, label: 'n' + i, type: 'host', cmd_index: i })) => Array.from({ length: n }, (_, i) => f(i));
const results = [];
function check(name, fn) {
  try { fn(); results.push(['PASS', name]); } catch (e) { results.push(['FAIL', name, String(e && e.message || e).split('\n')[0].slice(0, 160)]); if (process.env.DEBUG) console.error(e); }
}

check('R1 abnormal label (null / number) does not throw and does not stop the render loop', () => {
  const h = harness();
  h.window.initGraph(h.canvas, { nodes: [{ id: 'a', label: null, cmd_index: 0 }, { id: 'b', label: 42, cmd_index: 1 }], edges: [{ source: 'a', target: 'b' }] }, () => {});
  for (let i = 0; i < 5; i++) h.raf();
});

check('R1b focus route on a node with a missing label does not throw', () => {
  const h = harness();
  const g = h.window.initGraph(h.canvas, { nodes: [{ id: 'a', cmd_index: 0 }], edges: [] }, () => {});
  g.toggleRoute('a');
});

check('R2 an idle graph stops requesting animation frames (no endless 60 fps redraw)', () => {
  const h = harness();
  h.window.initGraph(h.canvas, { nodes: nodesOf(8), edges: [] }, () => {});
  for (let i = 0; i < 600 && h.pending(); i++) h.raf();
  assert.equal(h.pending(), false, 'still scheduling frames after 600 idle frames');
});

check('R3 destroy clears the canvas (an empty session must not show the previous graph)', () => {
  const h = harness();
  const g = h.window.initGraph(h.canvas, { nodes: nodesOf(3), edges: [] }, () => {});
  h.raf();
  const before = h.calls.clearRect;
  g.destroy();
  assert.ok(h.calls.clearRect > before, 'no clearRect on destroy');
});

check('R4 a devicePixelRatio change is applied on resize (sharp canvas after moving to a HiDPI screen)', () => {
  const h = harness();
  h.window.initGraph(h.canvas, { nodes: nodesOf(2), edges: [] }, () => {});
  h.window.devicePixelRatio = 2;
  h.resizeObserver();
  assert.equal(h.canvas.width, 1600);
});

check('R5 toggleRoute(B) while A is focused focuses B instead of only resetting', () => {
  const h = harness();
  const g = h.window.initGraph(h.canvas, { nodes: nodesOf(4), edges: [{ source: 'n0', target: 'n1' }, { source: 'n2', target: 'n3' }] }, () => {});
  g.toggleRoute('n0');
  g.toggleRoute('n2');
  assert.deepEqual(g.getVisibleIds().sort(), ['n2', 'n3']);
});

check('R6 a selected node hidden by a focused route is deselected (detail panel not left on a hidden node)', () => {
  const h = harness();
  const sel = [];
  const g = h.window.initGraph(h.canvas, { nodes: nodesOf(3), edges: [{ source: 'n0', target: 'n1' }] }, n => sel.push(n && n.id));
  h.raf();
  const p = h.calls.arcs[2]; // n2
  h.canvas.onmousedown({ offsetX: p[0], offsetY: p[1] });
  h.listeners.get('mouseup')();
  assert.equal(sel.at(-1), 'n2');
  g.toggleRoute('n0');
  assert.equal(sel.at(-1), null, 'n2 is hidden but still selected');
});

check('R7 a graph first shown in a hidden tab (0×0) is fitted when it becomes visible', () => {
  const h = harness({ rect: { width: 0, height: 0 } });
  h.window.initGraph(h.canvas, { nodes: nodesOf(3), edges: [] }, () => {});
  h.setRect({ width: 800, height: 600 });
  h.resizeObserver();
  h.calls.fillText = [];
  h.raf();
  assert.ok(h.calls.fillText.includes('n0'), 'node labels not drawn: the view stayed at the 0×0 fit (scale 0.2)');
});

check('R8 long session: band labels outside the viewport are not drawn every frame', () => {
  const h = harness();
  h.window.initGraph(h.canvas, { nodes: nodesOf(3000), edges: [] }, () => {});
  h.calls.fillText = [];
  h.raf();
  const bandLabels = h.calls.fillText.filter(t => typeof t === 'string' && t.startsWith('Command #')).length;
  assert.ok(bandLabels < 50, `${bandLabels} band labels drawn for a 600 px viewport`);
});

check('R9 long session: 400 settling frames of 3000 nodes in one command stay under 2 s', () => {
  const h = harness();
  const t0 = Date.now();
  h.window.initGraph(h.canvas, { nodes: nodesOf(3000, i => ({ id: 'n' + i, label: 'n' + i, cmd_index: 0 })), edges: [] }, () => {});
  for (let i = 0; i < 400 && h.pending(); i++) h.raf();
  const ms = Date.now() - t0;
  assert.ok(ms < 2000, `${ms} ms`);
});

check('R10 the canvas label follows the visible count and destroy does not leave the previous graph described', () => {
  const h = harness();
  const nodes = nodesOf(8);
  const edges = [{ source: 'n0', target: 'n1' }, { source: 'n1', target: 'n2' }, { source: 'n2', target: 'n3' }, { source: 'n3', target: 'n4' }];
  const g = h.window.initGraph(h.canvas, { nodes, edges }, () => {});
  assert.match(h.canvas.getAttribute('aria-label'), /: 8 of 8 elements$/);
  g.toggleRoute('n2');
  assert.match(h.canvas.getAttribute('aria-label'), /: 5 of 8 elements; paths through n2$/);
  g.resetRoute();
  assert.match(h.canvas.getAttribute('aria-label'), /: 8 of 8 elements$/);
  g.destroy();
  const label = h.canvas.getAttribute('aria-label') || '';
  assert.ok(!/\d+ of \d+/.test(label), `after destroy the label still describes the old graph: "${label}"`);
  assert.match(label, /^Relationship graph: /);
});


// ---- 04BE: layout, emphasis, keyboard, touch ----
const pentest = () => ({ nodes: [
    { id: 'h1', label: '10.0.0.1', type: 'host', cmd_index: 0 }, { id: 'h2', label: '10.0.0.2', type: 'host', cmd_index: 0 },
    { id: 'p1', label: '10.0.0.1:22', type: 'port', cmd_index: 0 }, { id: 'p2', label: '10.0.0.2:80', type: 'port', cmd_index: 0 },
    { id: 'p3', label: '10.0.0.1:443', type: 'port', cmd_index: 0 }, { id: 'lone', label: 'lone', type: 'domain', cmd_index: 0 },
    { id: 'u1', label: 'https://www.example.test/a/very/long/path/to/backup.zip', type: 'url', cmd_index: 1 }],
  // As internal/store/graph.go: the dependent element points to the one it belongs to.
  edges: [{ source: 'p1', target: 'h1', type: 'on' }, { source: 'p2', target: 'h2', type: 'on' }, { source: 'p3', target: 'h1', type: 'on' }, { source: 'u1', target: 'p2', type: 'serves' }] });
// Force one frame (a frame is drawn only after a change); a resize notification is a change.
const redraw = h => { h.resizeObserver(); h.raf(); };

check('R11 entities related within one command stay together: a parent above its indented children, unrelated ones after them', () => {
  const h = harness();
  const L = h.window.pentrailTimelineLayout(pentest());
  const P = id => L.positions.get(id);
  assert.equal(P('p1').x, P('p3').x, 'children of one parent share a column');
  assert.ok(P('p1').x > P('h1').x && P('p1').x - P('h1').x < 60, 'children are indented under their parent');
  assert.ok(P('h1').y < P('p1').y && P('p1').y < P('p3').y, 'parent first, children below in order');
  assert.ok(Math.abs(P('h2').x - P('h1').x) >= 200, 'separate groups get separate columns');
  assert.ok(P('lone').y > Math.max(P('p1').y, P('p3').y, P('p2').y), 'unrelated entities follow the groups');
  assert.equal(L.parent.get('p1'), 'h1'); assert.equal(L.parent.get('u1'), undefined, 'an edge across commands is not a tree connector');
  assert.ok(P('u1').y > P('lone').y, 'chronology between commands is kept');
  assert.equal(JSON.stringify(L.bands.map(b => [b.command, b.count])), '[[0,6],[1,1]]');
});

check('R12 a long outline continues in the next column without a connector to a parent in another column', () => {
  const h = harness();
  const nodes = [{ id: 'r', cmd_index: 0 }, ...Array.from({ length: 30 }, (_, i) => ({ id: 'c' + i, cmd_index: 0 }))];
  const L = h.window.pentrailTimelineLayout({ nodes, edges: nodes.slice(1).map(n => ({ source: n.id, target: 'r' })) });
  const xs = new Set(nodes.map(n => L.positions.get(n.id).x - (n.id === 'r' ? 0 : 22)));
  assert.ok(xs.size >= 3, 'not split into columns');
  const far = nodes.slice(1).filter(n => L.positions.get(n.id).x - 22 !== L.positions.get('r').x);
  assert.ok(far.length > 0 && far.every(n => !L.parent.has(n.id)), 'a child in another column keeps a tree connector');
  assert.equal(new Set(nodes.map(n => { const p = L.positions.get(n.id); return p.x + ',' + p.y; })).size, nodes.length);
});

// Screen position of each node = its arc in one frame (nodes are drawn in data order;
// call only without a selection or hover, which add rings, and with all nodes on screen).
function nodePoints(h, ids) { h.calls.arcs = []; redraw(h); const body = h.calls.arcs.filter(a => a[2] <= 12); const m = new Map(); ids.forEach((id, i) => m.set(id, body[i])); return m; }

check('R13 hovering an element shows the type of its relationships only; others are not labelled at overview zoom', () => {
  const h = harness();
  const d = pentest();
  h.window.initGraph(h.canvas, d, () => {});
  for (let i = 0; i < 400 && h.pending(); i++) h.raf();
  h.calls.fillText = []; redraw(h);
  assert.ok(!h.calls.fillText.includes('on'), 'relationship types drawn without hover');
  const pts = nodePoints(h, d.nodes.map(n => n.id)), p = pts.get('h1');
  h.calls.fillText = []; h.canvas.onmousemove({ offsetX: p[0], offsetY: p[1] }); h.raf();
  assert.ok(h.calls.fillText.length > 0, 'no frame drawn after hover');
  assert.equal(h.calls.fillText.filter(t => t === 'on').length, 2, 'the two relationships of h1 are labelled');
  assert.ok(!h.calls.fillText.includes('serves'), 'an unrelated relationship is labelled');
});

check('R14 a long label keeps its beginning and end; the hovered element shows it in full', () => {
  const h = harness();
  const d = pentest();
  h.window.initGraph(h.canvas, d, () => {});
  for (let i = 0; i < 400 && h.pending(); i++) h.raf();
  const pts = nodePoints(h, d.nodes.map(n => n.id));
  h.calls.fillText = []; redraw(h);
  const short = h.calls.fillText.find(t => typeof t === 'string' && t.startsWith('https://') && t.includes('…'));
  assert.ok(short && short.endsWith('backup.zip'), `shortened label lost its end: ${short}`);
  const u = pts.get('u1'); h.calls.fillText = []; h.canvas.onmousemove({ offsetX: u[0], offsetY: u[1] }); h.raf();
  assert.ok(h.calls.fillText.includes(d.nodes[6].label), 'hovered label not shown in full');
});

check('R15 keyboard: arrows select along the row first, Escape clears the selection, + / - zoom, 0 fits, Shift+arrow pans', () => {
  const h = harness();
  const sel = [];
  h.window.initGraph(h.canvas, pentest(), n => sel.push(n && n.id));
  for (let i = 0; i < 400 && h.pending(); i++) h.raf();
  const key = (k, shift) => h.canvas.onkeydown({ key: k, shiftKey: !!shift, preventDefault() {} });
  key('ArrowDown'); assert.equal(sel.at(-1), 'h1', 'first element is the top-left one');
  key('ArrowRight'); assert.equal(sel.at(-1), 'h2', 'right must prefer the next element in the row over an indented child');
  key('ArrowDown'); assert.equal(sel.at(-1), 'p2');
  key('Escape'); assert.equal(sel.at(-1), null, 'Escape without a route must clear the selection');
  const ids = ['h1', 'h2'];
  let pts = nodePoints(h, ids); const d0 = pts.get('h2')[0] - pts.get('h1')[0];
  key('+'); pts = nodePoints(h, ids); assert.ok(pts.get('h2')[0] - pts.get('h1')[0] > d0 * 1.1, 'zoom in');
  key('-'); key('-'); pts = nodePoints(h, ids); assert.ok(pts.get('h2')[0] - pts.get('h1')[0] < d0, 'zoom out');
  const before = pts.get('h1'); key('ArrowLeft', true); pts = nodePoints(h, ids); assert.ok(Math.abs(pts.get('h1')[0] - before[0] - 80) < 0.01, 'Shift+Left pans the view right by 80 px');
  key('0'); pts = nodePoints(h, ['h1', 'h2', 'p1', 'p2', 'p3', 'lone', 'u1']);
  for (const [, p] of pts) assert.ok(p[0] >= 0 && p[0] <= 800 && p[1] >= 0 && p[1] <= 600, 'fit leaves an element outside the view');
});

check('R16 select(): selects and reveals an element, select(null) clears, an element hidden by a route is not selected', () => {
  const h = harness();
  const sel = [];
  const g = h.window.initGraph(h.canvas, { nodes: nodesOf(40), edges: [{ source: 'n0', target: 'n1' }] }, n => sel.push(n && n.id));
  g.select('n39'); assert.equal(sel.at(-1), 'n39');
  h.calls.arcs = []; redraw(h);
  const ring = h.calls.arcs.find(a => a[2] === 9 + 3 + 5); // the selection ring around the selected host
  assert.ok(ring && ring[1] > 0 && ring[1] < 600 && ring[0] > 0 && ring[0] < 800, 'the selected element was not scrolled into view');
  g.select(null); assert.equal(sel.at(-1), null);
  g.toggleRoute('n0'); g.select('n5'); assert.equal(sel.at(-1), null, 'a hidden element was selected');
});

check('R17 touch: tap selects, a pan or pinch from the background keeps the selection, a tap on the background clears it, double tap filters, pinch zooms', () => {
  const h = harness();
  const sel = [];
  const d = pentest();
  const g = h.window.initGraph(h.canvas, d, n => sel.push(n && n.id));
  for (let i = 0; i < 400 && h.pending(); i++) h.raf();
  const ev = (id, x, y) => ({ pointerType: 'touch', pointerId: id, clientX: x, clientY: y, preventDefault() {} });
  let pts = nodePoints(h, d.nodes.map(n => n.id)); const p = pts.get('h1');
  h.canvas.onpointerdown(ev(1, p[0], p[1])); h.canvas.onpointerup(ev(1, p[0], p[1]));
  assert.equal(sel.at(-1), 'h1', 'tap did not select');
  // pan from the background keeps the selection
  h.canvas.onpointerdown(ev(2, 790, 590)); h.canvas.onpointermove(ev(2, 740, 560)); h.canvas.onpointerup(ev(2, 740, 560));
  assert.equal(sel.at(-1), 'h1', 'a pan cleared the selection');
  pts = nodePoints(h, ['h1']); assert.ok(Math.abs(pts.get('h1')[0] - (p[0] - 50)) < 0.01, 'one-finger pan did not move the view');
  // pinch from the background
  const a = pts.get('h1'); const two = nodePoints(h, ['h1', 'h2']); const d0 = two.get('h2')[0] - two.get('h1')[0];
  const mx = (two.get('h1')[0] + two.get('h2')[0]) / 2, my = two.get('h1')[1] - 20; // between the hosts, on the background
  h.canvas.onpointerdown(ev(3, mx - 50, my)); h.canvas.onpointerdown(ev(4, mx + 50, my));
  h.canvas.onpointermove(ev(3, mx - 80, my)); h.canvas.onpointermove(ev(4, mx + 80, my)); h.canvas.onpointerup(ev(3, mx - 80, my)); h.canvas.onpointerup(ev(4, mx + 80, my));
  assert.equal(sel.at(-1), 'h1', 'a pinch cleared the selection');
  const z = nodePoints(h, ['h1', 'h2']); assert.ok(z.get('h2')[0] - z.get('h1')[0] > d0 * 1.5, 'pinch did not zoom in');
  // tap on the background clears
  h.canvas.onpointerdown(ev(5, 795, 595)); h.canvas.onpointerup(ev(5, 795, 595));
  assert.equal(sel.at(-1), null, 'a tap on the background did not clear the selection');
  // double tap on an element filters its paths, and the emulated dblclick that may follow is ignored
  const q = nodePoints(h, ['h1', 'h2']).get('h2');
  for (const id of [6, 7]) { h.canvas.onpointerdown(ev(id, q[0], q[1])); h.canvas.onpointerup(ev(id, q[0], q[1])); }
  assert.match(h.canvas.getAttribute('aria-label'), /3 of 7 elements; paths through 10\.0\.0\.2$/);
  h.canvas.ondblclick({ offsetX: q[0], offsetY: q[1] });
  assert.match(h.canvas.getAttribute('aria-label'), /3 of 7 elements/, 'the emulated dblclick undid the double tap');
  g.destroy(); assert.equal(h.canvas.onpointerdown, null);
});

for (const r of results) console.log(r.join(' | '));
process.exitCode = results.some(r => r[0] === 'FAIL') ? 1 : 0;
