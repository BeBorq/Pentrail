// Self-contained chronological graph on a canvas. No external libraries, so the
// viewer stays fully offline — nothing leaves the machine. Renders typed nodes
// and directed, labelled edges; click a node to surface its provenance.
(function (global) {
  const COLORS = {
    host: "#58a6ff", port: "#3fb950", hostname: "#56d4bb", domain: "#8b949e",
    url: "#a371f7", endpoint: "#db61a2", email: "#d29922", finding: "#f85149",
  };
  const R = { host: 9, port: 7, finding: 8 }; // base radius per type (default 6)
  const BG = "#0d1117", FONT = "11px ui-monospace,monospace";
  // Layout grid inside a command band (world units).
  const COL_W = 290, ROW_H = 46, INDENT = 22, MAX_DEPTH = 3, MAX_COLS = 5, MAX_ROWS = 12, GRID_COLS = 5;

  // All directed routes through root: ancestors plus descendants, excluding siblings.
  function routeNodes(data, root) {
    const ids=new Set(data.nodes.map(n=>n.id));
    if(!ids.has(root)) return new Set();
    const forward=new Map(),reverse=new Map();
    for(const e of data.edges){if(!ids.has(e.source)||!ids.has(e.target))continue;
      if(!forward.has(e.source))forward.set(e.source,[]);if(!reverse.has(e.target))reverse.set(e.target,[]);
      forward.get(e.source).push(e.target);reverse.get(e.target).push(e.source);
    }
    const walk=adj=>{const seen=new Set([root]),queue=[root];for(let i=0;i<queue.length;i++)for(const id of adj.get(queue[i])||[])if(!seen.has(id)){seen.add(id);queue.push(id);}return seen;};
    return new Set([...walk(forward),...walk(reverse)]);
  }

  // Bands use the earliest recorded provenance, not edge direction: relationships
  // can point backwards in time. No synthetic chronology for unknown commands.
  // Inside a band, related entities are kept together: every group of entities
  // connected within the band becomes an outline (a parent, its children indented
  // below it). Groups are ordered by the position of their relations in earlier
  // bands, so lines between commands cross less. Unrelated entities follow in a
  // grid. `parent` records the outline edges, which are drawn as tree connectors.
  // Relationships in this graph point from the dependent element to the one it
  // belongs to (a port "on" a host, a URL "on" a host, a finding "affects" a
  // host), so the target of an edge is the parent in the outline.
  function timelineLayout(data) {
    const nodes=data.nodes,byId=new Map(nodes.map(n=>[n.id,n]));
    const first=new Map(nodes.map(n=>[n.id,Number.isSafeInteger(n.cmd_index)&&n.cmd_index>=0?n.cmd_index:null]));
    for(const e of data.edges) if(Number.isSafeInteger(e.cmd_index)&&e.cmd_index>=0)
      for(const id of [e.source,e.target]) if(first.has(id)&&(first.get(id)===null||e.cmd_index<first.get(id)))first.set(id,e.cmd_index);
    const out=new Map(),nbr=new Map();
    for(const e of data.edges){if(!byId.has(e.source)||!byId.has(e.target)||e.source===e.target)continue;
      if(!out.has(e.target))out.set(e.target,[]);out.get(e.target).push(e.source); // parent -> children
      for(const [a,b] of [[e.source,e.target],[e.target,e.source]]){if(!nbr.has(a))nbr.set(a,[]);nbr.get(a).push(b);}
    }
    const groups=new Map();
    for(const n of nodes){const key=first.get(n.id);if(!groups.has(key))groups.set(key,[]);groups.get(key).push(n);}
    const keys=[...groups.keys()].sort((a,b)=>a===null?1:b===null?-1:a-b);
    const positions=new Map(),parent=new Map(),bands=[];let top=0;
    for(const key of keys){
      const list=groups.get(key),inBand=new Set(list.map(n=>n.id)),indeg=new Map();
      for(const n of list)for(const t of out.get(n.id)||[])if(inBand.has(t))indeg.set(t,(indeg.get(t)||0)+1);
      const assigned=new Set(),clusters=[];
      // Depth-first outline from a root; each entity is placed once.
      const grow=root=>{const rows=[],stack=[{id:root.id,depth:0}];assigned.add(root.id);
        while(stack.length){const cur=stack.pop();rows.push({n:byId.get(cur.id),depth:cur.depth});
          const kids=(out.get(cur.id)||[]).filter(t=>inBand.has(t)&&!assigned.has(t));
          for(const t of kids){assigned.add(t);parent.set(t,cur.id);}
          for(let i=kids.length-1;i>=0;i--)stack.push({id:kids[i],depth:Math.min(cur.depth+1,MAX_DEPTH)});}
        return rows;};
      for(const n of list)if(!assigned.has(n.id)&&!indeg.get(n.id))clusters.push(grow(n));
      for(const n of list)if(!assigned.has(n.id))clusters.push(grow(n)); // cycles
      // Barycentre of already placed relations (earlier bands); stable otherwise.
      const bary=rows=>{let s=0,c=0;for(const r of rows)for(const m of nbr.get(r.n.id)||[])if(positions.has(m)){s+=positions.get(m).x;c++;}return c?s/c:null;};
      const order=arr=>arr.map((rows,i)=>({rows,i,b:bary(rows)})).sort((a,b)=>a.b===null&&b.b===null?a.i-b.i:a.b===null?1:b.b===null?-1:a.b-b.b||a.i-b.i).map(o=>o.rows);
      const multi=order(clusters.filter(c=>c.length>1)),single=order(clusters.filter(c=>c.length===1)).map(c=>c[0]);
      // A long outline continues in the next column; a parent in another column
      // is then drawn with an ordinary curve, not a tree connector.
      const columns=[];for(const rows of multi)for(let i=0;i<rows.length;i+=MAX_ROWS){const col=rows.slice(i,i+MAX_ROWS),ids=new Set(col.map(r=>r.n.id));
        for(const r of col)if(parent.has(r.n.id)&&!ids.has(parent.get(r.n.id)))parent.delete(r.n.id);columns.push(col);}
      let y=top+60;
      for(let s=0;s<columns.length;s+=MAX_COLS){const shelf=columns.slice(s,s+MAX_COLS);
        shelf.forEach((col,ci)=>{const x=(ci-(shelf.length-1)/2)*COL_W;col.forEach((r,ri)=>positions.set(r.n.id,{x:x+r.depth*INDENT,y:y+ri*ROW_H}));});
        y+=Math.max(...shelf.map(c=>c.length))*ROW_H+18;}
      const gc=Math.min(GRID_COLS,single.length);
      single.forEach((r,i)=>positions.set(r.n.id,{x:(i%gc-(gc-1)/2)*COL_W,y:y+Math.floor(i/gc)*ROW_H}));
      if(single.length)y+=Math.ceil(single.length/gc)*ROW_H;
      const height=Math.max(y-top,60+ROW_H)+10;
      bands.push({command:key,top,height,count:list.length,label:key===null?'No assigned command':`Command #${key}`});
      top+=height+36;
    }
    const center=top/2;for(const p of positions.values())p.y-=center;
    for(const band of bands)band.top-=center;
    return {positions,bands,parent};
  }

  // Long labels keep their start and end (a URL keeps its path).
  function shorten(s,n){if(s.length<=n)return s;const head=Math.ceil((n-1)*0.4),tail=n-1-head;return s.slice(0,head)+"\u2026"+(tail>0?s.slice(-tail):"");}

  function initGraph(canvas, data, onSelect, onRoute) {
    const ctx = canvas.getContext("2d");
    let W = 0, H = 0, dpr = Math.max(1, global.devicePixelRatio || 1);
    // Metadata may be missing or not a string (older stores, parser gaps): the
    // drawing code needs strings, and one bad label must not stop the view.
    const text = v => v == null ? '' : String(v);
    const nodes = data.nodes.map(n => ({ ...n, label: text(n.label != null ? n.label : n.id), type: text(n.type), x: 0, y: 0, vx: 0, vy: 0 }));
    const index = Object.create(null); nodes.forEach((n, i) => index[n.id] = i);
    const edges = data.edges.filter(e => index[e.source] != null && index[e.target] != null);

    let routeRoot=null, visible=null, savedView=null;
    const shown=id=>!visible||visible.has(id);
    function resetRoute(){routeRoot=null;visible=null;if(savedView){({scale,ox,oy}=savedView);savedView=null;}notifyRoute();invalidate();}
    function notifyRoute(){const root=nodes.find(n=>n.id===routeRoot);const count=visible?visible.size:nodes.length;
      canvas.setAttribute('aria-label',`Relationship graph: ${count} of ${nodes.length} elements${root?'; paths through '+root.label:''}`);
      onRoute&&onRoute({root:routeRoot,label:root?root.label:'',visible:count,total:nodes.length});}
    // Same root again (or Escape) restores; another root switches the focus and
    // keeps the view saved before the first focus.
    function toggleRoute(id){if(routeRoot===id){resetRoute();return;}const set=routeNodes(data,id);if(!set.size)return;if(!savedView)savedView={scale,ox,oy};visible=set;routeRoot=id;hover=null;cool=0;
      if(selected!==null&&!set.has(selected)){selected=null;onSelect&&onSelect(null);}
      fitTo(nodes.filter(n=>visible.has(n.id)),1.4);notifyRoute();invalidate();}
    function fitTo(list,maxScale){if(!list.length)return;let minX=Infinity,maxX=-Infinity,minY=Infinity,maxY=-Infinity;
      for(const n of list){minX=Math.min(minX,n.x-15);maxX=Math.max(maxX,n.x+Math.min(240,n.label.length*6)+15);minY=Math.min(minY,n.y-15);maxY=Math.max(maxY,n.y+15);}
      scale=Math.min(maxScale,Math.max(0.2,Math.min((W-70)/Math.max(80,maxX-minX),(H-100)/Math.max(80,maxY-minY))));
      ox=-(minX+maxX)*scale/2;oy=-(minY+maxY)*scale/2;}
    // view transform
    let scale = 1, ox = 0, oy = 0;
    let selected = null, hover = null, dragNode = null, panning = false, lastX = 0, lastY = 0;

    let viewTouched = false; // the user (or a route focus) has set the view
    function resize() {
      const rect = canvas.getBoundingClientRect();
      const wasEmpty = W <= 0 || H <= 0;
      W = rect.width; H = rect.height;
      dpr = Math.max(1, global.devicePixelRatio || 1); // moved to another screen / browser zoom
      canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      // Rendered while hidden (0×0): fit once it gets a size, unless the user moved the view.
      if (wasEmpty && W > 0 && H > 0 && !viewTouched && !routeRoot) fitStart();
      invalidate();
    }

    const layout=timelineLayout(data);
    const bands=layout.bands, treeParent=layout.parent;
    nodes.forEach(nd=>{const p=layout.positions.get(nd.id);nd.x=nd.homeX=p.x;nd.y=nd.homeY=p.y;nd.pinned=false;});

    // Gentle horizontal separation inside a chronological row. Time coordinates
    // remain stable; user-positioned nodes are pinned until this view is rebuilt.
    // Only nodes whose y differs by at most 40 interact: bucket by y (40 px) and
    // compare neighbouring buckets — the same pairs as all-pairs, without O(n²).
    function step() {
      const rows=new Map();
      for(const nd of nodes){const k=Math.floor(nd.y/40);if(!rows.has(k))rows.set(k,[]);rows.get(k).push(nd);}
      const push=(a,b)=>{if(Math.abs(a.y-b.y)>40)return;const dx=a.x-b.x,dist=Math.abs(dx);if(dist<250){const p=(250-dist)*0.015*(dx<0?-1:1);a.vx+=p;b.vx-=p;}};
      for(const [k,row] of rows){
        for(let i=0;i<row.length;i++)for(let j=i+1;j<row.length;j++)push(row[i],row[j]);
        const next=rows.get(k+1);if(next)for(const a of row)for(const b of next)push(a,b);
      }
      let moving=false;
      for(const nd of nodes){
        if(nd===dragNode||nd.pinned){nd.vx=nd.vy=0;continue;}
        nd.vx+=(nd.homeX-nd.x)*0.04;nd.vx*=0.75;nd.x+=nd.vx;nd.y=nd.homeY;
        if(Math.abs(nd.vx)>0.01)moving=true;
      }
      if(!moving&&!dragNode)cool=0; // settled: stop stepping (and drawing)
    }

    function world(px, py) { return { x: (px - ox - W / 2) / scale, y: (py - oy - H / 2) / scale }; }
    function screen(x, y) { return { x: x * scale + ox + W / 2, y: y * scale + oy + H / 2 }; }

    function radius(nd) { return (R[nd.type] || 6) + (nd.id === selected ? 3 : 0); }

    function nodeAt(px, py, slop = 4) {
      for (let i = nodes.length - 1; i >= 0; i--) {
        if(!shown(nodes[i].id))continue;
        const s = screen(nodes[i].x, nodes[i].y);
        const r = radius(nodes[i]) + slop;
        if ((px - s.x) ** 2 + (py - s.y) ** 2 <= r * r) return nodes[i];
      }
      return null;
    }

    function pill(t, x, y, color) {
      ctx.font = "10px ui-monospace,monospace";
      const m = ctx.measureText(t), w = (m && m.width) || t.length * 6;
      ctx.fillStyle = BG; ctx.globalAlpha = 0.9; ctx.fillRect(x - w / 2 - 3, y - 8, w + 6, 12); ctx.globalAlpha = 1;
      ctx.fillStyle = color; ctx.fillText(t, x - w / 2, y + 1);
    }
    function arrow(tipX, tipY, ux, uy) {
      ctx.beginPath(); ctx.moveTo(tipX, tipY);
      ctx.lineTo(tipX - ux * 7 - uy * 3.5, tipY - uy * 7 + ux * 3.5); ctx.lineTo(tipX - ux * 7 + uy * 3.5, tipY - uy * 7 - ux * 3.5);
      ctx.closePath(); ctx.fill();
    }

    function draw() {
      ctx.clearRect(0, 0, W, H);
      // The hovered (else selected) element and its direct relations are
      // emphasised; everything else is dimmed, not hidden.
      const focus = hover ? hover.id : selected;
      const near = focus ? new Set([focus]) : null;
      if (near) for (const e of edges) { if (e.source === focus) near.add(e.target); else if (e.target === focus) near.add(e.source); }
      // Chronological lanes; the label of a band stays at the top while its
      // band is on screen, so the current command is always named.
      bands.forEach((band, i) => {
        const y = screen(0, band.top).y, h = band.height * scale;
        if (y + h < 0 || y > H) return; // outside the viewport (long sessions)
        if (i % 2) { ctx.fillStyle = "rgba(255,255,255,0.018)"; ctx.fillRect(0, y, W, h); }
        const ly = Math.max(y, Math.min(0, y + h - 26));
        if (y < 0) { ctx.fillStyle = BG; ctx.globalAlpha = 0.85; ctx.fillRect(0, ly, W, 26); ctx.globalAlpha = 1; }
        ctx.fillStyle = "#8b949e"; ctx.font = FONT;
        ctx.fillText(`${band.label} · ${band.count} ${band.count === 1 ? 'element' : 'elements'}`, 18, ly + 17);
        ctx.strokeStyle = "#21262d"; ctx.lineWidth = 1; ctx.beginPath(); ctx.moveTo(16, ly + 26); ctx.lineTo(W - 16, ly + 26); ctx.stroke();
      });
      // edges: outline (parent → child in the same command) as tree connectors,
      // everything else as curves leaving and entering vertically.
      const labels = [];
      for (const e of edges) {
        if(!shown(e.source)||!shown(e.target))continue;
        const sn = nodes[index[e.source]], tn = nodes[index[e.target]];
        const a = screen(sn.x, sn.y), b = screen(tn.x, tn.y);
        const on = focus && (e.source === focus || e.target === focus);
        ctx.globalAlpha = near && !on ? 0.15 : 1;
        ctx.strokeStyle = ctx.fillStyle = on ? "#58a6ff" : "#3d444d";
        ctx.lineWidth = on ? 1.6 : 1;
        const rb = radius(tn) + 3;
        let lx, ly;
        // A connector only while the child is still below and to the right of
        // its parent; after the user drags either one, an ordinary curve. The
        // arrow keeps the relationship's direction (usually child -> parent).
        const up = treeParent.get(e.source) === e.target, down = treeParent.get(e.target) === e.source;
        const P = up ? b : a, C = up ? a : b, pn = up ? tn : sn, cn = up ? sn : tn;
        if ((up || down) && C.y > P.y + 4 && C.x >= P.x + 4) {
          const rp = radius(pn), rc = radius(cn) + 3;
          ctx.beginPath(); ctx.moveTo(P.x, P.y + rp + (up ? 3 : 0)); ctx.lineTo(P.x, C.y); ctx.lineTo(C.x - rc, C.y); ctx.stroke();
          if (down && C.x - P.x > rc + 6) arrow(C.x - rc, C.y, 1, 0);
          if (up && C.y - P.y > rp + 12) arrow(P.x, P.y + rp + 3, 0, -1);
          lx = P.x - 8 - text(e.type).length * 3; ly = C.y + 3; // left of the connector corner
        } else {
          const dy = b.y - a.y, k = Math.abs(dy) < 1 ? 40 : Math.max(30, Math.abs(dy) * 0.45) * Math.sign(dy);
          const c2x = b.x, c2y = b.y - k;
          ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.bezierCurveTo(a.x, a.y + k, c2x, c2y, b.x, b.y); ctx.stroke();
          const tx = b.x - c2x, ty = b.y - c2y, d = Math.hypot(tx, ty);
          if (d > 0 && Math.hypot(b.x - a.x, b.y - a.y) > 25) arrow(b.x - tx / d * rb, b.y - ty / d * rb, tx / d, ty / d);
          lx = 0.125 * a.x + 0.375 * a.x + 0.375 * c2x + 0.125 * b.x; ly = 0.125 * a.y + 0.375 * (a.y + k) + 0.375 * c2y + 0.125 * b.y;
        }
        ctx.globalAlpha = 1;
        if ((on || (!near && scale >= 1.3)) && text(e.type)) labels.push([text(e.type), lx, ly, on ? "#c9d1d9" : "#8b949e"]);
      }
      ctx.lineWidth = 1;
      for (const l of labels) pill(...l); // under the element labels
      // nodes. Labels are shortened to the space before the next column at
      // this zoom; the hovered and the selected element show their full label
      // on top of everything else.
      const room = Math.max(6, Math.min(40, Math.floor((COL_W * scale - 26) / 6.6)));
      const front = [];
      for (const nd of nodes) {
        if(!shown(nd.id))continue;
        const s = screen(nd.x, nd.y);
        if (s.x < -300 || s.x > W + 40 || s.y < -30 || s.y > H + 30) continue; // off screen
        const r = radius(nd);
        const col = COLORS[nd.type] || "#c9d1d9";
        const dim = near && !near.has(nd.id);
        ctx.beginPath(); ctx.arc(s.x, s.y, r, 0, Math.PI * 2);
        ctx.fillStyle = col; ctx.globalAlpha = (nd.confidence === "high" ? 1 : 0.55) * (dim ? 0.25 : 1);
        ctx.fill();
        if (nd.confidence !== "high") { ctx.lineWidth = 1; ctx.strokeStyle = col; ctx.setLineDash([2, 2]); ctx.stroke(); ctx.setLineDash([]); }
        ctx.globalAlpha = 1;
        if (nd.id === selected || nd === hover) {
          ctx.lineWidth = 2; ctx.strokeStyle = "#e6edf3"; ctx.stroke();
          if (nd.id === selected) { ctx.beginPath(); ctx.arc(s.x, s.y, r + 5, 0, Math.PI * 2); ctx.lineWidth = 1.5; ctx.strokeStyle = "#58a6ff"; ctx.stroke(); }
          ctx.lineWidth = 1;
        }
        if (nd.id === selected || nd === hover) front.push([shorten(nd.label, 80), s.x + r + 4, s.y + 4, "#ffffff"]);
        else if (scale > 0.6) {
          ctx.globalAlpha = dim ? 0.35 : 1; nodeLabel(shorten(nd.label, room), s.x + r + 4, s.y + 4, "#c9d1d9"); ctx.globalAlpha = 1;
        }
      }
      for (const l of front) nodeLabel(...l);
    }
    function nodeLabel(t, x, y, color) {
      ctx.font = FONT; ctx.lineWidth = 3; ctx.strokeStyle = BG; ctx.strokeText(t, x, y); // halo over lines
      ctx.fillStyle = color; ctx.fillText(t, x, y); ctx.lineWidth = 1;
    }

    // Frames are drawn on demand: while the layout settles and after a change
    // (input, resize, focus) — not 60 times a second while nothing changes.
    let alive = true, cool = 400, scheduled = false;
    function invalidate() { if (alive && !scheduled) { scheduled = true; requestAnimationFrame(frame); } }
    function frame() {
      scheduled = false;
      if (!alive) return;
      if (cool > 0) { step(); cool--; }
      draw();
      if (cool > 0) invalidate();
    }

    function select(id, reveal) {
      const nd = id == null ? null : nodes[index[id]];
      if (id != null && (!nd || !shown(nd.id))) return false; // unknown or hidden by a route
      selected = nd ? nd.id : null; onSelect && onSelect(nd || null);
      if (nd && reveal) {
        const s = screen(nd.x, nd.y), m = 60;
        if (s.x < m || s.x > W - m || s.y < m || s.y > H - m) { ox += W / 2 - s.x; oy += H * 0.35 - s.y; viewTouched = true; } // upper part: the details may cover the lower part on small screens
      }
      invalidate();
      return true;
    }

    // interaction (mouse; touch below)
    function down(x, y, slop, keepSelection) {
      const nd = nodeAt(x, y, slop);
      if (nd) { dragNode = nd; selected = nd.id; onSelect && onSelect(nd); cool = Math.max(cool, 120); }
      else { panning = true; if (!keepSelection) { selected = null; onSelect && onSelect(null); } }
      lastX = x; lastY = y; invalidate();
    }
    function move(x, y) {
      const was = hover;
      hover = dragNode || panning ? hover : nodeAt(x, y);
      if (hover !== was || dragNode || panning) invalidate();
      canvas.style.cursor = dragNode ? "grabbing" : hover ? "pointer" : (panning ? "grabbing" : "grab");
      if (dragNode) { const w = world(x, y); dragNode.x = w.x; dragNode.y = w.y; dragNode.pinned = true; cool = Math.max(cool, 60); }
      else if (panning) { ox += x - lastX; oy += y - lastY; viewTouched = true; }
      lastX = x; lastY = y;
    }
    function zoomAt(x, y, next) {
      next = Math.min(3, Math.max(0.2, next)); const f = next / scale;
      const mx = x - ox - W / 2, my = y - oy - H / 2;
      ox -= mx * (f - 1); oy -= my * (f - 1); scale = next; viewTouched = true; invalidate();
    }
    function dbl(x, y) { const nd = nodeAt(x, y); if (nd) toggleRoute(nd.id); else if (routeRoot) resetRoute(); }
    canvas.onmousedown = (e) => down(e.offsetX, e.offsetY);
    canvas.onmousemove = (e) => move(e.offsetX, e.offsetY);
    canvas.onmouseleave = () => { if (hover && !dragNode) { hover = null; invalidate(); } };
    const mouseUp=()=>{if(dragNode||panning)invalidate();dragNode=null;panning=false;};
    window.addEventListener("mouseup", mouseUp);
    let touchDbl = 0;
    canvas.ondblclick=e=>{if(Date.now()-touchDbl<700)return;dbl(e.offsetX,e.offsetY);};
    canvas.onwheel = (e) => { e.preventDefault(); zoomAt(e.offsetX, e.offsetY, scale * (e.deltaY < 0 ? 1.1 : 0.9)); };

    // Touch: one finger drags an element or the view, two fingers pinch-zoom,
    // a double tap filters paths like a double click. preventDefault on the
    // pointerdown suppresses the emulated mouse events.
    const touches = new Map(); let pinch = null, lastTap = null, tapStart = null;
    const pt = e => { const r = canvas.getBoundingClientRect(); return { x: e.clientX - (r.left || 0), y: e.clientY - (r.top || 0) }; };
    canvas.onpointerdown = e => {
      if (e.pointerType !== "touch") return;
      e.preventDefault(); try { canvas.setPointerCapture && canvas.setPointerCapture(e.pointerId); } catch (_) {}
      const p = pt(e); touches.set(e.pointerId, p);
      if (touches.size === 1) {
        const now = Date.now();
        if (lastTap && now - lastTap.t < 350 && Math.hypot(p.x - lastTap.x, p.y - lastTap.y) < 30) { touchDbl = now; lastTap = null; dbl(p.x, p.y); return; }
        // On the background the selection is cleared only by a tap, not by
        // the first finger of a pan or pinch.
        lastTap = { t: now, x: p.x, y: p.y }; tapStart = { x: p.x, y: p.y, moved: false }; down(p.x, p.y, 12, true);
      } else if (touches.size === 2) {
        dragNode = null; panning = false; lastTap = null; if (tapStart) tapStart.moved = true;
        const [a, b] = [...touches.values()];
        pinch = { d: Math.hypot(a.x - b.x, a.y - b.y) || 1, s: scale, mx: (a.x + b.x) / 2, my: (a.y + b.y) / 2 };
      }
    };
    canvas.onpointermove = e => {
      if (e.pointerType !== "touch" || !touches.has(e.pointerId)) return;
      const p = pt(e); touches.set(e.pointerId, p);
      if (tapStart && Math.hypot(p.x - tapStart.x, p.y - tapStart.y) > 8) tapStart.moved = true;
      if (pinch && touches.size >= 2) {
        const [a, b] = [...touches.values()], mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
        ox += mx - pinch.mx; oy += my - pinch.my; pinch.mx = mx; pinch.my = my;
        zoomAt(mx, my, pinch.s * Math.hypot(a.x - b.x, a.y - b.y) / pinch.d);
      } else if (!pinch) move(p.x, p.y);
    };
    canvas.onpointerup = canvas.onpointercancel = e => {
      if (!touches.delete(e.pointerId)) return;
      if (!touches.size) {
        if (tapStart && !tapStart.moved && panning && selected != null) { selected = null; onSelect && onSelect(null); }
        tapStart = null; pinch = null; hover = null; mouseUp();
      }
    };

    // Keyboard: arrows select the nearest element in that direction,
    // Shift+arrows pan, + / - zoom, 0 fits, Enter filters paths, Escape restores.
    canvas.tabIndex=0;
    const DIRS = { ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1] };
    function nearest(dx, dy) {
      const list = nodes.filter(n => shown(n.id));
      const cur = selected != null ? nodes[index[selected]] : null;
      if (!cur) return list.slice().sort((a, b) => a.y - b.y || a.x - b.x)[0] || null;
      // Prefer elements within 45° of the direction; otherwise the nearest one
      // that lies in that direction at all.
      let best = null, bestScore = Infinity, wide = null, wideScore = Infinity;
      for (const n of list) { if (n === cur) continue;
        const vx = n.x - cur.x, vy = n.y - cur.y, along = vx * dx + vy * dy; if (along <= 1) continue;
        const perp = Math.abs(vx * dy - vy * dx), score = along + perp * 2.5;
        if (perp <= along) { if (score < bestScore) { bestScore = score; best = n; } }
        else if (score < wideScore) { wideScore = score; wide = n; } }
      return best || wide;
    }
    canvas.onkeydown=e=>{
      const d = DIRS[e.key];
      if(e.key==='Escape'){if(routeRoot||!selected)resetRoute();else select(null);e.preventDefault();}
      else if(e.key==='Enter'&&selected){toggleRoute(selected);e.preventDefault();}
      else if(d&&e.shiftKey){ox-=d[0]*80;oy-=d[1]*80;viewTouched=true;invalidate();e.preventDefault();}
      else if(d){const n=nearest(d[0],d[1]);if(n)select(n.id,true);e.preventDefault();}
      else if(e.key==='+'||e.key==='='){zoomAt(W/2,H/2,scale*1.2);e.preventDefault();}
      else if(e.key==='-'||e.key==='_'){zoomAt(W/2,H/2,scale/1.2);e.preventDefault();}
      else if(e.key==='0'){fit();e.preventDefault();}
    };

    // Start at the first command, keeping labels legible even for long sessions.
    // (A loop, not Math.min(...array): spreading 100k+ values overflows the stack.)
    function fitStart(){if(!nodes.length)return;let minY=Infinity,minX=Infinity,maxX=-Infinity;
      for(const n of nodes){minY=Math.min(minY,n.homeY);minX=Math.min(minX,n.homeX);maxX=Math.max(maxX,n.homeX);}
      // Never below a legible zoom: when the bands are wider than the view, start
      // at the left edge and let the user pan, instead of shrinking the labels away.
      const width=Math.max(300,maxX-minX+240);
      scale=Math.min(1,Math.max(0.65,(W-100)/width));
      ox=width*scale<=W-40?-(minX+maxX+120)*scale/2:40-W/2-minX*scale;oy=75-H/2-minY*scale;
    }
    function fit(){fitTo(nodes.filter(n=>shown(n.id)),1.2);viewTouched=true;invalidate();}
    resize();
    fitStart();
    const ro = new ResizeObserver(resize); ro.observe(canvas);
    notifyRoute();
    frame();
    if (cool > 0) invalidate();

    return {resetRoute,toggleRoute,fit,select:id=>select(id,true),getVisibleIds(){return nodes.filter(n=>shown(n.id)).map(n=>n.id);},
      destroy(){alive=false;ro.disconnect();ctx.clearRect(0,0,W,H);canvas.setAttribute('aria-label','Relationship graph: no graph shown');window.removeEventListener("mouseup",mouseUp);
        canvas.onmousedown=canvas.onmousemove=canvas.onmouseleave=canvas.onwheel=canvas.ondblclick=canvas.onkeydown=null;
        canvas.onpointerdown=canvas.onpointermove=canvas.onpointerup=canvas.onpointercancel=null;}};
  }

  global.pentrailTimelineLayout = timelineLayout;
  global.initGraph = initGraph;
  global.pentrailRouteNodes = routeNodes;
})(window);
