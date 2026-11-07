const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
async function scenario(file,name,fn){
  const els={};const el=id=>els[id]||(els[id]={id,textContent:'',innerHTML:'',hidden:true,attrs:new Map(),setAttribute(k,v){this.attrs.set(k,String(v))},getAttribute(k){return this.attrs.has(k)?this.attrs.get(k):null},removeAttribute(k){this.attrs.delete(k)},classList:{s:new Set(),add(c){this.s.add(c)},remove(c){this.s.delete(c)},contains(c){return this.s.has(c)}}});
  const pending=[];const graphs=[];
  const ctxt={document:{getElementById:el},esc:v=>String(v).replace(/[<>&"]/g,''),TYPE_LABEL:{host:'host'},renderLegend(){},
    activeSession:1,graph:null,console,
    fetch:url=>new Promise((res)=>pending.push({url,res})),
    initGraph:(c,data,onSelect,onRoute)=>{
      // Like graph.js: the canvas is labelled with the visible count. destroy() only stops the graph here,
      // so these cases check renderGraph's own loading/empty/error labels (graph.js destroy: R10).
      const n=data.nodes.length,lab=(v,root)=>c.setAttribute('aria-label',`Relationship graph: ${v} of ${n} elements${root?'; paths through '+root:''}`);
      const g={data,onSelect,onRoute,destroyed:false,selects:[],fits:0,destroy(){this.destroyed=true},resetRoute(){},select(id){this.selects.push(id);return id===null||data.nodes.some(n=>n.id===id)},fit(){this.fits++},
        focus(root,v){lab(v,root);onRoute({root,label:root,visible:v,total:n});}};
      graphs.push(g);lab(n);onRoute({root:null,visible:n,total:n});return g;}};
  // Page globals the renderer uses (index.html defines them outside the extracted part).
  Object.assign(ctxt,{fmtTime:ms=>ms?'T'+ms:'—',fmtDur:()=>'',fmtBytes:n=>n+' B',strip:s=>String(s).replace(/\x1b\[[0-9;]*m/g,''),
    pendingNodes:null,shown:[],
    // Operator notes (04BJ) are page globals too; notes.test.cjs covers them.
    loadNotes:()=>new Promise(()=>{}),noteLinksHTML:()=>'',noteLinkClick:()=>false});ctxt.showCommand=i=>ctxt.shown.push(i);
  // 04BM: the renderer reads through the page's bounded read helpers; load the real ones from index.html.
  Object.assign(ctxt,{setTimeout,clearTimeout,AbortController});
  vm.createContext(ctxt);vm.runInContext(fs.readFileSync(require('node:path').join(__dirname,'xref.js'),'utf8'),ctxt);
  {const page=fs.readFileSync(require('node:path').join(__dirname,'index.html'),'utf8'),i=page.indexOf('// ---- reads with a bound'),j=page.indexOf('let sessionInfo=new Map();');
   if(i>=0&&j>i)vm.runInContext(page.slice(i,j),ctxt);}
  vm.runInContext(fs.readFileSync(file,'utf8')+'\nthis.renderGraph=renderGraph;',ctxt);
  const reply=(i,body,ok=true,status=200)=>pending[i].res({ok,status,json:async()=>body});
  try{await fn({ctxt,el,pending,graphs,reply});return['PASS',name];}catch(e){return['FAIL',name,String(e.message).split('\n')[0].slice(0,150)];}
}
const flush=()=>new Promise(r=>setTimeout(r,0));
(async()=>{
 for(const file of process.argv.slice(2)){
  console.log('== '+file);const out=[];
  out.push(await scenario(file,'G1 a slower reply for the previous session does not replace the current session graph',async({ctxt,pending,graphs,reply})=>{
    ctxt.activeSession=1;const a=ctxt.renderGraph();ctxt.activeSession=2;const b=ctxt.renderGraph();
    reply(1,{nodes:[{id:'s2'}],edges:[]});await flush();reply(0,{nodes:[{id:'s1'}],edges:[]});await a;await b;
    const live=graphs.filter(g=>!g.destroyed);assert.equal(live.length,1);assert.equal(live[0].data.nodes[0].id,'s2');}));
  out.push(await scenario(file,'G2 an empty session clears the route status and hides the reset button of the previous graph',async({ctxt,el,graphs,reply})=>{
    const a=ctxt.renderGraph();reply(0,{nodes:[{id:'x'}],edges:[]});await a;
    graphs[0].onRoute({root:'x',label:'x',visible:1,total:1});assert.equal(el('route-reset').hidden,false);
    const b=ctxt.renderGraph();reply(1,{nodes:[],edges:[]});await b;
    assert.equal(el('route-reset').hidden,true,'reset button still visible');assert.ok(!el('route-status').textContent.includes('Paths through'),'stale route status');}));
  out.push(await scenario(file,'G3 the detail panel shows no command for cmd_index null / offset missing',async({ctxt,el,graphs,reply})=>{
    const a=ctxt.renderGraph();reply(0,{nodes:[{id:'x'}],edges:[]});await a;
    graphs[0].onSelect({id:'x',label:'x',type:'host',cmd_index:null});assert.ok(!el('gdetail').innerHTML.includes('#null'),el('gdetail').innerHTML.match(/source:[^<]*/)[0]);
    graphs[0].onSelect({id:'x',label:'x',type:'host',cmd_index:3});assert.ok(!el('gdetail').innerHTML.includes('undefined'),el('gdetail').innerHTML.match(/source:[^<]*/)[0]);}));
  out.push(await scenario(file,'G4 an HTTP error reply is reported and the previous session graph is not left on screen',async({ctxt,el,graphs,reply})=>{
    const a=ctxt.renderGraph();reply(0,{nodes:[{id:'x'}],edges:[]});await a;
    const b=ctxt.renderGraph();reply(1,{error:'database locked'},false,500);await b.catch(e=>{throw new Error('renderGraph rejected: '+e.message)});
    assert.equal(graphs[0].destroyed,true,'previous graph still shown');assert.ok(el('gdetail').innerHTML.length>0,'no error shown');}));
  const eight={nodes:Array.from({length:8},(_,i)=>({id:'n'+i})),edges:[]};
  out.push(await scenario(file,'G5 switching from a focused 8-node graph to an empty session does not keep "of 8" in the canvas label',async({ctxt,el,graphs,reply})=>{
    const a=ctxt.renderGraph();reply(0,eight);await a;graphs[0].focus('n2',5);
    assert.match(el('gcanvas').getAttribute('aria-label'),/5 of 8/);
    ctxt.activeSession=2;const b=ctxt.renderGraph();
    const loading=el('gcanvas').getAttribute('aria-label')||'';
    assert.ok(!/of 8/.test(loading),'while loading: '+loading);assert.match(loading,/loading/);
    reply(1,{nodes:[],edges:[]});await b;
    const empty=el('gcanvas').getAttribute('aria-label')||'';
    assert.ok(!/of 8/.test(empty),'empty session: '+empty);assert.match(empty,/no entities/);}));
  out.push(await scenario(file,'G6 a failed load replaces the previous graph label with an error label',async({ctxt,el,reply})=>{
    const a=ctxt.renderGraph();reply(0,eight);await a;
    const b=ctxt.renderGraph();reply(1,{error:'database locked'},false,500);await b;
    const lab=el('gcanvas').getAttribute('aria-label')||'';
    assert.ok(!/of 8/.test(lab),lab);assert.match(lab,/could not be loaded/);}));
  out.push(await scenario(file,'G7 the detail panel lists relationships in both directions; a relationship selects that element, × closes, Fit to view fits',async({ctxt,el,graphs,reply})=>{
    const data={nodes:[{id:'h',label:'10.0.0.1',type:'host'},{id:'p',label:'10.0.0.1:22',type:'port'},{id:'d',label:'srv.test',type:'hostname'}],
      edges:[{source:'h',target:'p',type:'open'},{source:'d',target:'h',type:'resolves'},{source:'h',target:'missing',type:'x'}]};
    const a=ctxt.renderGraph();reply(0,data);await a;const g=graphs[0];
    g.onSelect({id:'h',label:'10.0.0.1',type:'host',confidence:'high'});
    const html=el('gdetail').innerHTML;
    assert.match(html,/relationships \(2\)/,'relationship count');
    assert.match(html,/data-id="p"[^>]*><span class="et">open → <\/span>10\.0\.0\.1:22/,'outgoing relationship');
    assert.match(html,/data-id="d"[^>]*><span class="et"><\/span>srv\.test<span class="et"> ← resolves/,'incoming relationship');
    assert.match(html,/class="close"[^>]*aria-label="Close details"/,'close button');
    const button=(cls,id)=>({closest:()=>({classList:{contains:c=>c===cls},dataset:id==null?{}:{id}})});
    el('gcanvas').focus=()=>{};
    el('gdetail').onclick({target:button('',  'p')});assert.deepEqual(g.selects,['p']);
    el('gdetail').onclick({target:button('close')});assert.equal(g.selects.length,2);assert.equal(g.selects[1],null);
    el('graph-fit').onclick();assert.equal(g.fits,1);}));
  const H={nodes:[{id:'host:10.0.0.1',label:'10.0.0.1',type:'host',cmd_index:0,confidence:'high'}],edges:[]};
  const CMDS=[{index:0,command:'nmap -sV 10.0.0.1',cwd:'/w',started_ms:5,ended_ms:6,exit_code:0,complete:true,out_start_off:0,out_end_off:10},
              {index:2,command:'curl http://10.0.0.1/',cwd:'/w',started_ms:7,ended_ms:8,exit_code:7,complete:true,out_start_off:10,out_end_off:10}];
  const ENTS=[{type:'host',value:'10.0.0.1',cmd_index:0},{type:'host',value:'10.0.0.1',cmd_index:2}];
  const text=(p,body,missing)=>p.res({ok:true,status:200,headers:{get:k=>k==='X-Missing-Bytes'?String(missing||0):null},text:async()=>body,json:async()=>JSON.parse(body)});
  out.push(await scenario(file,'G8 a selected element shows its command as typed by the user and the terminal output it produced; other commands and the timeline are one click away',async({ctxt,el,pending,graphs,reply})=>{
    const a=ctxt.renderGraph();reply(0,H);await a;const g=graphs[0];
    g.onSelect(H.nodes[0]);
    assert.match(el('gdetail').innerHTML,/loading the command…/);
    assert.equal(pending[1].url,'/api/commands?session=1');assert.equal(pending[2].url,'/api/entities?session=1');
    reply(1,CMDS);reply(2,ENTS);await flush();await flush();
    let html=el('gdetail').innerHTML;
    assert.match(html,/Command — typed by the user<\/summary><pre class="typed">nmap -sV 10\.0\.0\.1<\/pre>/);
    assert.match(html,/<details class="sec term" open[^>]*><summary>Terminal output — printed by the programs · 10 B<\/summary><pre class="output"><span class="none">loading…/);
    assert.match(html,/found in 2 commands: <button type="button" data-cmd="0" aria-pressed="true">#0<\/button><button type="button" data-cmd="2" aria-pressed="false">#2/);
    assert.equal(pending[3].url,'/api/output?session=1&start=0&end=10');
    text(pending[3],'\x1b[32m22/tcp open\x1b[0m',0);await flush();await flush();
    html=el('gdetail').innerHTML;
    assert.match(html,/<pre class="output">22\/tcp open<\/pre>/,'output not shown (or not cleaned)');
    assert.match(html,/relationships|source: command #0/);
    const button=ds=>({closest:()=>({classList:{contains:()=>false},dataset:ds})});
    el('gdetail').onclick({target:button({cmd:'2'})});await flush();await flush();
    html=el('gdetail').innerHTML;
    assert.match(html,/<pre class="typed">curl http:\/\/10\.0\.0\.1\/<\/pre>/);assert.match(html,/\(no output\)/);assert.match(html,/class="badge bad"[^>]*>7</);
    assert.equal(pending.length,4,'a command without output must not be fetched');
    el('gdetail').onclick({target:button({timeline:'2'})});assert.deepEqual([...ctxt.shown],[2]);
    // another element, then the commands fail: reported, not "no command"
  }));
  out.push(await scenario(file,'G9 a failed command list is reported; it is retried on the next selection',async({ctxt,el,pending,graphs,reply})=>{
    const a=ctxt.renderGraph();reply(0,H);await a;const g=graphs[0];
    g.onSelect(H.nodes[0]);reply(1,{error:'x'},false,500);reply(2,[]);await flush();await flush();
    assert.match(el('gdetail').innerHTML,/Could not load the command\. The viewer reported an internal error \(code 500\)/); // 04BM: the shared read messages
    assert.doesNotMatch(el('gdetail').innerHTML,/No command is recorded/);
    g.onSelect(H.nodes[0]);assert.equal(pending[3].url,'/api/commands?session=1','not retried');
  }));
  out.push(await scenario(file,'G10 opened from the timeline: the first existing candidate is selected, otherwise "Not in the graph"',async({ctxt,el,graphs,reply})=>{
    ctxt.pendingNodes=['domain:10.0.0.1','host:10.0.0.1'];
    const a=ctxt.renderGraph();reply(0,H);await a;
    assert.deepEqual([...graphs[0].selects],['domain:10.0.0.1','host:10.0.0.1']);assert.equal(ctxt.pendingNodes,null);
    ctxt.pendingNodes=['url:nope'];
    const b=ctxt.renderGraph();reply(1,H);await b;
    assert.match(el('gdetail').innerHTML,/Not in the graph/);assert.equal(el('gdetail').classList.contains('show'),true);
  }));
  // ---- 04BG: stale replies must not reach the current detail panel ----
  const A={nodes:[{id:'host:10.0.0.1',label:'10.0.0.1',type:'host',cmd_index:0,confidence:'high'},{id:'host:10.0.0.3',label:'10.0.0.3',type:'host',cmd_index:2,confidence:'high'}],edges:[]};
  const A_CMDS=[{index:0,command:'nmap SESSION-A',cwd:'/a',started_ms:1,ended_ms:2,exit_code:0,complete:true,out_start_off:0,out_end_off:10},
                {index:2,command:'curl SESSION-A-2',cwd:'/a',started_ms:3,ended_ms:4,exit_code:0,complete:true,out_start_off:10,out_end_off:30}];
  const A_ENTS=[{type:'host',value:'10.0.0.1',cmd_index:0},{type:'host',value:'10.0.0.1',cmd_index:2},{type:'host',value:'10.0.0.3',cmd_index:2}];
  const B={nodes:[{id:'host:10.0.0.9',label:'10.0.0.9',type:'host',cmd_index:0,confidence:'high'}],edges:[]};
  const B_CMDS=[{index:0,command:'nmap SESSION-B',cwd:'/b',started_ms:5,ended_ms:6,exit_code:0,complete:true,out_start_off:0,out_end_off:5}];
  const B_ENTS=[{type:'host',value:'10.0.0.9',cmd_index:0}];
  const txt=(p,body)=>p.res({ok:true,status:200,headers:{get:()=>null},text:async()=>body,json:async()=>JSON.parse(body)});
  const settle=async()=>{for(let i=0;i<6;i++)await flush();};
  const find=(pending,url)=>{const i=pending.findIndex(p=>p.url===url&&!p.used);assert.ok(i>=0,'no request '+url+' in '+pending.map(p=>p.url).join(', '));pending[i].used=true;return pending[i];};
  const ok=(p,body)=>p.res({ok:true,status:200,json:async()=>body});
  // session B: graph, selection, commands, entities and output, fully shown
  async function showB(ctxt,el,pending,graphs){
    ctxt.activeSession=2;const b=ctxt.renderGraph();ok(find(pending,'/api/graph?session=2'),B);await b;
    const g=graphs.at(-1);g.onSelect(B.nodes[0]);
    ok(find(pending,'/api/commands?session=2'),B_CMDS);ok(find(pending,'/api/entities?session=2'),B_ENTS);await settle();
    txt(find(pending,'/api/output?session=2&start=0&end=5'),'B-OUT');await settle();
    const html=el('gdetail').innerHTML;
    assert.match(html,/nmap SESSION-B/);assert.match(html,/<pre class="output">B-OUT<\/pre>/);assert.equal(el('gdetail').classList.contains('show'),true);
    return {g,html};
  }
  out.push(await scenario(file,'G11 a delayed output of session A, resolved after session B is shown, changes nothing; nor after B is deselected',async({ctxt,el,pending,graphs})=>{
    ctxt.activeSession=1;const a=ctxt.renderGraph();ok(find(pending,'/api/graph?session=1'),A);await a;
    graphs[0].onSelect(A.nodes[0]);ok(find(pending,'/api/commands?session=1'),A_CMDS);ok(find(pending,'/api/entities?session=1'),A_ENTS);await settle();
    const late=find(pending,'/api/output?session=1&start=0&end=10');
    const {g,html}=await showB(ctxt,el,pending,graphs);
    txt(late,'A-OUT');await settle();
    assert.equal(el('gdetail').innerHTML,html,'session A output replaced the panel of session B');
    g.onSelect(null);const hidden=el('gdetail').innerHTML;
    late.res({ok:true,status:200,headers:{get:()=>null},text:async()=>'A-OUT'});await settle();
    assert.equal(el('gdetail').classList.contains('show'),false,'a stale reply showed the hidden panel');assert.equal(el('gdetail').innerHTML,hidden);
  }));
  out.push(await scenario(file,'G12 delayed commands/entities of session A (success or failure) neither repaint B nor start A output requests',async({ctxt,el,pending,graphs})=>{
    for(const fail of [false,true]){
      ctxt.activeSession=1;const a=ctxt.renderGraph();ok(find(pending,'/api/graph?session=1'),A);await a;
      graphs.at(-1).onSelect(A.nodes[0]);
      const pc=find(pending,'/api/commands?session=1'),pe=find(pending,'/api/entities?session=1');
      const {html}=await showB(ctxt,el,pending,graphs);
      const before=pending.length;
      if(fail){pc.res({ok:false,status:500,json:async()=>({})});ok(pe,A_ENTS);}else{ok(pc,A_CMDS);ok(pe,A_ENTS);}
      await settle();
      assert.equal(el('gdetail').innerHTML,html,(fail?'failed':'late')+' commands of A repainted B');
      assert.equal(pending.length,before,'a stale selection requested output');
    }
  }));
  out.push(await scenario(file,'G13 within one graph: rapid selections and source-command switches show only the newest; previews are cached and shared',async({ctxt,el,pending,graphs})=>{
    ctxt.activeSession=1;const a=ctxt.renderGraph();ok(find(pending,'/api/graph?session=1'),A);await a;const g=graphs[0];
    const [X,Y]=A.nodes;
    // three selections before the command list arrives: the last one wins
    g.onSelect(X);g.onSelect(Y);g.onSelect(X);
    ok(find(pending,'/api/commands?session=1'),A_CMDS);ok(find(pending,'/api/entities?session=1'),A_ENTS);await settle();
    assert.match(el('gdetail').innerHTML,/<h3>10\.0\.0\.1<\/h3>/);assert.match(el('gdetail').innerHTML,/nmap SESSION-A</);
    assert.equal(pending.filter(p=>p.url.startsWith('/api/commands')).length,1,'command list loaded more than once');
    const p0=find(pending,'/api/output?session=1&start=0&end=10');
    // switch to command #2 while #0 is in flight; #0 resolving must not switch back
    const click=ds=>el('gdetail').onclick({target:{closest:()=>({classList:{contains:()=>false},dataset:ds})}});
    click({cmd:'2'});await settle();
    const p2=find(pending,'/api/output?session=1&start=10&end=30');
    txt(p0,'OUT-0');await settle();
    let html=el('gdetail').innerHTML;
    assert.match(html,/curl SESSION-A-2/,'the older command came back');assert.doesNotMatch(html,/OUT-0/);assert.match(html,/aria-pressed="true">#2</);
    // another element while #2 is in flight; then #2 resolves
    g.onSelect(Y);await settle();txt(p2,'OUT-2');await settle();
    html=el('gdetail').innerHTML;
    assert.match(html,/<h3>10\.0\.0\.3<\/h3>/,'the previous element came back');assert.match(html,/<pre class="output">OUT-2<\/pre>/,'shared preview of command #2 not shown for 10.0.0.3');
    // back to X: #0 preview was cached when it arrived, no new request
    const n=pending.length;g.onSelect(X);await settle();
    assert.match(el('gdetail').innerHTML,/<pre class="output">OUT-0<\/pre>/);assert.equal(pending.length,n,'cached preview requested again');
  }));
  out.push(await scenario(file,'G14 leaving the graph for the timeline while output is in flight: the reply neither repaints nor reveals the hidden panel',async({ctxt,el,pending,graphs})=>{
    ctxt.activeSession=1;const a=ctxt.renderGraph();ok(find(pending,'/api/graph?session=1'),A);await a;
    graphs[0].onSelect(A.nodes[0]);ok(find(pending,'/api/commands?session=1'),A_CMDS);ok(find(pending,'/api/entities?session=1'),A_ENTS);await settle();
    const late=find(pending,'/api/output?session=1&start=0&end=10');
    // what the Timeline tab does (index.html: if(activeView!=='graph')leaveGraph();)
    if(typeof ctxt.leaveGraph==='function')ctxt.leaveGraph();
    ctxt.activeView='timeline';el('gdetail').classList.remove('show');
    const before=el('gdetail').innerHTML;
    txt(late,'A-OUT');await settle();
    assert.doesNotMatch(el('gdetail').innerHTML,/A-OUT/,'the hidden panel was filled with the stale output');
    assert.equal(el('gdetail').innerHTML,before);assert.equal(el('gdetail').classList.contains('show'),false);
  }));
  out.push(await scenario(file,'G15 a failed preview is reported, not cached: the next selection asks again',async({ctxt,el,pending,graphs})=>{
    ctxt.activeSession=1;const a=ctxt.renderGraph();ok(find(pending,'/api/graph?session=1'),A);await a;const g=graphs[0];
    g.onSelect(A.nodes[0]);ok(find(pending,'/api/commands?session=1'),A_CMDS);ok(find(pending,'/api/entities?session=1'),A_ENTS);await settle();
    find(pending,'/api/output?session=1&start=0&end=10').res({ok:false,status:500});await settle();
    assert.match(el('gdetail').innerHTML,/Could not read the output \(The viewer reported an internal error \(code 500\)/); // 04BM: the shared read messages
    g.onSelect(null);g.onSelect(A.nodes[0]);await settle();
    txt(find(pending,'/api/output?session=1&start=0&end=10'),'RETRY');await settle();
    assert.match(el('gdetail').innerHTML,/<pre class="output">RETRY<\/pre>/);
  }));
  out.push(await scenario(file,'G16 the panel separates commands that recorded the element from commands where a related element names it; per observation',async({ctxt,el,pending,graphs})=>{
    const G={nodes:[{id:'host:192.0.2.1',label:'192.0.2.1',type:'host',cmd_index:0,confidence:'high'},{id:'host:192.0.2.2',label:'192.0.2.2',type:'host',cmd_index:2,confidence:'high'},
      {id:'hostname:rotating.example.test',label:'rotating.example.test',type:'hostname',cmd_index:0,confidence:'high'}],
      edges:[{source:'hostname:rotating.example.test',target:'host:192.0.2.1',type:'resolves',cmd_index:0},{source:'hostname:rotating.example.test',target:'host:192.0.2.2',type:'resolves',cmd_index:2}]};
    const CM=[0,1,2].map(i=>({index:i,command:'dig rotating #'+i,cwd:'/w',started_ms:i,ended_ms:i+1,exit_code:0,complete:true,out_start_off:i*10,out_end_off:i*10}));
    const EN=[{type:'host',value:'192.0.2.1',cmd_index:1},{type:'hostname',value:'rotating.example.test',cmd_index:0,details:'{"host":"192.0.2.1"}'},
      {type:'hostname',value:'rotating.example.test',cmd_index:2,details:'{"host":"192.0.2.2"}'}];
    ctxt.activeSession=1;const a=ctxt.renderGraph();ok(find(pending,'/api/graph?session=1'),G);await a;const g=graphs[0];
    g.onSelect(G.nodes[0]);ok(find(pending,'/api/commands?session=1'),CM);ok(find(pending,'/api/entities?session=1'),EN);await settle();
    let html=el('gdetail').innerHTML;
    assert.match(html,/found in 1 command: <button type="button" data-cmd="1" aria-pressed="false">#1<\/button> · named by a related element in: <button type="button" data-cmd="0" aria-pressed="true" class="relcmd"[^>]*>#0<\/button><\/div>/);
    assert.doesNotMatch(html,/data-cmd="2"/,'192.0.2.1 credited with the command that saw 192.0.2.2');
    assert.match(html,/Command #0 did not record this element itself/);
    const click=ds=>el('gdetail').onclick({target:{closest:()=>({classList:{contains:()=>false},dataset:ds})}});
    click({cmd:'1'});await settle();html=el('gdetail').innerHTML;
    assert.match(html,/dig rotating #1/);assert.doesNotMatch(html,/did not record this element itself/);
    g.onSelect(G.nodes[1]);await settle();html=el('gdetail').innerHTML;
    assert.doesNotMatch(html,/class="xnav"/,'one command only: no navigation');assert.match(html,/dig rotating #2/);assert.match(html,/Command #2 did not record this element itself/);
  }));
  for(const r of out)console.log(r.join(' | '));
 }
})();
