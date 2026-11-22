/* IPTM 5.4.3 Logical topology canvas: explicit non-physical edges; edit draft only. */
(() => {
'use strict';
const NS='http://www.w3.org/2000/svg';
const labels={trusted:'Fidati',iot:'IoT',guest:'Ospiti',unknown:'Non classificati'};
const kinds=['trusted','iot','guest','unknown'];
const icons={printer:'🖨️',camera:'📷',television:'📺',mobile:'📱',router:'📡',iot:'💡',generic:'💻'};
const policyNames={internet:'Internet',lan:'LAN',dns:'DNS esterno',dot:'DoT',quic:'QUIC',vpn:'VPN',forward:'Blocco totale'};
const palette={trusted:'#198754',iot:'#b47921',guest:'#4471bf',unknown:'#68758c'};
const nodeElement=(name,attrs={})=>{const e=document.createElementNS(NS,name);Object.entries(attrs).forEach(([k,v])=>e.setAttribute(k,String(v)));return e;};
const html=(tag,attrs={})=>{const e=document.createElement(tag);Object.entries(attrs).forEach(([k,v])=>{if(k==='className')e.className=v;else e.setAttribute(k,String(v));});return e;};
const txt=(e,value)=>{e.textContent=String(value);return e;};
function init(){
 const root=document.getElementById('iptm-topology-svg');if(!root||root.dataset.ready)return;
 const source=document.getElementById('iptm-topology-data');if(!source)return;
 let data;try{data=JSON.parse(source.textContent);}catch{return;}
 root.dataset.ready='1';
 const panel=document.getElementById('iptm-topology-panel'),issueEl=document.getElementById('iptm-topology-issues');
 const table=document.querySelector('#iptm-topology-table tbody'),search=document.getElementById('iptm-topo-search'),filter=document.getElementById('iptm-topo-filter');
 const records=(Array.isArray(data.nodes)?data.nodes:[]).map(n=>({...n,kind:labels[n.kind]?n.kind:'unknown',flags:[...new Set(n.flags||[])],warnings:[...(n.warnings||[])],ips:n.ips||[],selected:!!n.selected}));
 const byMac=new Map(records.map(n=>[n.mac,n]));
 const state={active:null,page:0,zoom:1,positions:new Map(),issues:new Map()};
 const W=1160,H=784;
 const zones={trusted:{x:22,y:276},iot:{x:596,y:276},guest:{x:22,y:524},unknown:{x:596,y:524}};
 const kindIcons={trusted:'shield',iot:'cpu',guest:'users',unknown:'help'};
 function calculateWarnings(){
   const ips=new Map(),warns=new Map();
   for(const n of records){
     const own=[...n.warnings];
     for(const ip of n.ips){if(!ips.has(ip))ips.set(ip,[]);ips.get(ip).push(n.mac);}
     if(n.flags.includes('forward')&&n.flags.length>1)own.push('Blocco totale incompatibile con altri filtri');
     if(n.kind==='trusted'&&n.flags.includes('forward'))own.push('Dispositivo fidato bloccato totalmente');
     warns.set(n.mac,own);
   }
   for(const [ip,macs] of ips){if(new Set(macs).size>1)for(const mac of macs)warns.get(mac)?.push('IP duplicato: '+ip);}
   return new Map([...warns].map(([mac,list])=>[mac,[...new Set(list)]]).filter(([,list])=>list.length));
 }
 function filtered(){const q=search?.value?.trim().toLowerCase()||'';return records.filter(n=>(!filter||filter.value==='all'||filter.value===n.kind)&&(!q||[n.mac,n.vendor,n.kind,...n.ips].join(' ').toLowerCase().includes(q)));}
 function layout(){
   const visible=filtered(),groups=Object.fromEntries(kinds.map(kind=>[kind,visible.filter(n=>n.kind===kind)]));
   const pageCount=Math.max(1,...kinds.map(k=>Math.ceil(groups[k].length/6)));
   state.page=Math.max(0,Math.min(pageCount-1,state.page));
   const output=[];
   for(const kind of kinds){
     groups[kind].slice(state.page*6,(state.page+1)*6).forEach((node,i)=>{
       const area=zones[kind],pos=state.positions.get(node.mac)||{x:area.x+143+(i%2)*258,y:area.y+92+Math.floor(i/2)*61};
       output.push({node,pos});
     });
   }
   return {visible,groups,output,pageCount};
 }
 function svgText(parent,x,y,value,attrs={}){
   const e=nodeElement('text',{x,y,...attrs});e.textContent=String(value);parent.append(e);return e;
 }
 function curve(parent,d,cls='iptm-topo-edge'){
   parent.append(nodeElement('path',{d,class:cls,fill:'none'}));
 }
 function icon(parent,type,x,y,size=20){
   const g=nodeElement('g',{transform:`translate(${x} ${y}) scale(${size/24})`,class:'iptm-topo-icon','aria-hidden':'true'});
   const common={fill:'none',stroke:'currentColor','stroke-width':1.9,'stroke-linejoin':'round','stroke-linecap':'round'};
   const path=(d)=>g.append(nodeElement('path',{d,...common}));
   const rect=(x,y,w,h,rx)=>g.append(nodeElement('rect',{x,y,width:w,height:h,rx,...common}));
   switch(type){
     case 'cloud': path('M6 18h12a4 4 0 0 0 .7-7.9A7 7 0 0 0 5.6 9 4.5 4.5 0 0 0 6 18z');break;
     case 'shield':path('M12 2 21 6v6c0 5-3.7 8.1-9 10-5.3-1.9-9-5-9-10V6z');path('m8.5 12 2.5 2.5 5-5');break;
     case 'globe':g.append(nodeElement('circle',{cx:12,cy:12,r:9,...common}));path('M3 12h18M12 3c-6 5-6 13 0 18M12 3c6 5 6 13 0 18');break;
     case 'cpu':rect(5,5,14,14,2);rect(9,9,6,6,1);path('M9 1v4m6-4v4M9 19v4m6-4v4M1 9h4m-4 6h4m14-6h4m-4 6h4');break;
     case 'users':g.append(nodeElement('circle',{cx:9,cy:8,r:3,...common}));path('M3 21v-2a6 6 0 0 1 12 0v2M17 5a3 3 0 0 1 0 6M17 15a5 5 0 0 1 4 5v1');break;
     case 'help':g.append(nodeElement('circle',{cx:12,cy:12,r:9,...common}));path('M9.5 9a3 3 0 1 1 5.5 2c-2 1.3-3 1.8-3 3.5M12 18h.01');break;
     case 'mobile':rect(7,2,10,20,2);path('M11 18h2');break;
     case 'camera':rect(3,7,15,12,3);path('m18 11 4-3v10l-4-3');g.append(nodeElement('circle',{cx:10.5,cy:13,r:2.6,...common}));break;
     case 'printer':rect(6,3,12,5,1);rect(3,8,18,10,2);rect(6,15,12,6,1);path('M18 11h.01');break;
     case 'television':rect(2,4,20,15,2);path('M8 23h8M12 19v4');break;
     case 'router':rect(3,11,18,9,2);path('M7 11V5m10 6V5M5 16h.01m4 0h.01');break;
     case 'iot':path('M9 19h6m-5 3h4M9 16c0-2-5-4-5-8a8 8 0 0 1 16 0c0 4-5 6-5 8z');break;
     default:rect(3,4,18,14,2);path('M8 22h8m-4-4v4');break;
   }
   parent.append(g);return g;
 }
 function metricBox(parent,x,y,w,type,title,subtitle){
   const g=nodeElement('g',{class:'iptm-topo-metric'});
   g.append(nodeElement('rect',{x,y,width:w,height:76,rx:15,class:'iptm-topo-metric-bg'}));
   g.append(nodeElement('rect',{x:x+14,y:y+15,width:46,height:46,rx:12,class:'iptm-topo-metric-symbol'}));
   icon(g,type,x+25,y+25,24);
   svgText(g,x+74,y+30,title,{class:'iptm-topo-metric-title'});
   svgText(g,x+74,y+51,subtitle.length>28?subtitle.slice(0,27)+'…':subtitle,{class:'iptm-topo-metric-sub'});
   parent.append(g);
 }
 function deviceNode(parent,node,pos){
   const warning=state.issues.has(node.mac);
   const g=nodeElement('g',{class:'iptm-topo-node'+(warning?' iptm-topo-problem':'')+(state.active===node.mac?' iptm-topo-selected':''),
     transform:`translate(${pos.x} ${pos.y})`,role:'button',tabindex:0,'aria-label':(node.vendor||node.mac)+' '+node.ips.join(' '),
     'data-node':node.mac,'data-dirty':String(state.positions.has(node.mac))});
   const bg=nodeElement('rect',{class:'iptm-topo-device-bg',x:-119,y:-24,width:238,height:49,rx:12});g.append(bg);
   const capsule=nodeElement('rect',{class:'iptm-topo-device-icon',x:-111,y:-17,width:35,height:35,rx:9});g.append(capsule);
   icon(g,node.device_type||'generic',-106,-12,24);
   const name=node.vendor||node.ips[0]||'Dispositivo';
   svgText(g,-67,-3,name.length>21?name.slice(0,20)+'…':name,{class:'iptm-topo-device-name'});
   const ipText=node.ips[0]||(node.observed?'Indirizzo non disponibile':'Non osservato');
   svgText(g,-67,15,ipText,{class:'iptm-topo-device-ip'});
   if(warning)g.append(nodeElement('circle',{cx:106,cy:-12,r:5,class:'iptm-topo-warning'}));
   g.append(txt(nodeElement('title'),(node.vendor||'Dispositivo')+' · '+node.mac+' · '+node.ips.join(', ')));
   g.addEventListener('click',()=>select(node.mac));
   g.addEventListener('keydown',event=>{
     if(event.key==='Enter'||event.key===' '){event.preventDefault();select(node.mac);return;}
     const moves={ArrowLeft:[-10,0],ArrowRight:[10,0],ArrowUp:[0,-10],ArrowDown:[0,10]};
     if(moves[event.key]){event.preventDefault();const step=event.shiftKey?3:1;
       move(node.mac,node.kind,{x:pos.x+moves[event.key][0]*step,y:pos.y+moves[event.key][1]*step});draw();
       [...root.querySelectorAll('.iptm-topo-node')].find(e=>e.getAttribute('data-node')===node.mac)?.focus();
     }
   });
   let dragging=null;
   g.addEventListener('pointerdown',event=>{if(event.button!==0)return;dragging={id:event.pointerId,x:event.clientX,y:event.clientY,start:{...pos},moved:false};g.setPointerCapture(event.pointerId);});
   g.addEventListener('pointermove',event=>{
     if(!dragging||event.pointerId!==dragging.id)return;
     const dx=event.clientX-dragging.x,dy=event.clientY-dragging.y;
     if(Math.abs(dx)+Math.abs(dy)>6)dragging.moved=true;
     if(!dragging.moved)return;
     const viewport=root.getBoundingClientRect();
     const scale=(W/state.zoom)/Math.max(1,viewport.width);
     const next=move(node.mac,node.kind,{x:dragging.start.x+dx*scale,y:dragging.start.y+dy*scale});
     g.setAttribute('transform',`translate(${next.x} ${next.y})`);
   });
   g.addEventListener('pointerup',event=>{if(!dragging||dragging.id!==event.pointerId)return;const moved=dragging.moved;dragging=null;if(moved){state.active=node.mac;draw();}});
   g.addEventListener('pointercancel',()=>dragging=null);
   parent.append(g);
 }
 function move(mac,kind,coords){
   const a=zones[kind];const pos={x:Math.max(a.x+120,Math.min(a.x+421,coords.x)),y:Math.max(a.y+83,Math.min(a.y+209,coords.y))};
   state.positions.set(mac,pos);return pos;
 }
 function drawMap(info){
   root.replaceChildren();root.setAttribute('viewBox',`${(W-W/state.zoom)/2} ${(H-H/state.zoom)/2} ${W/state.zoom} ${H/state.zoom}`);
   const defs=nodeElement('defs');const grd=nodeElement('linearGradient',{id:'iptm-topo-grd',x1:'0%',x2:'100%',y1:'0%',y2:'100%'});
   grd.append(nodeElement('stop',{offset:'0%','stop-color':'#155e73'}),nodeElement('stop',{offset:'100%','stop-color':'#137d70'}));defs.append(grd);root.append(defs);
   root.append(nodeElement('rect',{x:0,y:0,width:W,height:H,rx:22,class:'iptm-topo-canvas-bg'}));
   svgText(root,30,43,'MAPPA LOGICA DELLA RETE',{class:'iptm-topo-title'});
   svgText(root,30,66,'Inventario dei client, non un rilevamento dei cavi o degli switch',{class:'iptm-topo-subtitle'});
   const status=nodeElement('g',{class:'iptm-topo-count'});
   status.append(nodeElement('rect',{x:915,y:24,width:216,height:42,rx:21}));
   status.append(nodeElement('circle',{cx:939,cy:45,r:5,class:'iptm-topo-online-dot'}));
   svgText(status,957,50,`${info.visible.length} dispositivi nel filtro`,{});root.append(status);
   // Logical service associations only: no implied cable or physical edge.
   curve(root,'M 350 151 H 406','iptm-topo-service-edge');
   curve(root,'M 731 151 H 782','iptm-topo-service-edge');
   metricBox(root,40,113,310,'cloud','Internet / WAN',String(data.wan||'Interfaccia da verificare'));
   const gateway=nodeElement('g');gateway.append(nodeElement('rect',{x:406,y:108,width:325,height:87,rx:17,fill:'url(#iptm-topo-grd)'}));
   icon(gateway,'shield',427,133,28);
   svgText(gateway,464,143,'IPTM · Gateway',{class:'iptm-topo-gw-title'});
   svgText(gateway,464,165,'Protezione e policy locali',{class:'iptm-topo-gw-sub'});root.append(gateway);
   metricBox(root,782,113,336,'globe','DNS locale',String(data.dns||'Resolver da verificare'));
   const edges=nodeElement('g',{class:'iptm-topo-logical-edges'});
   curve(edges,'M 568 197 V 226 H 297 V 276');
   curve(edges,'M 568 226 H 866 V 276');
   // bottom zone connections are shown as a shared logical bus, never as physical wiring.
   curve(edges,'M 568 226 V 501 H 297 V 524');
   curve(edges,'M 568 501 H 866 V 524');root.append(edges);
   for(const kind of kinds){
     const area=zones[kind],group=info.groups[kind]||[];
     const card=nodeElement('g',{class:'iptm-topo-zone-card', 'data-kind':kind});
     card.append(nodeElement('rect',{x:area.x,y:area.y,width:542,height:230,rx:17,class:'iptm-topo-zone-bg'}));
     card.append(nodeElement('rect',{x:area.x,y:area.y,width:5,height:230,rx:3,fill:palette[kind]}));
     card.append(nodeElement('circle',{cx:area.x+31,cy:area.y+32,r:17,fill:palette[kind],opacity:.13}));
     const iconGroup=nodeElement('g',{style:`color:${palette[kind]}`});icon(iconGroup,kindIcons[kind],area.x+20,area.y+21,22);card.append(iconGroup);
     svgText(card,area.x+59,area.y+37,labels[kind],{class:'iptm-topo-zone-title'});
     svgText(card,area.x+419,area.y+37,`${group.length} nel filtro`,{class:'iptm-topo-zone-count'});
     card.append(nodeElement('line',{x1:area.x+20,y1:area.y+61,x2:area.x+522,y2:area.y+61,class:'iptm-topo-divider'}));
     root.append(card);
   }
   for(const {node,pos} of info.output)deviceNode(root,node,pos);
   drawMobile(info);
 }
 function drawMobile(info){
   let mobile=document.getElementById('iptm-topology-mobile');
   if(!mobile){mobile=html('div',{id:'iptm-topology-mobile',className:'iptm-topology-mobile'});root.parentElement.parentElement.append(mobile);}
   mobile.replaceChildren();
   for(const kind of kinds){
     const box=html('section',{className:'iptm-topology-mobile-zone'});
     box.style.setProperty('--zone-color',palette[kind]);
     const heading=html('h3');heading.textContent=labels[kind]+' · '+info.groups[kind].length;box.append(heading);
     const members=info.output.filter(row=>row.node.kind===kind);
     if(!members.length)box.append(txt(html('p',{className:'mut'}),'Nessun dispositivo in questa pagina'));
     for(const {node} of members){const btn=html('button',{type:'button',className:'iptm-topology-mobile-device'});
       const name=html('strong');name.textContent=node.vendor||node.mac;
       const caption=html('span');caption.textContent=(node.ips.join(', ')||'IP non noto')+(state.issues.has(node.mac)?' · Da verificare':'');
       btn.append(name,caption);btn.addEventListener('click',()=>select(node.mac));box.append(btn);
     }mobile.append(box);
   }
 }
 function renderPanel(){panel.replaceChildren();const n=byMac.get(state.active);
   if(!n){panel.append(txt(html('h3'),'Seleziona un dispositivo'),txt(html('p'),'Scegli un nodo o una riga: i cambiamenti rimangono in bozza.'));return;}
   panel.append(txt(html('h3'),(icons[n.device_type]||icons.generic)+' '+(n.vendor||'Dispositivo sconosciuto')));
   panel.append(txt(html('p',{className:'mut'}),n.mac+' · '+(n.ips.join(', ')||'IP non rilevato')));
   panel.append(txt(html('p',{className:'mut'}),n.evidence||'Inventario locale'));
   const group=html('label');group.textContent='Zona del dispositivo';const sel=html('select',{id:'iptm-topo-zone'});
   for(const [key,label] of Object.entries(labels)){const op=html('option',{value:key});op.textContent=label;sel.append(op);}
   sel.value=n.kind;sel.disabled=!data.can_edit;sel.addEventListener('change',()=>{n.kind=sel.value;state.positions.delete(n.mac);draw();document.getElementById('iptm-topo-zone')?.focus();});group.append(sel);panel.append(group);
   panel.append(txt(html('p'),'Filtri IoT (bozza)'));
   for(const [name,label]of Object.entries(policyNames)){
     const line=html('label',{className:'iptm-topology-flag'}),checkbox=html('input',{type:'checkbox',value:name});
     checkbox.checked=n.flags.includes(name);checkbox.disabled=!data.can_edit;
     checkbox.addEventListener('change',()=>{
       if(checkbox.checked){n.flags=name==='forward'?['forward']:[...n.flags.filter(x=>x!=='forward'),name];}
       else n.flags=n.flags.filter(x=>x!==name);
       n.flags=[...new Set(n.flags)];draw();panel.querySelector(`input[value="${name}"]`)?.focus();
     });line.append(checkbox,document.createTextNode(label));panel.append(line);
   }
   const selectedLine=html('label',{className:'iptm-topology-flag'}),selected=html('input',{type:'checkbox',id:'iptm-topology-selected'});
   selected.checked=n.selected;selected.disabled=!data.can_edit;selected.addEventListener('change',()=>{n.selected=selected.checked;draw();panel.querySelector('#iptm-topology-selected')?.focus();});
   selectedLine.append(selected,document.createTextNode('Includi nella prossima anteprima MAC'));panel.append(selectedLine);
   const warnings=state.issues.get(n.mac)||[];
   panel.append(txt(html('p',{className:warnings.length?'msg warn':'mut'}),warnings.join(' · ')||'Nessun avviso rilevato per questo nodo.'));
 }
 function drawIssues(){issueEl.replaceChildren();const count=state.issues.size;
   issueEl.append(txt(html('p'),count?`${count} nodi richiedono attenzione. Clicca un MAC per i dettagli.`:'Nessuna incoerenza rilevata nei dati disponibili (topologia fisica non verificata).'));
   let i=0;for(const [mac,warnings] of state.issues){if(i++>=20)break;
     const btn=html('button',{type:'button',className:'s iptm-topology-issue'});btn.textContent='⚠ '+mac+' · '+warnings.join(' · ');btn.addEventListener('click',()=>select(mac));issueEl.append(btn);
   }
   if(count>20)issueEl.append(txt(html('p'),`Altri ${count-20} nodi: usa la ricerca.`));
 }
 function drawTable(rows){table.replaceChildren();const fragment=document.createDocumentFragment();
   for(const {node:n} of rows){const tr=html('tr');if(n.mac===state.active)tr.className='iptm-topo-active-row';
     const warnings=state.issues.get(n.mac)||[];
     for(const val of [(icons[n.device_type]||'💻')+' '+n.mac,n.ips.join(', ')||'—',labels[n.kind],n.flags.join(', ')||'—',warnings.length?'⚠ Da verificare':'Inventario locale'])tr.append(txt(html('td'),val));
     tr.tabIndex=0;tr.addEventListener('click',()=>select(n.mac));tr.addEventListener('keydown',event=>{if(event.key==='Enter'){event.preventDefault();select(n.mac);}});fragment.append(tr);
   }table.append(fragment);
 }
 function drawPager(pageCount){let pager=document.getElementById('iptm-topology-paging');if(!pager){pager=html('div',{id:'iptm-topology-paging',className:'iptm-topology-pager'});root.parentElement.parentElement.after(pager);}
   pager.replaceChildren();
   for(const [delta,label]of [[-1,'‹ Precedenti'],[1,'Successivi ›']]){const btn=html('button',{type:'button',className:'s'});btn.textContent=label;btn.disabled=state.page+delta<0||state.page+delta>=pageCount;btn.addEventListener('click',()=>{state.page+=delta;state.active=null;draw();});pager.append(btn);}
   pager.append(txt(html('span'),`Pagina ${state.page+1} di ${pageCount}`));
 }
 function draw(){state.issues=calculateWarnings();const present=layout();drawMap(present);drawTable(present.output);renderPanel();drawIssues();drawPager(present.pageCount);}
 function select(mac){state.active=mac;draw();}
 search?.addEventListener('input',()=>{state.page=0;draw();});filter?.addEventListener('change',()=>{state.page=0;draw();});
 document.getElementById('iptm-topo-reset')?.addEventListener('click',()=>{state.positions.clear();state.zoom=1;draw();});
 for(const [id,action]of [['iptm-topo-zoom-in',1.2],['iptm-topo-zoom-out',1/1.2]])document.getElementById(id)?.addEventListener('click',()=>{state.zoom=Math.max(.75,Math.min(1.8,state.zoom*action));draw();});
 const form=document.getElementById('iptm-topology-save');
 form?.addEventListener('submit',event=>{
   if([...calculateWarnings().values()].some(warnings=>warnings.some(w=>w.includes('incompatibile')))){
     event.preventDefault();window.alert('Correggi prima i filtri incompatibili. Nessuna bozza salvata.');return;
   }
   if(records.filter(n=>n.selected).length>32){event.preventDefault();window.alert('Massimo 32 MAC selezionati per bozza.');return;}
   const target=document.getElementById('iptm-topology-post-data');target.replaceChildren();
   const add=(key,value)=>target.append(Object.assign(html('input',{type:'hidden',name:key}),{value:String(value)}));
   for(const n of records){add('included[]',n.mac);add(`kinds[${n.mac}]`,n.kind);for(const policy of n.flags)add(`policies[${n.mac}][]`,policy);if(n.selected)add('selected_macs[]',n.mac);}
 });
 draw();
}
const observer=new MutationObserver(()=>{if(document.getElementById('iptm-topology-svg')&&!document.getElementById('iptm-topology-svg').dataset.ready)init();});
function bootTopology(){
 if(!document.querySelector('.iptm-view-topology,#iptm-topology-svg'))return;
 init();observer.observe(document.body,{childList:true,subtree:true});
}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',bootTopology);
else bootTopology();
})();
