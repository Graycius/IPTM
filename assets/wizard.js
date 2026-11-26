(function(){
const q=s=>document.querySelector(s),qa=s=>[...document.querySelectorAll(s)];
const ico={auto:'🌗',dark:'🌙',light:'☀️'};
let th='auto';try{th=localStorage.getItem('iptm-theme')||'auto';}catch(_e){}if(!['auto','dark','light'].includes(th))th='auto';document.documentElement.dataset.theme=th;
const tb=q('#theme'),themeName={auto:'automatico',dark:'scuro',light:'chiaro'};
if(tb){const syncTheme=n=>{tb.textContent=ico[n];tb.setAttribute('aria-label','Tema attuale: '+themeName[n]+'. Cambia tema');tb.title='Tema attuale: '+themeName[n]+'. Premi per cambiare';};syncTheme(th);tb.onclick=()=>{const n={auto:'dark',dark:'light',light:'auto'}[document.documentElement.dataset.theme||'auto'];document.documentElement.dataset.theme=n;try{localStorage.setItem('iptm-theme',n);}catch(_e){}syncTheme(n);};}
// Menu laterale mobile: stato ARIA, chiusura con ESC e ritorno del focus.
const bg=q('#burger'),side=q('#side'),layout=q('#app-layout'),backdrop=q('#navBackdrop');
const setMenuOpen=open=>{
 if(!bg||!side||!layout)return;
 side.classList.toggle('open',open);layout.classList.toggle('nav-open',open);
 bg.setAttribute('aria-expanded',String(open));
 bg.setAttribute('aria-label',open?'Chiudi il menu di navigazione':'Apri il menu di navigazione');
 if(backdrop)backdrop.hidden=!open;
 if(open){const search=q('#ms');if(search)search.focus();}
 else if(window.innerWidth<=860)bg.focus();
};
if(bg&&side){bg.addEventListener('click',()=>setMenuOpen(bg.getAttribute('aria-expanded')!=='true'));if(backdrop)backdrop.addEventListener('click',()=>setMenuOpen(false));document.addEventListener('keydown',e=>{if(e.key==='Escape'&&bg.getAttribute('aria-expanded')==='true')setMenuOpen(false);});}
// Chiudi il menu dopo una navigazione mobile e filtra le voci senza rimuoverle dal DOM.
qa('#side a').forEach(a=>a.addEventListener('click',()=>{if(window.innerWidth<=860)setMenuOpen(false);}));
// One complete tree. Filtering expands matching groups without hiding routes permanently.
const ms=q('#ms'),nav=q('#primary-menu');
const normalize=v=>String(v||'').normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLocaleLowerCase('it');
const navGroups=qa('#primary-menu details.mg');
/* Multiple groups may stay open: fewer clicks between network areas. */
if(ms){
 const output=q('#msResults');let expanded=null;
 function filterNavigation(){
  const query=normalize(ms.value.trim());
  if(query && !expanded)expanded=navGroups.map(g=>g.open);
  let visible=0;
  nav?.classList.toggle('searching',!!query);
  navGroups.forEach((g,i)=>{
   const groupName=normalize(g.querySelector(':scope > summary')?.textContent||'');
   const matchGroup=query && groupName.includes(query);
   const anchors=[...g.querySelectorAll('a.iptm-nav-link')];let matches=0;
   anchors.forEach(a=>{
    const ok=!query||matchGroup||normalize(a.dataset.label||a.textContent).includes(query);
    a.hidden=!ok;if(ok){matches++;visible++;}
   });
   if(query){g.hidden=!matches;g.open=matches>0;}
   else {g.hidden=false;if(expanded)g.open=expanded[i];}
  });
  if(!query)expanded=null;
  if(output)output.textContent=query?(visible?visible+' funzioni trovate':'Nessuna funzione trovata'):'';
 }
 ms.addEventListener('input',filterNavigation);
 ms.addEventListener('keydown',e=>{if(e.key==='Escape'&&ms.value){ms.value='';filterNavigation();e.stopPropagation();}});
 document.addEventListener('keydown',e=>{
  if(e.key!=='/'||e.altKey||e.ctrlKey||e.metaKey||e.isComposing)return;
  const el=e.target;
  if(el instanceof Element&&el.closest('input,textarea,select,[contenteditable="true"],[role="textbox"]'))return;
  e.preventDefault();ms.focus();ms.select();
 });
 filterNavigation();
}
qa('#toasts .msg').forEach(m=>{m.onclick=()=>m.remove();if(m.classList.contains('ok'))setTimeout(()=>m.remove(),7000);});
qa('[data-table]').forEach(i=>i.oninput=()=>{const t=i.value.toLowerCase();qa(i.dataset.table+' tr').forEach((r,n)=>{if(n)r.style.display=(r.dataset.filter||r.textContent).toLowerCase().includes(t)?'':'none';});});
const rs=q('#rsearch');if(rs)rs.oninput=()=>{const t=rs.value.toLowerCase();qa('#rtab tbody tr').forEach(r=>{r.style.display=r.textContent.toLowerCase().includes(t)||r.classList.contains('cm')&&t===''?'':'none';});};
qa('form.acc').forEach(f=>{[...f.children].filter(e=>e.tagName==='H3').forEach(h=>{const d=document.createElement('details');d.open=true;const s=document.createElement('summary');s.textContent=h.textContent;d.appendChild(s);let n=h.nextSibling;const mv=[];while(n&&!(n.nodeType===1&&(n.tagName==='H3'||n.classList.contains('sticky')))){mv.push(n);n=n.nextSibling;}mv.forEach(x=>d.appendChild(x));h.replaceWith(d);});});
// ================= CONFIGURAZIONE GUIDATA DA ZERO =================
const Z=window.ZERO,root=q('#zero');if(!Z||!root)return;
const B=q('#zbody'),P=q('#zprog'),ifs=Object.keys(Z.ifaces),priv=/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/;
const A={mode:'single',wan_if:ifs[0]||'',lan_nets:Object.keys(Z.nets).filter(n=>priv.test(n)).slice(0,3).join(','),nat:'1',dns_local:'0',dns_ip:'',dot:'1',level:'standard',vpn:'none',vpn_if:'wg0',vpn_net:'10.8.0.0/24',vpn_port:'51820',gateway_ip:'',dhcp_server:'1',pihole_web:'1',pihole_ports:'8089,8489',recovery:'no',web_ports:'80,443,8089,8489',ssh_from:['lan'],ssh_port:'22',ssh_limit:'1',svcs:[],custom_ports:'',docker:'0',crowdsec:'0',fwd:[],lists:[],geo_codes:'',logging:'drops',v6:'0',base:'keep'};
if(Z.pre)Object.keys(Z.pre).forEach(k=>{A[k]=Z.pre[k];});
const R={nets:/^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?(,\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?)*$/,ip:/^\d{1,3}(\.\d{1,3}){3}$/,port:/^\d{1,5}$/,ports:/^\d{1,5}(:\d{1,5})?(,\d{1,5}(:\d{1,5})?)*$/,ifn:/^[A-Za-z0-9_.+-]{1,15}$/,cc:/^([A-Za-z]{2})(,[A-Za-z]{2})*$/};
const E=s=>String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/"/g,'&quot;');
const rt=()=>A.mode!=='host';
const card=(k,v,l,d)=>`<label class="sc ${A[k]===v?'sel':''}"><input type=radio name=${k} value="${v}" ${A[k]===v?'checked':''} hidden><b>${l}</b><div class=mut>${d||''}</div></label>`;
const yn=(k,l,h)=>`<div class=fl><span>${l}</span><label><input type=radio name=${k} value=1 ${A[k]==='1'?'checked':''}> Sì</label> <label style="margin-left:14px"><input type=radio name=${k} value=0 ${A[k]!=='1'?'checked':''}> No</label>${h?`<small>${h}</small>`:''}</div>`;
const tx=(k,l,ph,h)=>`<label class=fl><span>${l}</span><input name=${k} value="${E(A[k])}" placeholder="${ph||''}">${h?`<small>${h}</small>`:''}</label>`;
const mu=(k,items)=>items.map(([v,l])=>`<label style="display:block;margin:4px 0"><input type=checkbox name=${k} value="${v}" ${A[k].includes(v)?'checked':''}> ${l}</label>`).join('');
const chips=(k,arr)=>arr.map(([v,l])=>`<a href="#" class=chip data-z="${k}" data-v="${E(v)}">${E(l)}</a>`).join('');
const Q=[
{t:'Che ruolo ha questo dispositivo?',show:()=>1,html:()=>`<p class=mut>Ti faccio qualche domanda e creo io tutte le regole. Puoi cambiare ogni scelta dopo.</p><div class=grid>${card('mode','router','🌐 Router / gateway','Ha due o più interfacce: collega la LAN a Internet.')}${card('mode','single','🔌 Firewall con una sola scheda','Un solo cavo (anche bond): fa da gateway, DNS o firewall per la LAN.')}${card('mode','host','🖥 Solo questo dispositivo','Non inoltra traffico: protegge solo se stesso.')}</div>`},
{t:'Quale interfaccia va verso Internet?',show:rt,html:()=>`<label class=fl><span>Interfaccia WAN</span><select name=wan_if>${ifs.map(i=>`<option ${A.wan_if===i?'selected':''} value="${E(i)}">${E(i)} — ${E(Z.ifaces[i]||'senza IPv4')}</option>`).join('')}</select><small>Con una sola scheda scegli quella unica.</small></label>`,chk:()=>R.ifn.test(A.wan_if)?'':'Scegli un\'interfaccia.'},
{t:'Quali sono le reti locali (LAN)?',show:()=>1,html:()=>tx('lan_nets','Reti LAN (CIDR separati da virgola)','192.168.1.0/24','Da queste reti consentirò l\'accesso ai servizi. Includi la rete da cui ti stai collegando adesso!')+'<p>Rilevate: '+chips('lan_nets',Object.keys(Z.nets).map(n=>[n,n+' ('+Z.nets[n]+')']))+'</p>',chk:()=>R.nets.test(A.lan_nets)?'':'Indica almeno una rete valida, es. 192.168.1.0/24.'},
{t:'Come raggiunge Internet il router?',show:rt,html:()=>tx('gateway_ip','Gateway IPv4 (se presente)','192.168.3.1','Se il gateway è privato o sulla stessa scheda della LAN, le protezioni WAN aggressive sono pericolose. Il wizard non modificherà la rotta.')+'<p class=mut>Il router potrebbe avere più subnet su una sola scheda: controlla che il gateway non venga incluso in una rete isolata.</p>',chk:()=>A.gateway_ip!==''&&!R.ip.test(A.gateway_ip)?'Gateway IP non valido.':''},
{t:'Chi serve DHCP ai client?',show:()=>1,html:()=>yn('dhcp_server','DietPi o un servizio locale fornisce DHCP?','Mantengo comunque le eccezioni DHCP indispensabili: disabilitarle automaticamente può lasciare i client senza indirizzo IP. Se il server DHCP è esterno, verifica il relativo percorso.'),chk:()=>''},
{t:'Vuoi condividere Internet con la LAN (NAT)?',show:rt,html:()=>yn('nat','Abilitare il NAT / masquerade in uscita?','Serve se questo dispositivo è il gateway della LAN. Attiverò anche il clamp MSS.')},
{t:'DNS locale (es. Pi-hole, AdGuard)',show:()=>1,html:()=>yn('dns_local','Hai un server DNS locale e vuoi che tutti i client lo usino?','Reindirizzo le query DNS dei client LAN verso di lui, anche se ne impostano un altro.')+(A.dns_local==='1'?tx('dns_ip','IP del DNS locale','192.168.1.165')+yn('dot','Bloccare anche DNS-over-TLS (porta 853)?','Impedisce di aggirare il DNS locale.'):''),chk:()=>A.dns_local==='1'&&!R.ip.test(A.dns_ip)?'Indica un IP valido.':''},
{t:'Accesso web di Pi-hole',show:()=>1,html:()=>yn('pihole_web','La dashboard Pi-hole è ospitata su questo DietPi?','FTL può usare porte diverse da 80/443. Verifica la configurazione FTL e l’IP da cui ti colleghi.')+(A.pihole_web==='1'?tx('pihole_ports','Porte web Pi-hole TCP','8089,8489','Queste porte saranno aggiunte alle eccezioni INPUT per le reti LAN consentite; nessuna modifica ai listener FTL.'):''),chk:()=>A.pihole_web==='1'&&!R.ports.test(A.pihole_ports)?'Porte Pi-hole non valide.':''},
{t:'Quanto vuoi essere rigoroso?',show:()=>1,html:()=>`<div class=grid>${card('level','base','Base','Chiuso di default, connessioni stabilite, anti-spoofing, pacchetti non validi.')}${card('level','standard','Consigliato','Base + limiti ping e SYN flood, porte privilegiate chiuse, IGMP.')}</div>`},
{t:'Hai una VPN?',show:()=>1,html:()=>`<div class=grid>${card('vpn','none','Nessuna VPN','')}${card('vpn','wireguard','WireGuard','Porta UDP, interfaccia wg0.')}${card('vpn','openvpn','OpenVPN','Porta UDP, interfaccia tun0.')}</div>`+(A.vpn!=='none'?tx('vpn_if','Interfaccia VPN','wg0')+tx('vpn_net','Rete della VPN','10.8.0.0/24')+tx('vpn_port','Porta UDP di ascolto',A.vpn==='openvpn'?'1194':'51820'):''),chk:()=>A.vpn==='none'?'':(R.ifn.test(A.vpn_if)&&R.nets.test(A.vpn_net)&&R.port.test(A.vpn_port)?'':'Controlla interfaccia, rete e porta della VPN.')},
{t:'Pagina di gestione web',show:()=>1,html:()=>tx('web_ports','Porte del server web che ospita questa pagina','80,443','Le consento dalla LAN per non chiuderti fuori.'),chk:()=>R.ports.test(A.web_ports)?'':'Porte non valide.'},
{t:'Accesso SSH',show:()=>1,html:()=>`<div class=fl><span>Da dove si può accedere via SSH?</span>${mu('ssh_from',[['lan','Dalla LAN'],...(A.vpn!=='none'?[['vpn','Dalla VPN']]:[]),...(rt()?[['wan','Da Internet (sconsigliato)']]:[])])}</div>`+tx('ssh_port','Porta SSH','22')+yn('ssh_limit','Limitare tentativi e connessioni (anti brute-force)?','Per ogni rete LAN: max connessioni simultanee e tentativi al minuto.'),chk:()=>R.port.test(A.ssh_port)?'':'Porta non valida.'},
{t:'Servizi offerti alla LAN',show:()=>1,html:()=>`<div class=fl><span>Quali servizi vengono usati su questo dispositivo?</span>${mu('svcs',Object.entries(Z.svcs))}</div>`+tx('custom_ports','Altre porte (proto:porte, separate da spazio)','tcp:8080 udp:5000:5100'),chk:()=>(A.custom_ports.split(/\s+/).filter(Boolean).every(x=>/^(tcp|udp):\d{1,5}(:\d{1,5})?(,\d{1,5}(:\d{1,5})?)*$/.test(x)))?'':'Formato: tcp:8080 oppure udp:5000:5100.'},
{t:'Integrazioni',show:()=>1,html:()=>yn('docker','Usi Docker su questo dispositivo?','Consento le reti dei container e proteggo DOCKER-USER.')+yn('crowdsec','Usi CrowdSec (firewall bouncer)?','Aggancio le sue catene e la blacklist ipset.')},
{t:'Port forwarding',show:rt,html:()=>`<p class=mut>Vuoi rendere raggiungibili da Internet dei servizi interni? (facoltativo)</p><table><tr><th>Nome</th><th>Proto</th><th>Porta esterna</th><th>IP interno</th><th>Porta interna</th><th></th></tr>${A.fwd.map((f,i)=>`<tr><td><input data-f="${i}.name" value="${E(f.name)}"></td><td><select data-f="${i}.proto">${['both','tcp','udp'].map(p=>`<option ${f.proto===p?'selected':''}>${p}</option>`).join('')}</select></td><td><input data-f="${i}.eport" value="${E(f.eport)}"></td><td><input data-f="${i}.ip" value="${E(f.ip)}"></td><td><input data-f="${i}.tport" value="${E(f.tport)}" placeholder="uguale"></td><td><button type=button class="s sm" data-fd="${i}">✕</button></td></tr>`).join('')}</table><p><button type=button class=s id=zfa>＋ Aggiungi</button></p>`,chk:()=>A.fwd.every(f=>R.ports.test(f.eport)&&R.ip.test(f.ip)&&(f.tport===''||R.port.test(f.tport)))?'':'Controlla porte e IP dei forward.'},
{t:'Liste di IP malevoli e GeoIP',show:()=>1,html:()=>`<div class=fl><span>Blocca automaticamente (aggiornate ogni giorno)</span>${mu('lists',Object.entries(Z.bl))}</div>`+tx('geo_codes','Paesi da bloccare (codici ISO, facoltativo)','CN,RU')+'<p>'+chips('geo_codes',Object.entries(Z.geo).map(([c,n])=>[c,c+' '+n]))+'</p>',chk:()=>A.geo_codes===''||R.cc.test(A.geo_codes.replace(/\s/g,''))?'':'Codici non validi.'},
{t:'Registrazione (log)',show:()=>1,html:()=>`<div class=grid>${card('logging','none','Nessun log','')}${card('logging','drops','Pacchetti scartati','Con limiti per sorgente (utile a CrowdSec).')}${card('logging','all','Scartati + connessioni','Aggiunge i nuovi ingressi/uscite dal WAN.')}</div>`},
{t:'IPv6',show:()=>1,html:()=>yn('v6','Creare anche una bozza di firewall IPv6?','Chiuso di default, ICMPv6 consentito, servizi dai prefissi fidati.')},
{t:'Hai un accesso indipendente di recupero?',show:()=>1,html:()=>`<div class=grid>${card('recovery','yes','Console locale / out-of-band','Posso intervenire anche se il firewall blocca la rete.')}${card('recovery','no','Solo connessione di rete','L’operazione è più rischiosa: non applicare profili sperimentali o combinazioni aggressive senza una persona davanti al router.')}</div><p class=mut>Nessuna risposta abilita automaticamente «Forza» né disattiva il watchdog.</p>`},
{t:'Cosa faccio con le regole attuali?',show:()=>1,html:()=>`<div class=grid>${card('base','zero','🧹 Parti da zero','Sostituisce tutte le regole della bozza con quelle nuove. L\'originale va nei backup.')}${card('base','keep','🧩 Mantieni le regole manuali','Conserva quelle non gestite e rigenera solo i blocchi automatici.')}</div>`},
{t:'Riepilogo',show:()=>1,html:()=>{const L=[`Ruolo: <b>${A.mode==='router'?'router/gateway':A.mode==='single'?'firewall a scheda unica':'solo questo dispositivo'}</b>`,rt()?`WAN: <b>${E(A.wan_if)}</b>, NAT: <b>${A.nat==='1'?'sì':'no'}</b>`:'',`LAN: <b>${E(A.lan_nets)}</b>`,A.dns_local==='1'?`DNS locale forzato: <b>${E(A.dns_ip)}</b>${A.dot==='1'?' (DoT bloccato)':''}`:'',`Livello: <b>${A.level}</b>`,A.vpn!=='none'?`VPN: <b>${A.vpn}</b> su ${E(A.vpn_if)} (${E(A.vpn_net)}, UDP ${E(A.vpn_port)})`:'',`Web gestione: <b>${E(A.web_ports)}</b> dalla LAN`,A.pihole_web==='1'?`Pi-hole TCP: <b>${E(A.pihole_ports)}</b>`:'',A.gateway_ip?`Gateway dichiarato: <b>${E(A.gateway_ip)}</b>`:'',`Recupero indipendente: <b>${A.recovery==='yes'?'disponibile':'non disponibile'}</b>`,`SSH da: <b>${A.ssh_from.join(', ')||'nessuno'}</b> (porta ${E(A.ssh_port)}${A.ssh_limit==='1'?', con limiti':''})`,A.svcs.length?`Servizi: <b>${A.svcs.map(s=>E(Z.svcs[s])).join(', ')}</b>`:'',A.custom_ports?`Porte extra: <b>${E(A.custom_ports)}</b>`:'',A.docker==='1'?'Docker: <b>sì</b>':'',A.crowdsec==='1'?'CrowdSec: <b>sì</b>':'',A.fwd.length?`Port forward: <b>${A.fwd.length}</b>`:'',A.lists.length?`Liste IP: <b>${A.lists.map(s=>E(Z.bl[s])).join(', ')}</b>`:'',A.geo_codes?`GeoIP: <b>${E(A.geo_codes)}</b>`:'',`Log: <b>${A.logging}</b>`,A.v6==='1'?'IPv6: <b>bozza creata</b>':'',`Regole attuali: <b>${A.base==='zero'?'sostituite':'mantenute le manuali'}</b>`].filter(Boolean);
 return `<ul>${L.map(x=>'<li>'+x+'</li>').join('')}</ul><p class=mut>Non cambia il firewall in funzione: crea la <b>bozza</b>. Poi verifichi le differenze e applichi con rollback automatico.</p><form method=post>${Z.fh}<input type=hidden name=action value=zero_apply><input type=hidden name=answers id=zans><button class=g>✔ Crea la configurazione</button></form>`;}}
];
let cur=0;
const vis=()=>Q.map((x,i)=>[x,i]).filter(([x])=>x.show());
function draw(){const v=vis(),pos=v.findIndex(([,i])=>i===cur),last=pos===v.length-1;P.innerHTML=`<div style="flex:1"><div class=mut style="font-size:13px">Domanda ${pos+1} di ${v.length}</div><div class=bar><i style="width:${Math.round((pos+1)*100/v.length)}%"></i></div></div>`;
 B.innerHTML=`${cur===0&&Z.pre_src?`<div class="msg ok">Campi precompilati dalla <b>${E(Z.pre_src)}</b>. Controllali e modificali se serve.</div>`:''}<h2>${Q[cur].t}</h2><div id=zerr class="msg err" style="display:none"></div>${Q[cur].html()}${last?'':`<p style="margin-top:14px">${pos?'<button type=button class=s id=zb>← Indietro</button> ':''}<button type=button id=zn>Avanti →</button></p>`}`;
 if(last){const f=B.querySelector('form');if(f)f.onsubmit=()=>{for(const [step,index] of vis()){const error=step.chk?step.chk():'';if(error){cur=index;draw();const box=q('#zerr');box.style.display='block';box.textContent=error;return false;}}q('#zans').value=JSON.stringify(A);const submit=f.querySelector('button');if(submit){submit.disabled=true;submit.textContent='Validazione in corso…';}return true;};B.insertAdjacentHTML('beforeend','<p><button type=button class=s id=zb>← Indietro</button></p>');}
 const nx=q('#zn'),bk=q('#zb');
 if(nx)nx.onclick=()=>{const e=Q[cur].chk?Q[cur].chk():'';if(e){const x=q('#zerr');x.style.display='block';x.textContent=e;return;}cur=v[pos+1][1];draw();};
 if(bk)bk.onclick=()=>{cur=v[pos-1][1];draw();};
 const fa=q('#zfa');if(fa)fa.onclick=()=>{A.fwd.push({name:'',proto:'both',eport:'',ip:'',tport:''});draw();};
 qa('[data-fd]').forEach(b=>b.onclick=()=>{A.fwd.splice(+b.dataset.fd,1);draw();});
}
root.addEventListener('input',e=>{const t=e.target;if(t.dataset.f){const[i,k]=t.dataset.f.split('.');A.fwd[+i][k]=t.value;return;}if(t.name&&t.type!=='radio'&&t.type!=='checkbox'&&t.tagName!=='SELECT'&&!Array.isArray(A[t.name]))A[t.name]=t.value;});
root.addEventListener('change',e=>{const t=e.target;if(t.dataset.f){const[i,k]=t.dataset.f.split('.');A.fwd[+i][k]=t.value;return;}if(!t.name||!(t.name in A))return;
 if(t.type==='checkbox'){const s=new Set(A[t.name]);t.checked?s.add(t.value):s.delete(t.value);A[t.name]=[...s];}else{A[t.name]=t.value;if(t.type==='radio')draw();}});
root.addEventListener('click',e=>{const c=e.target.closest('[data-z]');if(c){e.preventDefault();const k=c.dataset.z,v=c.dataset.v;A[k]=A[k]?(A[k].split(',').includes(v)?A[k]:A[k]+','+v):v;draw();}});
draw();
})();

/* IPTM 5.4.3: one guided fabric editor backed by the original pipe grammar.
 * No live commands, no changes to legacy POST field names. */
(()=>{
'use strict';
function initFabric(){
 const form=document.getElementById('iptm-unified-network-form');if(!form||form.dataset.fabricReady)return;
 form.dataset.fabricReady='1';
 const editors=[...form.querySelectorAll('[data-iptm-fabric-editor]')];
 for(const box of editors){
  const rows=box.querySelector('[data-iptm-fabric-rows]');
  const tpl=box.querySelector('[data-iptm-fabric-template]');
  const raw=box.querySelector('[data-iptm-fabric-raw]');
  if(!rows||!tpl||!raw)continue;
  const cols=tpl.content.querySelectorAll('[data-iptm-fabric-field]').length;
  const sync=()=>{
   raw.value=[...rows.querySelectorAll('.iptm-fabric-row')].map(row=>
    [...row.querySelectorAll('[data-iptm-fabric-field]')].map(x=>x.value.trim()).join(' | ')
   ).filter(line=>line.split('|').some(x=>x.trim())).join('\n');
  };
  const add=(values=[])=>{
   if(rows.children.length>=Math.min(384,Math.max(1,Number(box.dataset.iptmFabricLimit)||32)))return;
   const node=tpl.content.firstElementChild.cloneNode(true);
   [...node.querySelectorAll('[data-iptm-fabric-field]')].forEach((input,i)=>{
    input.value=values[i]||'';
    input.addEventListener('input',sync);
   });
   node.querySelector('[data-iptm-fabric-remove]')?.addEventListener('click',()=>{node.remove();sync();});
   rows.append(node);sync();
  };
  const previous=raw.value.split(/\r?\n/).map(x=>x.trim()).filter(x=>x&&!x.startsWith('#'));
  // Preserve unrecognized pre-existing rows verbatim. A format change must
  // never silently discard a previously saved fabric rule on form submit.
  const parsed=previous.map(line=>line.split('|').map(x=>x.trim()));
  if(parsed.some(parts=>parts.length!==cols)){
   const note=document.createElement('p');note.className='msg warn';
   note.textContent='Formato precedente non riconosciuto: modifica le righe testuali per evitare perdita di dati.';
   raw.before(note); continue;
  }
  parsed.forEach(parts=>add(parts));
  raw.hidden=true;
  box.querySelector('[data-iptm-fabric-add]')?.addEventListener('click',()=>{add();box.open=true;rows.lastElementChild?.querySelector('input')?.focus();});
  form.addEventListener('submit',sync);
 }
}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',initFabric);else initFabric();
})();
