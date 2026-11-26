(function(){
'use strict';
function one(node,key){if(!node||node.dataset[key]==='1')return false;node.dataset[key]='1';return true;}
function searchableReadOnlyTable(table){
 // Do not hide editable rows: a filtered-out checkbox could otherwise be
 // accidentally submitted. Search only large read-only data sets.
 const rows=[...table.querySelectorAll(':scope > tbody > tr')];
 if(rows.length<16||table.querySelector('input,select,textarea,button,[contenteditable]'))return;
 if(table.dataset.iptmSearch==='1')return;
 const wrapper=table.closest('.iptm-table-scroll,.iptm-rule-table-scroll');
 if(!wrapper)return;
 table.dataset.iptmSearch='1';
 const tools=document.createElement('div');tools.className='iptm-table-tools';tools.setAttribute('role','search');
 const label=document.createElement('label'),input=document.createElement('input'),out=document.createElement('output');
 const heading=table.closest('.card')?.querySelector('h2,h3')?.textContent?.trim()||table.getAttribute('aria-label')||'Tabella';
 const id='iptm-table-filter-'+document.querySelectorAll('.iptm-table-tools').length;
 label.htmlFor=id;label.textContent='Filtra '+heading;
 input.id=id;input.type='search';input.placeholder='Cerca nelle righe';input.setAttribute('aria-label','Filtra '+heading);
 out.setAttribute('aria-live','polite');
 const normalize=text=>String(text||'').normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLocaleLowerCase('it');
 const values=rows.map(row=>normalize(row.textContent));
 const update=()=>{let n=0;const query=normalize(input.value.trim());rows.forEach((row,i)=>{const visible=!query||values[i].includes(query);row.hidden=!visible;if(visible)n++;});out.textContent=n+' / '+rows.length+' righe';};
 input.addEventListener('input',update);
 tools.append(label,input,out);wrapper.before(tools);update();
}
function tables(scope){
 for(const t of scope.querySelectorAll('table:not([data-iptm-enhanced])')){
  t.dataset.iptmEnhanced='1';
  if(!t.closest('.iptm-table-scroll,.iptm-rule-table-scroll')){
   const w=document.createElement('div');w.className='iptm-table-scroll';w.tabIndex=0;
   w.setAttribute('role','region');w.setAttribute('aria-label',(t.closest('.card')?.querySelector('h2,h3')?.textContent||'Tabella dati').trim());
   t.before(w);w.append(t);
  }
  searchableReadOnlyTable(t);
 }
}
function panelSearch(){
 const page=document.getElementById('iptm-page-body');if(!page||!one(page,'iptmSearchReady'))return;
 const cards=[...page.children].filter(el=>el.classList?.contains('card')&&el.querySelector(':scope > h2,:scope > h3'));
 if(cards.length<3)return;
 const nav=document.createElement('nav');nav.className='iptm-section-index';nav.setAttribute('aria-label','Pannelli della pagina');
 const title=document.createElement('strong');title.textContent='In questa pagina';
 const links=document.createElement('div');links.className='iptm-section-links';nav.append(title,links);
 cards.forEach((card,i)=>{
  const heading=card.querySelector(':scope > h2,:scope > h3');
  if(!card.id){let id='iptm-panel-'+i;while(document.getElementById(id))id+='x';card.id=id;}
  card.classList.add('iptm-panel-anchor');
  const a=document.createElement('a');a.href='#'+encodeURIComponent(card.id);a.textContent=heading.textContent.trim();links.append(a);
 });
 cards[0].before(nav);
}
function policy(){
 const root=document.querySelector('.fw-policy-sections'),input=document.getElementById('fw-policy-search');if(!root||!input||!one(root,'iptmPolicyReady'))return;
const groups=[...root.querySelectorAll(".fw-acc")];function apply(){const q=input.value.trim().toLocaleLowerCase("it");groups.forEach(g=>{const rows=[...g.querySelectorAll(".dd")];let visible=0;rows.forEach(r=>{const match=!q||r.textContent.toLocaleLowerCase("it").includes(q);r.hidden=!match;if(match)visible++;});g.hidden=!!q&&!visible;if(q&&visible)g.open=true;});}input.addEventListener("input",apply);document.getElementById("fw-policy-open")?.addEventListener("click",()=>groups.forEach(g=>{if(!g.hidden)g.open=true;}));document.getElementById("fw-policy-close")?.addEventListener("click",()=>groups.forEach(g=>g.open=false));
}
function pihole(){
 const f=document.getElementById('plImport');if(!f||!one(f,'iptmPiholeReady'))return;

const read=document.getElementById('plRead');
const checks=[...f.querySelectorAll('input[name="adlists[]"]')],cnt=document.getElementById('plCount'),search=document.getElementById('plFilter');
const rethinkChecks=[...f.querySelectorAll('input[name="rethink_ids[]"]')],rethinkCount=document.getElementById('plRethinkCount');
const rethinkFilter=document.getElementById('plRethinkFilter'),rethinkStateFilter=document.getElementById('plRethinkStateFilter');
function showRethink(){if(rethinkCount)rethinkCount.textContent=rethinkChecks.filter(x=>x.checked).length+' selezionate · '+rethinkChecks.length+' nel catalogo';}
rethinkChecks.forEach(x=>x.addEventListener('change',showRethink));
document.getElementById('plRethinkAll')?.addEventListener('click',()=>{rethinkChecks.forEach(x=>x.checked=true);showRethink();});
document.getElementById('plRethinkClear')?.addEventListener('click',()=>{rethinkChecks.forEach(x=>x.checked=false);showRethink();});
function filterRethink(){const q=rethinkFilter?.value.trim().toLocaleLowerCase('it')||'';
 const mode=rethinkStateFilter?.value||'all';
 f.querySelectorAll('.plRethinkItem').forEach(el=>{const s=el.dataset.state||'unknown';
  const match=mode==='all'||(mode==='present'&&['active','disabled','present'].includes(s))||mode===s;
  el.hidden=!match||!!q&&!el.textContent.toLocaleLowerCase('it').includes(q);
 });}
rethinkFilter?.addEventListener('input',filterRethink);
rethinkStateFilter?.addEventListener('change',filterRethink);
showRethink();
function show(){const n=checks.filter(x=>x.checked).length;cnt.textContent=n+' adlist selezionate'+(n>10?' · staging disabilitato, Gravity rinviato':'');}
checks.forEach(x=>x.addEventListener('change',show));
document.getElementById('plAll').addEventListener('click',()=>{checks.forEach(x=>x.checked=true);show();});
document.getElementById('plClear').addEventListener('click',()=>{checks.forEach(x=>x.checked=false);show();});
const regexChecks=[...f.querySelectorAll('input[name="regex_presets[]"]')],rxCount=document.getElementById('plRxCount');
function showRx(){rxCount.textContent=regexChecks.filter(x=>x.checked).length+' regex selezionate';}
regexChecks.forEach(x=>x.addEventListener('change',showRx));
document.getElementById('plRxAll').addEventListener('click',()=>{regexChecks.forEach(x=>x.checked=true);showRx();});
document.getElementById('plRxClear').addEventListener('click',()=>{regexChecks.forEach(x=>x.checked=false);showRx();});
showRx();show();
const stateFilter=document.getElementById('plStateFilter');
function applyViewFilter(){
 const q=search.value.toLowerCase(),mode=stateFilter?.value||'all';
 f.querySelectorAll('.plItem,.plRegexItem').forEach(el=>{
  const s=el.dataset.state||'unknown';
  const match=(mode==='all'||(mode==='present'&&['active','disabled','present'].includes(s))||mode===s) &&
    (el.classList.contains('plRegexItem')||el.textContent.toLowerCase().includes(q));
  el.style.display=match?'':'none';
 });
}
search.addEventListener('input',applyViewFilter);
stateFilter?.addEventListener('change',applyViewFilter);
const stateLabel={active:'Già presente · attiva',disabled:'Già presente · disattivata',present:'Già presente · stato sconosciuto',new:'Da aggiungere',unknown:'Non verificato'};
function updateStatus(entries,groups){
 const totals={active:0,disabled:0,present:0,new:0};
 for(const [selector,group] of [['.plItem','adlists'],['.plRegexItem','regex'],['.plRethinkItem','rethink']]){
  f.querySelectorAll(selector).forEach(el=>{
   const id=el.querySelector('input[type="checkbox"]')?.value;
   const raw=entries?.[group]?.[id];
   const state=groups && ['active','disabled','present','new'].includes(raw)?raw:'unknown';
   el.dataset.state=state;
   const badge=el.querySelector('.plStatus');if(badge){badge.dataset.state=state;badge.textContent=stateLabel[state];}
   if(state!=='unknown')totals[state]++;
  });
 }
 applyViewFilter();filterRethink();
 return totals;
}
const cachedNode=document.getElementById('plReadStatus');
let verified=false;
if(cachedNode?.dataset.iptmSavedStatus && cachedNode.dataset.iptmStatusUrl===read?.elements.pihole_api_url.value){
 try{updateStatus(JSON.parse(cachedNode.dataset.iptmSavedStatus),true);verified=true;}catch(_e){}
}
if(!verified)updateStatus(null,false);
read?.elements.pihole_api_url.addEventListener('input',()=>{
 if(read.elements.pihole_api_url.value!==cachedNode?.dataset.iptmStatusUrl) updateStatus(null,false);
});
f.addEventListener('submit',e=>{
 // Transient in-page credential reuse: no storage, no new network request.
 if(read && !f.elements.pihole_api_password.value &&
    read.elements.pihole_api_password.value &&
    f.elements.pihole_api_url.value===read.elements.pihole_api_url.value){
   f.elements.pihole_api_password.value=read.elements.pihole_api_password.value;
 }
 const applying=e.submitter?.name==='import_action' && e.submitter.value==='apply';
 const n=checks.filter(x=>x.checked).length,err=document.getElementById('plImportError');
 err.hidden=true;err.textContent='';
 

});
const status=document.getElementById('plReadStatus');
document.getElementById('plLoad')?.addEventListener('click',async()=>{
 status.textContent='Verifica in corso…';const b=document.getElementById('plLoad');b.disabled=true;
 try{
  const fd=new FormData(read);fd.append('read_preview','1');
  const r=await fetch(location.pathname+location.search,{method:'POST',body:fd,credentials:'same-origin',cache:'no-store',signal:AbortSignal.timeout(60000)});
  const j=await r.json();if(!r.ok||!j.ok)throw Error(j.error||'HTTP '+r.status);
  const totals=updateStatus(j.catalog_status,true);
  status.textContent='Verifica completata: '+(totals.active+totals.disabled+totals.present)+' elementi già presenti, '+totals.new+' da aggiungere (adlist, regex, RethinkDNS). Verde = attivo, ambra = disattivato. Nessuna lista modificata.';
  f.elements.pihole_api_url.value=read.elements.pihole_api_url.value;
  if(!f.elements.pihole_api_password.value)
    f.elements.pihole_api_password.value=read.elements.pihole_api_password.value;
  status.textContent+=' Credenziali trasferite nel modulo di importazione solo per questa pagina.';
 }catch(e){
  updateStatus(null,false);
  status.textContent='Verifica non riuscita: '+e.message+'. Nessuna lista segnata come presente senza una lettura autenticata. Se HTTP 401: genera una password applicativa nelle impostazioni Pi-hole v6 e ripeti la verifica.';
 }finally{b.disabled=false;}
});
}
function dnsFlow(){
 const w=document.getElementById('dns-flow-wrap');if(!w||!one(w,'iptmDnsReady'))return;
if(!w)return;let labels;try{labels=JSON.parse(w.dataset.flowLabels||'{}');}catch(_e){return;}var act=w.getAttribute("data-actual"),cap=document.getElementById("dns-flow-cap"),N=labels;
function show(m){var f=w.querySelectorAll(".dns-flow"),ok=false,i;for(i=0;i<f.length;i++){var on=f[i].getAttribute("data-mode")===m;f[i].hidden=!on;if(on)ok=true;}
if(!ok){if(m!==act)show(act);return;}
cap.textContent=(m===act?"Configurazione effettiva rilevata: ":"Anteprima della selezione (non ancora applicata): ")+N[m];}
w.parentElement.addEventListener("change",function(e){var t=e.target;if(t&&t.name==="dns_stack_mode"&&t.checked)show(t.value);});   /* delegazione: i radio sono nel form piu' in basso, non ancora presenti qui */
show(act);
}
function qosCountdown(){
 const e=document.getElementById('iptm-qos-countdown');if(!e||!one(e,'iptmCountdownReady'))return;
 const until=Date.now()+Math.max(0,Number(e.dataset.seconds)||0)*1000;
 function tick(){const n=Math.max(0,Math.ceil((until-Date.now())/1000));e.textContent=n?n+' s':'Scaduto: verifica rollback';if(!n)clearInterval(timer);}
 const timer=setInterval(tick,1000);tick();
}
// Short, contextual help for form controls that did not have a description.
// Titles are available on hover; focus or tap exposes the same text below the field.
const IPTM_FIELD_HINTS=[
 [/^interfaccia( principale| primaria)?$/i,'Seleziona la scheda che deve usare questo servizio.'],
 [/^scheda|^nic$/i,'Scegli una scheda rilevata dal sistema.'],
 [/^indirizzo ip|^ipv4|^ip server|^address$/i,'Indirizzo IPv4 della rete, con prefisso CIDR quando richiesto.'],
 [/alias|aggiuntivo/i,'Secondo indirizzo IP sulla stessa interfaccia, senza aggiungere un gateway.'],
 [/^gateway|^router$/i,'Indirizzo del router usato dai dispositivi di questa rete.'],
 [/^inizio pool/i,'Primo indirizzo che il server DHCP può assegnare.'],
 [/^fine pool/i,'Ultimo indirizzo assegnabile dal DHCP.'],
 [/dhcp secondario/i,'Distribuisce indirizzi solo sulla rete secondaria selezionata.'],
 [/dhcp primario|pi-hole primario/i,'Usa il DHCP di Pi-hole sull’interfaccia principale.'],
 [/dns distribuito/i,'Indirizzo del server DNS che verrà comunicato ai client.'],
 [/^dns$|server dns/i,'Server utilizzato per risolvere i nomi di dominio.'],
 [/^wan|uscita internet/i,'Collegamento utilizzato per raggiungere Internet.'],
 [/^lan/i,'Rete locale dei dispositivi.'],
 [/^vlan|^vid/i,'Identificativo numerico VLAN dello switch o dell’interfaccia.'],
 [/^pvid/i,'VLAN assegnata ai pacchetti in ingresso privi di tag.'],
 [/tagged/i,'VLAN trasportate con tag 802.1Q, separate da virgole.'],
 [/^porta|^porte/i,'Seleziona le porte fisiche coinvolte nella configurazione.'],
 [/^bond|bonding/i,'Unisce porte compatibili in una singola interfaccia logica.'],
 [/^bridge/i,'Collega più porte all’interno della stessa rete locale.'],
 [/^stp/i,'Riduce il rischio di loop Layer 2 quando sono presenti più collegamenti.'],
 [/^lacp/i,'Usa solo se lo switch è configurato per aggregazione 802.3ad.'],
 [/^zona/i,'Gruppo di rete a cui applicare regole di accesso.'],
 [/^policy|^azione predefinita/i,'Consenti o blocca il traffico secondo la regola scelta.'],
 [/^priorit[aà]/i,'Le connessioni con priorità maggiore sono preferite quando disponibili.'],
 [/^capacit[aà]|^velocit[aà]/i,'Velocità stimata del collegamento, in Mbit/s.'],
 [/^upload/i,'Limite della velocità in uscita, in Mbit/s.'],
 [/^download/i,'Limite della velocità in ingresso, in Mbit/s.'],
 [/^ack/i,'Riduce il traffico degli ACK dove compatibile.'],
 [/^diffserv/i,'Distribuisce il traffico nelle classi di priorità CAKE.'],
 [/^overhead/i,'Compensa i byte aggiunti dal collegamento fisico.'],
 [/^nat/i,'Traduce gli indirizzi delle reti private verso l’uscita.'],
 [/^porta (esterna|interna)/i,'Porta del servizio a cui si applica la regola NAT.'],
 [/^indirizzo destinazione/i,'Indirizzo del dispositivo a cui inoltrare il traffico.'],
 [/^mac/i,'Indirizzo hardware rilevato o registrato per il dispositivo.'],
 [/^tipo dispositivo/i,'Categoria identificata nell’inventario, usata per suggerire le policy.'],
 [/^internet/i,'Consente o blocca l’accesso del dispositivo a Internet.'],
 [/^dot|^quic|^vpn/i,'Imposta la policy per questo protocollo o servizio.'],
 [/^seleziona|^attiva/i,'Abilita la scelta in questo profilo.'],
 [/^nome/i,'Nome riconoscibile utilizzato per identificare l’elemento.'],
 [/^durata|^intervallo/i,'Tempo di validità o frequenza dell’operazione.'],
 [/^limite/i,'Soglia oltre la quale la regola viene applicata.']
];
function helpFor(label,control){
 const raw=String(label||'').replace(/\s+/g,' ').trim().slice(0,90);
 for(const [pattern,explain] of IPTM_FIELD_HINTS)if(pattern.test(raw))return explain;
 if(control.type==='checkbox'||control.type==='radio')return 'Abilita questa scelta nel profilo corrente.';
 if(control.tagName==='SELECT')return 'Scegli il valore da usare per '+raw+'.';
 if(control.type==='number')return 'Inserisci il valore numerico richiesto per '+raw+'.';
 return 'Inserisci il valore di '+raw+'. Controlla le modifiche prima di salvarle.';
}
function optionDescriptions(scope=document){
 for(const label of scope.querySelectorAll('label')){
  if(!one(label,'iptmHelpReady'))continue;
  const control=label.querySelector('input:not([type=hidden]),select,textarea') ||
    (label.htmlFor ? document.getElementById(label.htmlFor) : null);
  if(!control || control.type==='hidden' || control.closest('.iptm-table-scroll'))continue;
  if(control.hasAttribute('aria-describedby') || control.hasAttribute('aria-description') ||
     label.querySelector('.iptm-hint,.mut,small,[data-iptm-help]'))continue;
  let raw=label.querySelector(':scope > span')?.textContent || label.textContent || control.name;
  raw=raw.replace(/\s+/g,' ').trim();
  if(!raw || raw.length>80)continue;
  const explain=helpFor(raw,control);
  control.setAttribute('aria-description',explain);
  if(!control.title)control.title=explain;
  const tip=document.createElement('span');tip.className='iptm-field-help';tip.textContent=explain;
  tip.setAttribute('data-iptm-help','');label.append(tip);
 }
}

function applicationSelection(){
 const form=document.getElementById('iptm-app-selection');if(!form||!one(form,'iptmAppSelection'))return;
 const rows=[...form.querySelectorAll('tr')].filter(r=>r.querySelector('.acb'));
 const toolbar=document.createElement('div');toolbar.className='iptm-app-toolbar';
 const label=document.createElement('label');label.textContent='Cerca software';label.htmlFor='iptm-app-filter';
 const input=document.createElement('input');input.type='search';input.id=label.htmlFor;input.placeholder='Nome, categoria o porta';
 const count=document.createElement('output');count.setAttribute('aria-live','polite');
 const select=document.createElement('button');select.type='button';select.className='s';select.textContent='Seleziona risultati visibili';
 const clear=document.createElement('button');clear.type='button';clear.className='s';clear.textContent='Deseleziona risultati visibili';
 const normalize=v=>String(v).toLocaleLowerCase('it').normalize('NFD').replace(/[\u0300-\u036f]/g,'');
 function update(){const q=normalize(input.value.trim());let shown=0,checked=0;
  for(const row of rows){row.hidden=!!q&&!normalize(row.textContent).includes(q);if(!row.hidden)shown++;if(row.querySelector('.acb').checked)checked++;}
  if(q)for(const detail of form.querySelectorAll('details'))if([...detail.querySelectorAll('tr')].some(r=>!r.hidden&&r.querySelector('.acb')))detail.open=true;
  count.textContent=shown+' risultati · '+checked+' profili selezionati (anche nascosti)';
 }
 function changeVisible(value){for(const row of rows){const box=row.querySelector('.acb');if(!row.hidden&&row.getClientRects().length&&!box.disabled)box.checked=value;}update();}
 select.addEventListener('click',()=>changeVisible(true));clear.addEventListener('click',()=>changeVisible(false));input.addEventListener('input',update);
 form.addEventListener('change',update);form.addEventListener('click',e=>{if(e.target.closest('button[type=button]'))queueMicrotask(update);});
 toolbar.append(label,input,select,clear,count);form.prepend(toolbar);update();
}
function hydrate(scope=document){
 const tasks=[['tables',()=>tables(scope)],['policy',policy],['pihole',pihole],['dns',dnsFlow],['qos',qosCountdown],['search',panelSearch],['help',()=>optionDescriptions(scope)],['apps',applicationSelection]];
 for(const [name,task] of tasks){try{task();}catch(error){console.warn('IPTM UI '+name,error);}}
}
function fragments(){
 for(const root of document.querySelectorAll('[data-fragment],[data-iptm-fragment]')){
  if(!one(root,'iptmFragmentReady'))continue;
  const page=root.dataset.fragment||root.dataset.iptmFragment;if(!page)continue;
  const card=root.dataset.fragment?document.querySelector('.iptm-loading'):null;
  let ctrl=null;
  async function load(){
   ctrl?.abort();const request=new AbortController();ctrl=request;
   if(card){card.hidden=false;const state=card.querySelector('[role=status]');if(state)state.textContent='Caricamento dati…';}
   else root.textContent='Caricamento diagnostica…';
   const url=new URL(location.href);url.searchParams.set('p',page);url.searchParams.set('fragment',page);
   const timeout=setTimeout(()=>request.abort(),20000);
   try{
    const res=await fetch(url.toString(),{credentials:'same-origin',cache:'no-store',signal:request.signal,headers:{'X-IPTM-Fragment':'1'}});
    if(!res.ok)throw Error('HTTP '+res.status);
    const html=await res.text();if(request.signal.aborted||ctrl!==request)return;
    if(!html.trim()||/^\s*(?:<!doctype html|<html[\s>])/i.test(html))throw Error('Sessione scaduta o risposta non valida: ricarica la pagina');
    root.innerHTML=html;
    if(card)card.hidden=true;
    hydrate(root);
    document.dispatchEvent(new CustomEvent('iptm:fragment-ready',{detail:{page}}));
   }catch(e){
    if(request.signal.aborted&&ctrl!==request)return;
    const message=e.name==='AbortError'?'tempo scaduto':('HTTP/servizio: '+String(e.message||e));
    if(card){const state=card.querySelector('[role=status]');if(state)state.textContent='Dati non disponibili ('+message+'). Puoi continuare a usare il menu.';}
    else{root.replaceChildren();const label=document.createElement('span');label.textContent='Diagnostica non disponibile ('+message+'). ';
      const retry=document.createElement('button');retry.type='button';retry.className='s';retry.textContent='Riprova';retry.addEventListener('click',load);root.append(label,retry);}
   }finally{clearTimeout(timeout);}
  }
  card?.querySelector('[data-async-retry]')?.addEventListener('click',load);
  load();
 }
}
document.addEventListener('change',e=>{
 const input=e.target;
 if(!(input instanceof HTMLInputElement)||!input.matches('.iptm-iot-flags input[name="flags[]"]')||!input.checked)return;
 const group=input.closest('.iptm-iot-flags');if(!group)return;
 for(const other of group.querySelectorAll('input[name="flags[]"]')){
  if(other!==input&&(input.value==='forward'||other.value==='forward'))other.checked=false;
 }
});
document.addEventListener('click',e=>{
 const button=e.target instanceof Element?e.target.closest('[data-iptm-mac-select]'):null;
 if(!button)return;
 const choice=button.getAttribute('data-iptm-mac-select');
 if(!['all','suggested','none'].includes(choice))return;
 for(const input of document.querySelectorAll('.iptm-iot-unified-table .iptm-mac-selected:not(:disabled)')){
  input.checked=choice==='all'||(choice==='suggested'&&input.dataset.iotHint==='1');
 }
});
hydrate();fragments();
})();
