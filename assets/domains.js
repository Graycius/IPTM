/* IPTM 4.3.5 · Unico wizard Anti-DPI, importazione asincrona e DOM-hostlist.
   Non richiama operazioni live: importazione, salvataggio e attivazione restano separati. */
(() => {
'use strict';
const MAX_BYTES=16*1024*1024; // Nessun tetto numerico sui domini; protezione memoria/input.
const GROUPS=[
 ['Video e streaming', [['YouTube',['youtube.com','youtu.be','googlevideo.com','ytimg.com','youtube-nocookie.com']],['Netflix',['netflix.com','nflxvideo.net','nflximg.net','nflxso.net']],['Twitch',['twitch.tv','ttvnw.net','jtvnw.net']],['Prime Video',['primevideo.com','amazonvideo.com']],['Disney+',['disneyplus.com','bamgrid.com']],['Vimeo',['vimeo.com','vimeocdn.com']]]],
 ['Social network', [['Instagram',['instagram.com','cdninstagram.com']],['Facebook',['facebook.com','fbcdn.net','messenger.com']],['TikTok',['tiktok.com','tiktokcdn.com']],['X / Twitter',['x.com','twitter.com','twimg.com']],['Reddit',['reddit.com','redd.it','redditmedia.com']]]],
 ['Messaggistica', [['Discord',['discord.com','discord.gg','discordapp.com','discordapp.net']],['WhatsApp',['whatsapp.com','web.whatsapp.com','whatsapp.net']],['Telegram',['telegram.org','web.telegram.org','t.me']],['Signal',['signal.org','signal.me']]]],
 ['Videoconferenze e lavoro', [['Zoom',['zoom.us','zoom.com']],['Google Meet',['meet.google.com']],['Microsoft Teams',['teams.microsoft.com','teams.live.com']],['Slack',['slack.com','slack-edge.com']]]],
 ['Gaming', [['Steam',['steampowered.com','steamcommunity.com','steamcontent.com','steamstatic.com']],['Epic Games',['epicgames.com','unrealengine.com']],['Xbox',['xbox.com','xboxlive.com']],['PlayStation',['playstation.com','playstation.net']],['Roblox',['roblox.com','rbxcdn.com']]]],
 ['Cloud e sviluppo', [['GitHub',['github.com','githubusercontent.com','githubassets.com']],['GitLab',['gitlab.com','gitlab.io']],['Google Drive',['drive.google.com','docs.google.com']],['Dropbox',['dropbox.com','dropboxusercontent.com']]]],
 ['Musica e podcast', [['Spotify',['spotify.com','scdn.co','spotifycdn.com']],['SoundCloud',['soundcloud.com','sndcdn.com']],['Deezer',['deezer.com','dzcdn.net']]]],
 ['Informazione e comunità', [['Wikipedia',['wikipedia.org','wikimedia.org']],['Archive.org',['archive.org','archive-it.org']],['Stack Overflow',['stackoverflow.com','stackexchange.com']]]]
];
const utf8Size = s => new TextEncoder().encode(s).length;
const create=(tag,attrs={},label='')=>{const el=document.createElement(tag); for(const [key,value] of Object.entries(attrs)){ if(key==='className')el.className=value;else el.setAttribute(key,value); }if(label)el.textContent=label;return el;};
const domainRe=/^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
function normalize(line){
 let value=String(line).split('#',1)[0].trim();if(!value || value.startsWith('!'))return '';
 const bits=value.split(/\s+/);if(bits.length>1&&/^(?:0\.0\.0\.0|127\.0\.0\.1|::|::1)$/.test(bits[0]))value=bits[1];
 else if(bits.length!==1)return '';
 if(/^https?:\/\//i.test(value)){try{value=new URL(value).hostname;}catch(_){return '';}}
 value=value.toLowerCase().replace(/\.$/,'');return domainRe.test(value)?value:'';
}
function parse(text){const result=new Set();for(const line of String(text).split(/\r?\n/)){const v=normalize(line);if(v)result.add(v);}return result;}
function merge(...sets){const result=new Set();for(const items of sets)for(const item of items)result.add(item);return result;}
function renderList(textarea,set){
 const output=[...set].sort().join('\n');
 if(utf8Size(output)>MAX_BYTES)throw Error('Hostlist oltre il limite tecnico di 16 MiB; non è previsto un limite numerico di domini.');
 textarea.value=output;
 textarea.dispatchEvent(new Event('change',{bubbles:true}));
}
function start(form){
 const known=form.querySelector('[data-antidpi-known]');
 const local=form.querySelector('[name="source_local"]');
 const upload=form.querySelector('[data-antidpi-file]');
 const notice=form.querySelector('[data-antidpi-import-info]');
 const submit=form.querySelector('button[type="submit"]');
 const progress=form.querySelector('[data-antidpi-progress]')||create('progress',{'data-antidpi-progress':'',max:'1'});
 const report=form.querySelector('[data-antidpi-download-report]')||create('div',{'data-antidpi-download-report':''});
 const next=form.querySelector('[data-antidpi-next]')||create('button',{type:'button','data-antidpi-next':''},'Prosegui');
 if(!progress.isConnected){progress.hidden=true;form.append(progress);}
 if(!report.isConnected)form.append(report);
 if(!next.isConnected){next.hidden=true;form.append(next);}
 const engine=form.querySelector('[name="zapret_engine"]')?.value||'zapret2';
 const profile=[...document.querySelectorAll('form')].find(f=>f.querySelector('input[name="zapret_op"][value="configure"]'));
 const profileDomains=profile?.querySelector('[name="zapret_domains"]');
 if(!known||!local||!upload||!notice||!submit||!progress||!report||!next||!profile||!profileDomains)return;
 const storageKey='iptm:antidpi:import-flags:v1:'+engine;
 const importedKey='iptm:antidpi:imported-token:v1:'+engine;
 const online=()=>[...form.querySelectorAll('input[name="source_ids[]"]')];
 const services=()=>[...known.querySelectorAll('[data-known-domains]')];
 GROUPS.forEach(([name,entries],gi)=>{
  const details=create('details');details.append(create('summary',{},name));
  const container=create('div',{className:'iptm-domain-services'});
  entries.forEach(([label,domains],si)=>{
   const row=create('label',{className:'iptm-domain-service'});
   const checkbox=create('input',{type:'checkbox','data-known-id':`${gi}-${si}`,'data-known-domains':domains.join('\n')});
   row.append(checkbox,document.createTextNode(` ${label} (${domains.length})`));container.append(row);
  });details.append(container);known.append(details);
 });
 const mode=form.querySelector('[name="source_mode"]');
 let manual=parse(profileDomains.value), downloaded=new Set(), generated=new Set(), running=false;
 let composing=false;
 function servicesChosen(){return parse(services().filter(el=>el.checked).map(el=>el.dataset.knownDomains).join('\n'));}
 function syncSelected(){
  if(running)return;
  const auto=servicesChosen();
  renderList(profileDomains,merge(manual,downloaded,auto));generated=merge(downloaded,auto);
 }
 function counters(){for(const [key,inputs] of Object.entries({known:services(),online:online()})){
  const node=form.querySelector(`[data-antidpi-count="${key}"]`);
  if(node)node.textContent=`${inputs.filter(el=>el.checked).length} / ${inputs.length} selezionati`;
 }}
 function saveFlags(){counters();try{localStorage.setItem(storageKey,JSON.stringify({known:services().filter(x=>x.checked).map(x=>x.dataset.knownId),online:online().filter(x=>x.checked).map(x=>x.value),mode:mode?.value||'merge'}));}catch(_){}}
 function restoreFlags(){try{const j=JSON.parse(localStorage.getItem(storageKey)||'null');if(!j||typeof j!=='object')return;
  const k=new Set(Array.isArray(j.known)?j.known:[]),o=new Set(Array.isArray(j.online)?j.online:[]);
  services().forEach(x=>x.checked=k.has(x.dataset.knownId));online().forEach(x=>x.checked=o.has(x.value));
  if(mode&&['merge','replace'].includes(j.mode))mode.value=j.mode;
 }catch(_){}}
 restoreFlags();counters();syncSelected();
 form.querySelectorAll('[data-antidpi-all],[data-antidpi-none]').forEach(btn=>btn.addEventListener('click',()=>{
  const group=btn.dataset.antidpiAll||btn.dataset.antidpiNone;
  const checked=btn.hasAttribute('data-antidpi-all');
  (group==='known'?services():online()).forEach(ch=>ch.checked=checked);
  saveFlags();if(group==='known')syncSelected();
 }));
 form.addEventListener('change',event=>{
  if(event.target.matches('[data-known-domains],input[name="source_ids[]"],[name="source_mode"]')){
   saveFlags();if(event.target.matches('[data-known-domains]'))syncSelected();
  }
 });
 profileDomains.addEventListener('input',()=>{if(composing||running)return;manual=new Set([...parse(profileDomains.value)].filter(x=>!generated.has(x)));});
 next.addEventListener('click',()=>{profile.scrollIntoView({behavior:'smooth',block:'center'});profileDomains.focus();});
 function show(message){notice.textContent=message;}
 function showSources(status){report.replaceChildren();const groups=Array.isArray(status.per_source)?status.per_source:[];
  if(!groups.length)return;
  const ul=create('ul');for(const item of groups){const ok=item.status==='ok';
   ul.append(create('li',{},`${item.id||'fonte'} · ${ok?'OK: '+item.count+' domini':'Errore: '+(item.detail||'fonte non disponibile')}`));
  }report.append(ul);
 }
 async function json(url,opts){
  let r;
  try{r=await fetch(url,{credentials:'same-origin',cache:'no-store',redirect:'follow',...opts});}
  catch(_){throw Error('Connessione al server IPTM non riuscita. Verifica rete e servizio web.');}
  let data=null,raw='';
  try{raw=await r.text();data=JSON.parse(raw);}catch(_){}
  if(!data||typeof data!=='object'||Array.isArray(data)){
   if(r.status===413)throw Error('Richiesta troppo grande per PHP/web server (HTTP 413): verifica post_max_size, upload_max_filesize e client_max_body_size.');
   if(r.status===419||r.status===400)throw Error('Richiesta rifiutata (HTTP '+r.status+'): sessione o token CSRF scaduti, oppure limite PHP post_max_size superato. Ricarica IPTM.');
   if(r.status===401||r.status===403)throw Error('Accesso a IPTM non autorizzato (HTTP '+r.status+'). Accedi nuovamente.');
   if(r.redirected||/<(?:!doctype\s+html|html|form)\b/i.test(raw))
    throw Error('Il server ha restituito HTML invece di JSON. Controlla sessione e versione IPTM (azione antidpi_sources non registrata o moduli non aggiornati).');
   throw Error('Risposta server non JSON (HTTP '+r.status+'). Verifica log PHP/web server e integrità moduli IPTM.');
  }
  if(!r.ok||data.ok!==true)throw Error(typeof data.error==='string'&&data.error?data.error:'Operazione IPTM fallita (HTTP '+r.status+').');
  return data;
 }
 const endpoint=(params)=>'?p=dnsguard&'+new URLSearchParams({zapret_engine:engine,...params}).toString();
 async function waitFor(token,initial){
  let s=initial,attempt=0;
  while(true){
   if(s.state==='downloaded')return s;
   if(s.state==='failed')throw Error(s.error||'Errore durante i download');
   if(!['queued','running','none'].includes(s.state))throw Error('Stato download inatteso: '+s.state);
   const total=Math.max(1,Number(s.source_total)||1),done=Number(s.downloaded_sources)||0;
   progress.hidden=false;progress.max=total;progress.value=done;
   show(`Scaricamento delle raccolte: ${done}/${Number(s.source_total)||0} concluse. Attendo anche quelle ancora in corso…`);
   showSources(s);
   if(attempt++>300)throw Error('Monitoraggio scaduto: il job può continuare sul server. Riapri la pagina per verificarlo.');
   await new Promise(resolve=>setTimeout(resolve,1500));
   s=await json(endpoint({source_poll:'1'}));
   if(s.token!==token)throw Error('Importazione sostituita da una successiva; nessuna lista applicata');
  }
 }
 async function receive(token,total){
  let offset=0;const received=new Set();progress.hidden=false;progress.max=Math.max(1,total);
  while(true){
   const response=await json(endpoint({source_chunk:'1',source_token:token,source_offset:String(offset)}));
   if(response.offset!==offset || !Array.isArray(response.domains) || response.next<=offset && !response.done)throw Error('Blocco download incoerente');
   for(const name of response.domains){if(typeof name!=='string'||!domainRe.test(name))throw Error('Dominio scaricato non valido');received.add(name);}
   offset=response.next;progress.value=received.size;show(`Importazione nel riquadro domini: ${received.size}/${total}…`);
   if(response.done){if(received.size!==total)throw Error('Download parziale: conteggio non corrispondente');break;}
  }
  return received;
 }
 async function prepareLocal(){
  const selected=servicesChosen();let totalSize=0;
  const pieces=[local.value,...selected];
  for(const file of upload.files){totalSize+=file.size;if(totalSize>MAX_BYTES)throw Error('I file locali superano il limite tecnico di 16 MiB');pieces.push(await file.text());}
  const all=pieces.filter(Boolean).join('\n');if(utf8Size(all)>MAX_BYTES)throw Error('Input locale oltre 16 MiB');return all;
 }
 async function submitJob(event){
  event.preventDefault();if(running)return;
  running=true;submit.disabled=true;next.hidden=true;progress.hidden=false;progress.value=0;report.replaceChildren();
  show('Preparazione dei servizi selezionati e avvio download…');
  try{
   const val=name=>profile.querySelector(`[name="${name}"]`)?.value??'';
   const draft={wan_if:val('zapret_wan').trim(),clients:val('zapret_clients').split(/\r?\n/).map(s=>s.trim()).filter(Boolean),
    domains:[...parse(profileDomains.value)],queue:Number(val('zapret_queue')),strategy:val('zapret_strategy')};
   if(!draft.wan_if||!draft.clients.length)throw Error('Compila prima interfaccia WAN e reti IPv4 del profilo.');
   const localText=await prepareLocal();
   if(!online().some(x=>x.checked)&&!localText.trim())throw Error('Seleziona almeno un servizio, raccolta online o file.');
   const fd=new FormData(form);fd.set('source_local',localText);fd.set('source_draft',JSON.stringify(draft));fd.set('source_async','1');
   const response=await json(location.pathname+location.search,{method:'POST',body:fd});
   if(!/^[a-f0-9]{24}$/.test(response.token||''))throw Error('Il server non ha restituito un identificatore valido.');
   // Even a local-only job can finish within start(): get the authoritative
   // server totals instead of assuming an empty (zero-domain) response.
   let state=await json(endpoint({source_poll:'1'}));
   if(state.token!==response.token)throw Error('Il job più recente non corrisponde alla richiesta.');
   if(state.state!=='downloaded')state=await waitFor(response.token,state);
   if((mode?.value||'merge')==='replace' && (state.per_source||[]).some(item=>item.status==='error')){
    showSources(state);throw Error('Sostituzione rifiutata: non tutte le raccolte hanno risposto. Scegli Unisci o riprova.');
   }
   showSources(state);
   const fetched=await receive(response.token,Number(state.download_total)||0);
   // Do not replace the text until the entire transfer and integrity checks finish.
   const before=parse(profileDomains.value);
   const result=(mode?.value||'merge')==='replace'?fetched:merge(before,fetched);
   if(!result.size)throw Error('Nessun dominio valido scaricato');
   composing=true;renderList(profileDomains,result);composing=false;
   manual=(mode?.value||'merge')==='replace'?new Set():new Set([...manual]);
   downloaded=merge(downloaded,fetched);generated=merge(downloaded,servicesChosen());
   progress.value=progress.max;show(`Download terminati. ${fetched.size} domini raccolti, ${result.size} nel profilo. Controlla il riquadro e salva il profilo: Anti-DPI resta inattivo.`);
   next.hidden=false;next.focus();saveFlags();
   try{localStorage.setItem(importedKey,response.token);}catch(_){}
  }catch(error){composing=false;show(error instanceof Error?error.message:'Errore importazione. Nessuna modifica live applicata.');}
  finally{running=false;submit.disabled=false;}
 }
 form.addEventListener('submit',submitJob);
 // Recover a server-side download after a reload without blocking the UI.
 json(endpoint({source_poll:'1'})).then(async s=>{
  if(!['queued','running','downloaded'].includes(s.state)||!/^[a-f0-9]{24}$/.test(s.token||''))return;
  // The same completed job must not be re-injected after a normal profile save
  // and subsequent page reload. Jobs that finished while the page was closed
  // can still be recovered and inserted into the textarea.
  try{if(s.state==='downloaded'&&localStorage.getItem(importedKey)===s.token)return;}catch(_){}
  if(running)return;running=true;submit.disabled=true;
  try{const done=await waitFor(s.token,s);showSources(done);
   if(done.mode==='replace'&&(done.per_source||[]).some(x=>x.status==='error'))throw Error('Sostituzione incompleta: ripeti download o scegli Unisci');
   const fetched=await receive(s.token,Number(done.download_total)||0);
   const result=done.mode==='replace'?fetched:merge(parse(profileDomains.value),fetched);
   composing=true;renderList(profileDomains,result);composing=false;
   downloaded=merge(downloaded,fetched);generated=merge(downloaded,servicesChosen());
   show(`${fetched.size} domini recuperati nel profilo. Salva il profilo per proseguire.`);next.hidden=false;
   try{localStorage.setItem(importedKey,s.token);}catch(_){}
  }catch(e){show(String(e.message||e));}finally{composing=false;running=false;submit.disabled=false;}
 }).catch(()=>{});
}
document.querySelectorAll('form[data-antidpi-unified]').forEach(start);
})();
