(function(){
const $=s=>document.querySelector(s);
// countdown rollback
const cd=$('#cd');if(cd){const u=+cd.dataset.until;const t=()=>{const r=u-Math.floor(Date.now()/1000);cd.textContent=Math.max(r,0);if(r<=-3)location.reload();};t();setInterval(t,1000);}
const MODEL=window.MODEL||{};
const SN={'limit':'-m limit --limit 10/min --limit-burst 20','hashlimit (per sorgente)':'-m hashlimit --hashlimit-name nome --hashlimit-mode srcip --hashlimit-upto 10/sec --hashlimit-burst 20','connlimit (max connessioni)':'-m connlimit --connlimit-above 10 --connlimit-mask 32','recent (anti brute-force)':'-m recent --name nome --update --seconds 60 --hitcount 15','ipset':'-m set --match-set nome src','commento':'-m comment --comment "testo"','tipo indirizzo':'-m addrtype --dst-type MULTICAST','MAC sorgente':'-m mac --mac-source AA:BB:CC:DD:EE:FF','intervallo IP':'-m iprange --src-range 192.168.1.10-192.168.1.50','orario':'-m time --timestart 08:00 --timestop 18:00 --weekdays Mon,Tue,Wed,Thu,Fri','stringa nel payload':'-m string --string "testo" --algo bm','flag TCP':'--tcp-flags SYN,RST SYN','solo SYN':'--syn','tipo ICMP':'--icmp-type echo-request','utente (OUTPUT)':'-m owner --uid-owner 1000','lunghezza':'-m length --length 0:28','TTL':'-m ttl --ttl-eq 1','mark':'-m mark --mark 1','tipo pacchetto':'-m pkttype --pkt-type broadcast'};
const sn=$('#snip');if(sn){for(const k in SN){const o=document.createElement('option');o.value=SN[k];o.textContent=k;sn.appendChild(o);}sn.onchange=()=>{if(sn.value){const e=$('#extra');e.value=(e.value.trim()+' '+sn.value).trim();sn.selectedIndex=0;}};}
const TH={ACCEPT:['','Accetta e termina la valutazione.'],DROP:['','Scarta in silenzio (il mittente va in timeout).'],REJECT:['--reject-with tcp-reset','Rifiuta avvisando il mittente. Valori: icmp-port-unreachable, tcp-reset, icmp-host-prohibited…'],LOG:['--log-prefix "IPT: " --log-level 4','Scrive nel log del kernel e CONTINUA con la regola dopo.'],RETURN:['','Esce dalla catena corrente.'],DNAT:['--to-destination 192.168.1.10:8080','Solo nat PREROUTING/OUTPUT: cambia la destinazione.'],SNAT:['--to-source 203.0.113.5','Solo nat POSTROUTING: IP sorgente fisso.'],MASQUERADE:['','Solo nat POSTROUTING: usa l\'IP dell\'interfaccia di uscita.'],REDIRECT:['--to-ports 8080','nat: reindirizza a una porta locale.'],TCPMSS:['--clamp-mss-to-pmtu','mangle FORWARD: adatta la MSS.'],MARK:['--set-mark 1','mangle: marca il pacchetto.'],CT:['--notrack','raw: esclude dal connection tracking.'],NOTRACK:['','raw: esclude dal tracking (kernel vecchi).']};
const ft=$('#f_t'),fc=$('#f_c'),tg=$('#tgt'),ps=$('#posSel');
function chainsOf(t){return Object.keys(MODEL[t]||{});}
function setOptions(select,values,selected){
 // textContent is required here: chain names are configuration, not HTML.
 select.replaceChildren();
 for(const value of values){const opt=new Option(value,value,false,value===selected);select.add(opt);}
}
function fillAll(first){
 if(!ft||!fc||!tg||!ps)return;
 const t=ft.value;const all=chainsOf(t),old=first!==false?fc.dataset.cur:fc.value;
 setOptions(fc,old&&!all.includes(old)?[old,...all]:all,old);
 const std=Object.keys(TH),cust=all.filter(c=>!['INPUT','FORWARD','OUTPUT','PREROUTING','POSTROUTING'].includes(c));
 const cur=tg.dataset.cur;
 tg.replaceChildren(new Option('(nessuna azione: solo contatore)',''));
 const actions=document.createElement('optgroup');actions.label='Azioni';
 for(const value of std)actions.append(new Option(value,value));
 const chains=document.createElement('optgroup');chains.label='Salta a catena';
 for(const value of cust)chains.append(new Option(value,value));
 tg.append(actions,chains);
 if(cur&&![...tg.options].some(o=>o.value===cur))tg.add(new Option(cur,cur));
 if(first!==false)tg.value=cur||'ACCEPT';
 hint();fillPos();
}
function hint(){const h=TH[tg.value];$('#thint').textContent=h?h[1]:(tg.value?'Salta alla catena «'+tg.value+'»; se non decide, torna qui.':'');}
function fillPos(){
 if(!ft||!fc||!ps)return;
 const list=(MODEL[ft.value]||{})[fc.value]?.r||[];
 ps.replaceChildren();
 if(ps.dataset.edit==='1')ps.add(new Option('Mantieni la posizione attuale','keep'));
 ps.add(new Option('In fondo (prima dell’eventuale regola finale «catch-all»)','smart'));
 ps.add(new Option('In cima','start'));
 ps.add(new Option('In fondo assoluto','last'));
 for(const item of list){
  const n=String(item[0]);const label=String(item[1]);
  ps.add(new Option('Prima della regola #'+n+': '+label.slice(0,90),n));
 }
}
if(ft){ft.onchange=()=>fillAll(false);fc.onchange=fillPos;tg.onchange=hint;fillAll(true);
 const tu=$('#tuse');if(tu)tu.onclick=e=>{e.preventDefault();const h=TH[tg.value];if(h)document.querySelector('[name=targs]').value=h[0];};}
// ============ WIZARD ============
const root=$('#wiz');if(!root)return;
const j=(...a)=>a.filter(Boolean).join(' ');const po=(p,f)=>p.includes(',')?`-m multiport --${f}s ${p}`:`--${f} ${p}`;
const R={ip:/^!?\s*\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?(,\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?)*$/,ports:/^\d{1,5}(:\d{1,5})?(,\d{1,5}(:\d{1,5})?)*$/,port:/^\d{1,5}$/,if:/^[A-Za-z0-9_.+-]{1,15}$/,num:/^\d{1,9}$/,rate:/^\d{1,6}\/(sec|min|hour|day)$/,txt:/^[^"\\\r\n]*$/};
const actsOpt=()=>['DROP','REJECT',...chainsOf('filter').filter(c=>!['INPUT','FORWARD','OUTPUT'].includes(c))];
const SC=[
{id:'open',i:'🔓',n:'Apri una porta',d:'Permetti connessioni in ingresso verso un servizio di questo server (web, SSH, VPN…).',pos:'smart',f:[
 {id:'proto',l:'Protocollo',o:['tcp','udp','tcp+udp'],h:'TCP per web/SSH, UDP per DNS/VPN/giochi.'},
 {id:'ports',l:'Porta/e',t:'ports',req:1,ph:'443  oppure  80,443  oppure  5000:5100',h:'Singola, lista con virgole (max 15) o intervallo con «:».'},
 {id:'src',l:'Consenti solo da (opz.)',t:'ip',ph:'192.168.1.0/24',h:'Vuoto = da chiunque. Più sicuro limitare alla tua rete.'},
 {id:'if',l:'Solo dall\'interfaccia (opz.)',t:'if',ph:'bond0'}],
 gen:v=>(v.proto==='tcp+udp'?['tcp','udp']:[v.proto]).map(p=>({t:'filter',r:j('-A INPUT',v.if&&'-i '+v.if,v.src&&'-s '+v.src,'-p '+p,po(v.ports,'dport'),'-j ACCEPT')})),
 note:'Controlla nel passo successivo che la regola stia PRIMA di eventuali blocchi più generici sulla stessa porta.'},
{id:'block',i:'⛔',n:'Blocca un IP o una rete',d:'Scarta o rifiuta tutto il traffico proveniente da un indirizzo.',pos:'start',f:[
 {id:'addr',l:'Indirizzo / rete da bloccare',t:'ip',req:1,ph:'203.0.113.7  oppure  198.51.100.0/24'},
 {id:'dir',l:'Dove',o:['INPUT (verso questo server)','FORWARD (traffico instradato)','entrambe'],h:'INPUT protegge l\'host, FORWARD le macchine dietro di lui.'},
 {id:'act',l:'Azione',o:actsOpt,h:'DROP = silenzio; REJECT = rifiuto esplicito; LOG-DROP (se presente) = scarta e registra.'}],
 gen:v=>(v.dir.startsWith('INPUT')||v.dir==='entrambe'?['INPUT']:[]).concat(v.dir.startsWith('FORWARD')||v.dir==='entrambe'?['FORWARD']:[]).map(c=>({t:'filter',r:j('-A '+c,'-s '+v.addr,'-j '+v.act)})),
 note:'La regola viene messa in cima. Le connessioni già stabilite possono restare attive se una regola ESTABLISHED le accetta prima.'},
{id:'fwd',i:'🔀',n:'Port forwarding (inoltra una porta a un altro dispositivo)',d:'Reindirizza una porta in ingresso verso un PC/server della rete (DNAT + permesso FORWARD).',pos:'smart',f:[
 {id:'proto',l:'Protocollo',o:['tcp','udp']},{id:'eport',l:'Porta esterna',t:'port',req:1,ph:'8080'},
 {id:'ip',l:'IP di destinazione interno',t:'ip',req:1,ph:'192.168.1.50'},{id:'tport',l:'Porta di destinazione (vuoto = stessa)',t:'port',ph:'80'},
 {id:'if',l:'Interfaccia di ingresso (opz.)',t:'if',ph:'bond0',h:'Consigliato: limita il forward al lato Internet/modem.'}],
 gen:v=>[{t:'nat',r:j('-A PREROUTING',v.if&&'-i '+v.if,'-p '+v.proto,'--dport '+v.eport,'-j DNAT --to-destination '+v.ip+':'+(v.tport||v.eport))},{t:'filter',r:j('-A FORWARD','-d '+v.ip,'-p '+v.proto,'--dport '+(v.tport||v.eport),'-j ACCEPT')}],
 note:'Vengono create 2 regole: il DNAT (tabella nat) e l\'ACCEPT in FORWARD. Dalla stessa LAN potrebbe servire anche un MASQUERADE (hairpin NAT).'},
{id:'nat',i:'🌐',n:'Condividi la connessione (NAT in uscita)',d:'Fai uscire una rete interna verso Internet con l\'IP dell\'interfaccia esterna.',pos:'smart',f:[
 {id:'type',l:'Tipo',o:['MASQUERADE (IP dinamico)','SNAT (IP pubblico fisso)']},{id:'oif',l:'Interfaccia di uscita',t:'if',req:1,ph:'bond0'},
 {id:'src',l:'Solo per la rete (opz.)',t:'ip',ph:'192.168.1.0/24'},{id:'to',l:'IP pubblico (solo SNAT)',t:'ip',ph:'203.0.113.5'}],
 gen:v=>[{t:'nat',r:j('-A POSTROUTING',v.src&&'-s '+v.src,'-o '+v.oif,v.type.startsWith('SNAT')?'-j SNAT --to-source '+v.to:'-j MASQUERADE')}],
 note:'Serve anche che il traffico sia permesso in FORWARD (e net.ipv4.ip_forward=1).'},
{id:'brute',i:'🛡',n:'Proteggi un servizio da brute-force (connlimit + recent)',d:'Limita connessioni simultanee e tentativi al minuto su una porta (es. SSH). Crea 3 regole.',pos:'smart',f:[
 {id:'proto',l:'Protocollo',o:['tcp','udp']},{id:'port',l:'Porta',t:'port',req:1,d:'22'},{id:'src',l:'Sorgente (opz.)',t:'ip',ph:'192.168.1.0/24'},
 {id:'maxc',l:'Max connessioni simultanee per IP',t:'num',d:'10'},{id:'hits',l:'Max nuove connessioni nel periodo',t:'num',d:'15'},{id:'secs',l:'Periodo (secondi)',t:'num',d:'60'},
 {id:'act',l:'Azione se superato',o:actsOpt}],
 gen:v=>{const b=j('-p '+v.proto,'--dport '+v.port),s=v.src&&'-s '+v.src,n='rl'+v.port;return [
  {t:'filter',r:j('-A INPUT',s,b,'-m connlimit --connlimit-above '+v.maxc+' --connlimit-mask 32','-j '+v.act)},
  {t:'filter',r:j('-A INPUT',s,b,'-m recent --name '+n+' --update --seconds '+v.secs+' --hitcount '+v.hits,'-j '+v.act)},
  {t:'filter',r:j('-A INPUT',s,b,'-m recent --name '+n+' --set','-j ACCEPT')}];},
 note:'Le 3 regole devono restare nell\'ordine mostrato e consecutive.'},
{id:'flood',i:'🌊',n:'Anti-flood per sorgente (hashlimit)',d:'Scarta chi supera una certa frequenza di pacchetti, calcolata per singolo IP.',pos:'smart',f:[
 {id:'proto',l:'Protocollo',o:['tcp','udp','icmp']},{id:'port',l:'Porta (opz., tcp/udp)',t:'ports',ph:'80,443'},
 {id:'syn',l:'Solo nuovi SYN (tcp)',o:['no','sì']},{id:'rate',l:'Soglia al secondo',t:'num',d:'50'},{id:'burst',l:'Burst',t:'num',d:'100'},{id:'act',l:'Azione',o:actsOpt}],
 gen:v=>[{t:'filter',r:j('-A INPUT','-p '+v.proto,v.port&&v.proto!=='icmp'&&po(v.port,'dport'),v.syn==='sì'&&v.proto==='tcp'&&'--syn','-m hashlimit --hashlimit-name fl'+(Date.now()%1e6)+' --hashlimit-mode srcip --hashlimit-above '+v.rate+'/sec --hashlimit-burst '+v.burst,'-j '+v.act)}],
 note:'Metti questa regola PRIMA di quelle che accettano il traffico, altrimenti non scatta mai.'},
{id:'fw2',i:'↔',n:'Traffico tra reti (FORWARD)',d:'Consenti o vieta la comunicazione fra due reti/dispositivi che attraversano questo router.',pos:'smart',f:[
 {id:'src',l:'Rete/IP di origine',t:'ip',req:1,ph:'192.168.10.0/24'},{id:'dst',l:'Rete/IP di destinazione',t:'ip',req:1,ph:'192.168.1.0/24'},
 {id:'proto',l:'Protocollo',o:['qualsiasi','tcp','udp','icmp']},{id:'port',l:'Porta/e di destinazione (opz.)',t:'ports',ph:'22'},
 {id:'act',l:'Azione',o:['ACCEPT','DROP','REJECT']}],
 gen:v=>[{t:'filter',r:j('-A FORWARD','-s '+v.src,'-d '+v.dst,v.proto!=='qualsiasi'&&'-p '+v.proto,v.port&&v.proto!=='qualsiasi'&&v.proto!=='icmp'&&po(v.port,'dport'),'-j '+v.act)}],
 note:'Le risposte passano già dalla regola RELATED,ESTABLISHED, se presente.'},
{id:'log',i:'📝',n:'Registra pacchetti nel log',d:'Scrivi nel log del sistema i pacchetti che corrispondono (con limite di frequenza).',pos:'smart',f:[
 {id:'chain',l:'Catena',o:['INPUT','FORWARD','OUTPUT']},{id:'proto',l:'Protocollo',o:['qualsiasi','tcp','udp','icmp']},{id:'port',l:'Porta/e (opz.)',t:'ports'},
 {id:'src',l:'Sorgente (opz.)',t:'ip'},{id:'prefix',l:'Prefisso nel log',t:'txt',d:'IPT-LOG: '},{id:'rate',l:'Limite',t:'rate',d:'5/min',h:'Formato n/sec|min|hour|day'}],
 gen:v=>[{t:'filter',r:j('-A '+v.chain,v.src&&'-s '+v.src,v.proto!=='qualsiasi'&&'-p '+v.proto,v.port&&v.proto!=='qualsiasi'&&v.proto!=='icmp'&&po(v.port,'dport'),'-m limit --limit '+v.rate,'-j LOG --log-prefix "'+v.prefix+'" --log-level 4')}],
 note:'LOG non ferma il pacchetto: le regole successive decidono comunque cosa farne.'}];
const st={s:null,V:{},step:1};
const setStep=n=>{st.step=n;root.querySelectorAll('.steps span').forEach((e,i)=>e.classList.toggle('on',i===n-1));};
const B=$('#wbody');
function s1(){setStep(1);B.innerHTML='<p class=mut>Cosa vuoi fare? Ti guido passo dopo passo e scrivo io la regola corretta.</p><div class=grid>'+SC.map(s=>`<div class=sc data-id=${s.id}><div class=i>${s.i}</div><b>${s.n}</b><div class=mut>${s.d}</div></div>`).join('')+'<a class=sc href="?p=rule" style="color:inherit"><div class=i>🛠</div><b>Regola avanzata</b><div class=mut>Modulo completo con tutte le opzioni di iptables.</div></a></div>';
 B.querySelectorAll('.sc[data-id]').forEach(e=>e.onclick=()=>{st.s=SC.find(s=>s.id===e.dataset.id);s2();});}
function s2(){setStep(2);const s=st.s;B.innerHTML=`<h3>${s.i} ${s.n}</h3><p class=mut>${s.d}</p><div id=werr class="msg err" style="display:none"></div><div class=row>`+s.f.map(f=>{const o=typeof f.o==='function'?f.o():f.o;const id='w_'+f.id,val=st.V[f.id]??f.d??'';
  return `<label class=fl><span>${f.l}${f.req?' *':''}</span>${o?`<select id=${id}>${o.map(x=>`<option${x===val?' selected':''}>${x}</option>`).join('')}</select>`:`<input id=${id} value="${String(val).replace(/"/g,'&quot;')}" placeholder="${f.ph||''}">`}<small>${f.h||''}</small></label>`;}).join('')+'</div><p><button class=s id=bk>← Indietro</button> <button id=nx>Avanti →</button></p>';
 $('#bk').onclick=s1;$('#nx').onclick=()=>{const V={},er=[];for(const f of s.f){const v=document.getElementById('w_'+f.id).value.trim();V[f.id]=v;if(!v&&f.req)er.push(f.l+': obbligatorio');else if(v&&f.t&&R[f.t]&&!R[f.t].test(v))er.push(f.l+': formato non valido');}
  if(er.length){const e=$('#werr');e.style.display='block';e.innerHTML=er.join('<br>');return;}st.V=V;st.rules=s.gen(V);s3();};}
function s3(){setStep(3);const r0=st.rules[0],ch=r0.r.split(' ')[1],L=(MODEL[r0.t]||{})[ch]?.r||[];
 B.innerHTML=`<h3>Dove inserire la regola in ${r0.t}/${ch}?</h3><p class=mut>Le regole si leggono dall'alto: la prima che corrisponde vince. Se esiste già una regola più generica sopra, la tua potrebbe non scattare mai.</p>
 <label class=fl><span>Posizione</span><select id=wpos><option value=smart>In fondo (prima dell'eventuale regola finale «catch-all»)</option><option value=start>In cima</option><option value=last>In fondo assoluto</option>${L.map(r=>`<option value=${r[0]}>Prima della regola #${r[0]}: ${r[1].replace(/</g,'&lt;').slice(0,90)}</option>`).join('')}</select></label>
 <label class=fl><span>Commento da salvare nel file (opz.)</span><input id=wcmt value="${st.s.n}"></label><p><button class=s id=bk>← Indietro</button> <button id=nx>Avanti →</button></p>`;
 $('#wpos').value=st.s.pos;$('#bk').onclick=s2;$('#nx').onclick=()=>{st.pos=$('#wpos').value;st.cmt=$('#wcmt').value.replace(/"/g,"'");s4();};}
function s4(){setStep(4);B.innerHTML=`<h3>Riepilogo</h3><p>Verranno aggiunte <b>${st.rules.length}</b> regole alla <b>bozza</b> (il firewall attivo non cambia finché non premi «Applica»):</p><pre>${st.rules.map(r=>'['+r.t+'] '+r.r).join('\n').replace(/</g,'&lt;')}</pre><p class=mut>💡 ${st.s.note}</p>
 <form method=post>${window.FH}<input type=hidden name=action value=wizard_add><input type=hidden name=rules id=wr><input type=hidden name=pos value="${st.pos}"><input type=hidden name=cmt value="${st.cmt.replace(/"/g,'&quot;')}"><button class=s type=button id=bk>← Indietro</button> <button class=g>✔ Aggiungi alla bozza</button></form>`;
 $('#wr').value=JSON.stringify(st.rules);$('#bk').onclick=s3;}
s1();
})();
