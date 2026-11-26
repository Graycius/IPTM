(() => {
  'use strict';
  const bar=document.getElementById('iptm-diag-progress');
  if(!bar)return;
  const stateLabel=document.getElementById('iptm-diag-status');
  const pctLabel=document.getElementById('iptm-diag-pct');
  const report=document.getElementById('iptm-diag-report');
  const summary=document.getElementById('iptm-diag-summary');
  let pending=false;
  const poll=async()=>{
    if(!bar.isConnected){clearInterval(timer);return;}
    if(pending||document.hidden)return;
    pending=true;
    try{
      const r=await fetch('?p=diag&diag_poll=1',{credentials:'same-origin',cache:'no-store',headers:{'Accept':'application/json'},signal:AbortSignal.timeout(15000)});
      if(!r.ok)throw new Error('HTTP '+r.status);
      const json=await r.json();
      if(!json.ok)throw new Error('Stato non disponibile');
      const s=json.state||{};
      const progress=Math.max(0,Math.min(100,Number(s.progress)||0));
      bar.value=progress;if(pctLabel)pctLabel.textContent=progress+'%';
      if(stateLabel)stateLabel.textContent=(s.status||'idle')+' · '+(s.message||'');
      if(s.run){
        const comboRoot=document.getElementById('iptm-diag-combo-results');
        if(comboRoot){
          comboRoot.replaceChildren();
          const combos=(Array.isArray(s.run.results)?s.run.results:[]).filter(v=>v && typeof v==='object' && String(v.option||'').startsWith('combo:'));
          if(!combos.length){const p=document.createElement('p');p.textContent='Nessuna verifica combinatoria ancora disponibile';comboRoot.append(p);}
          for(const item of combos){
            const details=document.createElement('details');
            const head=document.createElement('summary');
            head.textContent=String(item.option||'')+' · '+String(item.result||'unknown');
            const content=document.createElement('p');content.textContent=String(item.detail||'');
            details.append(head,content);comboRoot.append(details);
          }
        }
        if(report)report.textContent=JSON.stringify(s.run,null,2);
        if(summary)summary.textContent=`Risultati: ${s.run.passed||0} passati · ${s.run.warning||0} avvisi · ${s.run.unknown||0} non verificabili · ${s.run.failed||0} falliti · ${s.run.skipped||0} esclusi`;
      }
      if(['completed','failed','stale'].includes(s.status)){clearInterval(timer);}
    }catch(e){if(stateLabel)stateLabel.textContent='Monitoraggio temporaneamente non disponibile; prova a ricaricare la pagina.'}
    finally{pending=false;}
  };
  const timer=setInterval(poll,1200);
  poll();
})();


// Lynis background audit polling (lightweight, authenticated, never waits for Lynis).
(() => {
  const root=document.getElementById('iptm-lynis');
  if (!root || !document.getElementById('iptm-lynis-running'))return;
  const status=root.querySelector('#iptm-lynis-state');
  const elapsed=root.querySelector('#iptm-lynis-elapsed');
  let busy=false;
  const poll=async()=>{
    if(!root.isConnected){clearInterval(timer);return;}
    if(busy || document.hidden)return;
    busy=true;
    try{
      const response=await fetch('?p=health&lynis_poll=1',{credentials:'same-origin',cache:'no-store',signal:AbortSignal.timeout(20000)});
      if(!response.ok)throw new Error('status-unavailable');
      const data=await response.json();
      if(!data.ok)throw new Error('invalid');
      if(elapsed)elapsed.textContent=String(data.elapsed_seconds??0);
      if(data.state!=='running'){
        clearInterval(timer);
        if(status)status.textContent='Audit terminato: ricarico il report completo…';
        window.location.assign('?p=health#iptm-lynis');
      } else if(status){status.textContent='Lynis in esecuzione in background · '+(data.summary||'');}
    }catch(e){if(status)status.textContent='Audit ancora avviato; stato temporaneamente non disponibile. Puoi tornare su questa pagina più tardi.';}
    finally{busy=false;}
  };
  const timer=setInterval(poll,12000);poll();
})();
