(function () {
  'use strict';
  const PREFIX='iptm-ui-picks-v1:';
  const escapeKey=(s)=>String(s||'').slice(0,160);
  const skipped=/^(?:csrf|_csrf|token|nonce|password|passphrase|secret|api_|recovery_|confirm|ack|explicit_optin|force|apply_sysctl|dnsbundle_|antidpi_console|sni_console)/i;
  const explicit=['source_mode','unbound_profile','diag_level','diag_network','apply_gravity','zapret_engine'];
  function init(){
    let storage;try{storage=window.localStorage;}catch(_){return;}
    if(!storage)return;
    const page=(new URLSearchParams(location.search)).get('p')||'status';
    const forms=[...document.querySelectorAll('form')];
    const seenKeys=new Map(),stores=[];
    forms.forEach((form,index)=>{
      if(!form.matches('form[method="post"],form[method="POST"],form:not([method])'))return;
      const action=form.querySelector('input[type="hidden"][name="action"]')?.value||'';
      const postButtons=[...form.querySelectorAll('button[name="action"]')];
      const actionLabel=action||postButtons.map(b=>b.value).join(',')||'form';
      // Avoid storing user inputs, addresses, tokens or passwords. Only checkbox flags/radio and a few selectors.
      const all=[...form.querySelectorAll('input[type="checkbox"],input[type="radio"],select')].filter(el=>el.name&&!skipped.test(el.name));
      const groups=new Map(); all.forEach(el=>{const k=el.name;if(!groups.has(k))groups.set(k,[]);groups.get(k).push(el);});
      const fields=all.filter(el=>el.type==='checkbox'||el.type==='radio'||groups.get(el.name).length>1||explicit.includes(el.name)||el.dataset.iptmRemember==='1'||el.name.endsWith('[]'));
      if(!fields.length)return;
      const base=PREFIX+escapeKey(page)+':'+escapeKey(actionLabel)+':'+escapeKey([...new Set(fields.map(el=>el.name))].join(','));
      const occurrence=seenKeys.get(base)||0;seenKeys.set(base,occurrence+1);
      const key=base+':'+occurrence;
      let saved={};try{saved=JSON.parse(storage.getItem(key)||'{}');if(!saved||typeof saved!=='object')saved={};}catch(_){saved={};}
      fields.forEach(el=>{
        const id=el.name+'|'+(el.type==='checkbox'||el.type==='radio'?el.value:'select');
        if(!Object.prototype.hasOwnProperty.call(saved,id))return;
        if(el.type==='checkbox'||el.type==='radio')el.checked=Boolean(saved[id]);
        else if([...el.options].some(o=>o.value===saved[id]))el.value=saved[id];
      });
      function store(){
        const values={};fields.forEach(el=>{
          const id=el.name+'|'+(el.type==='checkbox'||el.type==='radio'?el.value:'select');
          values[id]=el.type==='checkbox'||el.type==='radio'?el.checked:el.value;
        });
        try{storage.setItem(key,JSON.stringify(values));}catch(_){/* browser private mode */}
      }
      stores.push(store);
      form.addEventListener('change',event=>{if(fields.includes(event.target))store();});
      // On apply/save, server data is the source of truth. Retain multi-choice lists
      // (adlists, MACs, regex, source catalogs) for easy re-use, but discard other options.
      form.addEventListener('submit',()=>{
        const preserve=fields.filter(el=>/^(?:adlists\[\]|regex_presets\[\]|rethink_ids\[\]|source_ids\[\]|recommended_rules\[\]|selected_macs\[\])$/.test(el.name));
        if(!preserve.length){try{storage.removeItem(key);}catch(_){}}
        else{fields.splice(0,fields.length,...preserve);store();}
      });
    });
    // Bulk-selection buttons update .checked programmatically without firing change.
    document.addEventListener('click',ev=>{
      if(!ev.target.closest('button[type="button"]'))return;
      setTimeout(()=>stores.forEach(save=>save()),0);
    });
  }
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init,{once:true});else init();
})();
