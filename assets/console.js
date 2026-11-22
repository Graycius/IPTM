/* IPTM 5.30.9 – navigation and progressive UI only.
   Never changes a server action, security confirmation, or live firewall state. */
(()=>{
 'use strict';
 const doc=document;
 const $=s=>doc.querySelector(s);
 const norm=s=>String(s||'').normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLocaleLowerCase('it');
 const dialog=$('#iptm-command');
 const search=$('#iptm-command-input');
 const results=$('#iptm-command-results');
 const targets=[...doc.querySelectorAll('#primary-menu a.iptm-nav-link')].map(a=>({
   href:a.getAttribute('href'),
   label:a.querySelector('span:last-child')?.textContent.trim()||a.textContent.trim(),
   icon:a.querySelector('.iptm-nav-icon svg')?.cloneNode(true) || a.querySelector('.iptm-nav-icon')?.textContent || '•',
   group:a.closest('details')?.querySelector('summary>span:nth-child(2)')?.textContent.trim()||'',
   keywords:a.dataset.label||a.textContent,
 })).filter(x=>x.href);
 let selected=0, matched=[];
 function render(){
   if(!results)return;
   const q=norm(search?.value?.trim());
   matched=targets.filter(x=>!q||norm(x.label+' '+x.group+' '+x.keywords).includes(q)).slice(0,40);
   selected=0;results.replaceChildren();
   if(!matched.length){search?.removeAttribute('aria-activedescendant');const empty=doc.createElement('div');empty.className='iptm-command-empty';empty.textContent='Nessuna funzione corrisponde alla ricerca';results.append(empty);return;}
   matched.forEach((item,i)=>{
     const a=doc.createElement('a');a.href=item.href;a.className='iptm-command-result'+(i===0?' is-active':'');
     a.id='iptm-command-option-'+i;a.setAttribute('role','option');a.setAttribute('aria-selected',i===0?'true':'false');
     const sym=doc.createElement('span');if(typeof item.icon==='string')sym.textContent=item.icon;else sym.append(item.icon.cloneNode(true));sym.setAttribute('aria-hidden','true');
     const detail=doc.createElement('div'),title=doc.createElement('b'),sub=doc.createElement('small');
     title.textContent=item.label;sub.textContent=item.group;detail.append(title,sub);
     const arrow=doc.createElement('span');arrow.textContent='↗';arrow.setAttribute('aria-hidden','true');
     a.append(sym,detail,arrow);results.append(a);
   });
   search?.setAttribute('aria-activedescendant','iptm-command-option-0');
 }
 function select(index){
   const links=[...results.querySelectorAll('.iptm-command-result')];if(!links.length)return;
   selected=(index+links.length)%links.length;
   links.forEach((a,i)=>{a.classList.toggle('is-active',i===selected);a.setAttribute('aria-selected',i===selected?'true':'false');});
   links[selected].scrollIntoView({block:'nearest'});
   search?.setAttribute('aria-activedescendant',links[selected].id);
 }
 function open(){
   if(!dialog||!dialog.showModal)return;
   if(!dialog.open)dialog.showModal();
   search?.setAttribute('role','combobox');
   search?.setAttribute('aria-controls','iptm-command-results');
   search?.setAttribute('aria-expanded','true');
   search?.setAttribute('aria-autocomplete','list');
   if(search){search.value='';render();search.focus();}
 }
 function close(){dialog?.open&&dialog.close();}
 $('#iptm-open-search')?.addEventListener('click',open);
 $('#iptm-command-close')?.addEventListener('click',close);
 doc.querySelectorAll('[data-open-command]').forEach(button=>button.addEventListener('click',open));
 search?.addEventListener('input',render);
 search?.addEventListener('keydown',e=>{
   if(e.key==='Escape'){e.preventDefault();close();return;}
   if(e.key==='ArrowDown'||e.key==='ArrowUp'){e.preventDefault();select(selected+(e.key==='ArrowDown'?1:-1));}
   if(e.key==='Enter'&&matched[selected]){e.preventDefault();location.assign(matched[selected].href);}
 });
 dialog?.addEventListener('click',e=>{if(e.target===dialog)close();});
 doc.addEventListener('keydown',e=>{
   if(e.defaultPrevented||e.isComposing||e.altKey)return;
   if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){e.preventDefault();open();}
 });
 // For large panels, a compact index of actual, rendered headings.
 // No forms, previews or privileged calls are duplicated or hidden.
 const root=$('#iptm-page-body');
 if(root){
   const headings=[...root.querySelectorAll(':scope > .card > h2:first-child,:scope > .card > h3:first-child')]
     .filter(h=>h.textContent.trim().length>2&&h.textContent.trim().length<95);
   if(headings.length>=5){
     const index=doc.createElement('details');index.className='iptm-page-index';
     const summary=doc.createElement('summary');summary.textContent='Vai a una sezione della pagina';
     const nav=doc.createElement('nav');nav.setAttribute('aria-label','Indice della pagina');
     headings.slice(0,25).forEach((h,i)=>{
       if(!h.id)h.id='iptm-panel-'+i;
       const a=doc.createElement('a');a.href='#'+h.id;a.textContent=h.textContent.trim();nav.append(a);
     });
     index.append(summary,nav);root.prepend(index);
   }
 }
 // Improve large editable forms with coherent visual focus, leaving all submit actions intact.
 doc.addEventListener('change',e=>{
   const el=e.target;
   if(!(el instanceof HTMLInputElement)||!['checkbox','radio'].includes(el.type))return;
   const host=el.closest('.sc,.iptm-dscp-option,.iptm-domain-source');
   if(host)host.classList.toggle('is-selected',el.checked);
 });
})();
