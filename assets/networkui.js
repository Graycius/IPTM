/* IPTM 5.30.1 - Progressive accessibility for all 59 existing page handlers.
 * Does not submit forms, bypass server checks, or write to firewall/network. */
(()=>{
  'use strict';
  const doc=document;
  const root=doc.getElementById('iptm-page-body');
  if(!root)return;
  let nextId=0;
  const uniqueId=prefix=>`${prefix}-${++nextId}`;
  function accessibleName(el){
    return !!(el.getAttribute('aria-label')?.trim() || el.getAttribute('aria-labelledby')?.trim() ||
      el.labels?.length || el.closest('label'));
  }
  function enhanceFields(node){
    for(const field of node.querySelectorAll('input:not([type="hidden"]),select,textarea')){
      if(field.dataset.iptmA11y==='1')continue;
      field.dataset.iptmA11y='1';
      if(!accessibleName(field)){
        const dd=field.closest('.dd');
        const label=dd?.querySelector(':scope > label, :scope > .mut');
        const name=(label?.textContent || field.getAttribute('title') || field.getAttribute('placeholder') ||
          field.name?.replace(/\[|\]|[_-]+/g,' ').trim() || field.type || 'Campo').trim();
        field.setAttribute('aria-label',name.slice(0,140));
      }
      const enclosing=field.closest('.fl');
      const help=enclosing?.querySelector('small');
      if(help && help.textContent.trim() && !field.getAttribute('aria-describedby')){
        if(!help.id)help.id=uniqueId('iptm-hint');
        field.setAttribute('aria-describedby',help.id);
      }
    }
    for(const button of node.querySelectorAll('button')){
      if(button.dataset.iptmA11y==='1')continue;
      button.dataset.iptmA11y='1';
      if(!button.textContent.trim()&&!button.getAttribute('aria-label')&&!button.getAttribute('aria-labelledby')){
        button.setAttribute('aria-label',button.title||button.name?.replace(/[_-]/g,' ')||'Azione');
      }
      // Passive tools should not compete visually with a form's primary submit.
      if(button.type==='button'&&!button.classList.contains('d')&&!button.classList.contains('g')&&!button.classList.contains('danger')){
        button.classList.add('iptm-neutral-action');
      }
    }
    for(const table of node.querySelectorAll('table')){
      if(table.dataset.iptmHeadings==='1')continue;
      table.dataset.iptmHeadings='1';
      const head=table.querySelector('thead');
      if(head)for(const th of head.querySelectorAll('th:not([scope])'))th.scope='col';
    }
    for(const alert of node.querySelectorAll('.msg.err,.alert.err')){
      if(!alert.hasAttribute('role'))alert.setAttribute('role','alert');
    }
    for(const region of node.querySelectorAll('.card')){
      if(region.dataset.iptmRegion==='1')continue;
      region.dataset.iptmRegion='1';
      const h=region.querySelector(':scope > h2,:scope > h3');
      if(!h)continue;
      if(!h.id)h.id=uniqueId('iptm-heading');
      if(!region.hasAttribute('role')){
        region.setAttribute('role','region');region.setAttribute('aria-labelledby',h.id);
      }
    }
  }
  enhanceFields(root);
  // Forms and live status fragments are inserted asynchronously on some pages.
  // Observe inserted descendants only; never modify data values or submit actions.
  if(typeof MutationObserver==='function'){
    const watcher=new MutationObserver(records=>{
      const scopes=new Set();
      for(const record of records)for(const n of record.addedNodes){
        if(n.nodeType!==1)continue;
        if(n.matches?.('input,select,textarea,button,table,.card,.msg.err,.alert.err')){
          scopes.add(n.closest('.card')||root);
        } else if(n.querySelector?.('input,select,textarea,button,table,.card,.msg.err,.alert.err')){
          scopes.add(n);
        }
      }
      for(const scope of scopes)enhanceFields(scope);
    });
    watcher.observe(root,{subtree:true,childList:true});
  }
  // The off-canvas navigation traps keyboard focus only while open on mobile.
  // It is a normal static sidebar on desktop, so focus remains unrestricted there.
  const side=doc.getElementById('side'),burger=doc.getElementById('burger');
  doc.querySelector('.skip-navigation')?.addEventListener('click',e=>{
    if(window.matchMedia('(max-width:860px)').matches && side && !side.classList.contains('open')){
      e.preventDefault();burger?.click();
    }
  });
  function isMobile(){return window.matchMedia('(max-width:860px)').matches;}
  doc.addEventListener('keydown',e=>{
    if(e.key!=='Tab'||!isMobile()||!side?.classList.contains('open'))return;
    const items=[...side.querySelectorAll('a[href],button:not([disabled]),input:not([disabled]),summary')]
      .filter(el=>el.getClientRects().length && !el.closest('[hidden]') &&
        !(el.closest('details')&&!el.closest('details').open && el.tagName!=='SUMMARY'));
    if(!items.length)return;
    const first=items[0],last=items.at(-1);
    if(e.shiftKey && (doc.activeElement===first || !side.contains(doc.activeElement))){e.preventDefault();last.focus();}
    else if(!e.shiftKey && (doc.activeElement===last || !side.contains(doc.activeElement))){e.preventDefault();first.focus();}
  });
  window.addEventListener('resize',()=>{
    if(!isMobile()&&side?.classList.contains('open')){
      side.classList.remove('open');doc.getElementById('app-layout')?.classList.remove('nav-open');
      const bg=doc.getElementById('navBackdrop');if(bg)bg.hidden=true;
      burger?.setAttribute('aria-expanded','false');
      burger?.setAttribute('aria-label','Apri il menu di navigazione');
    }
  });
  // Clear screen-reader state when the quick search dialog closes.
  const command=doc.getElementById('iptm-command'),commandInput=doc.getElementById('iptm-command-input');
  command?.addEventListener('close',()=>{
    commandInput?.setAttribute('aria-expanded','false');
    commandInput?.removeAttribute('aria-activedescendant');
    doc.getElementById('iptm-open-search')?.focus();
  });
})();
