(function(){
  'use strict';
  // Every modifying form uses standard POST and server-side PRG/flash messages.
  // No asynchronous transport, client upload hooks or duplicate transport.
  document.addEventListener('submit',function(event){
    const form=event.target;
    if(event.defaultPrevented || !(form instanceof HTMLFormElement))return;
    if(form.method.toLowerCase()!=='post' || !form.checkValidity())return;
    const wait=document.getElementById('iptm-global-wait');
    if(wait)queueMicrotask(()=>{if(!event.defaultPrevented)wait.hidden=false;});
  });
  window.addEventListener('pageshow',()=>{const wait=document.getElementById('iptm-global-wait');if(wait)wait.hidden=true;});
  // The Health and QoS transaction countdowns are display-only.
  setInterval(function(){
    const e=document.getElementById('iptm-health-seconds');if(!e)return;
    const until=Number(e.dataset.until);if(!Number.isFinite(until)||until<=0){e.textContent='Scadenza non verificabile';return;}
    const n=Math.max(0,until-Math.floor(Date.now()/1000));
    e.textContent=n>0?n+' s':'Scaduto — verificare il ripristino';
  },1000);
})();

// Unified IoT bulk save: include the MAC-preview checkbox state as a single snapshot.
document.addEventListener('submit', function (event) {
  if (!event.target || event.target.id !== 'iptm-iot-bulk-form') return;
  event.target.querySelectorAll('input[data-iptm-iot-selection]').forEach(n => n.remove());
  document.querySelectorAll('input.iptm-mac-selected:checked').forEach(input => {
    const hidden=document.createElement('input');
    hidden.type='hidden'; hidden.name='selected_macs[]'; hidden.value=input.value;
    hidden.dataset.iptmIotSelection='1'; event.target.appendChild(hidden);
  });
});

// DSCP preset picker: selection controls only; never changes kernel/QoS until POST stage/apply.
(function(){
  'use strict';
  function choices(root){return [...root.querySelectorAll('input.iptm-dscp-check[name="recommended_rules[]"]')];}
  function update(root){
    if(!root)return;
    const list=choices(root), selected=list.filter(box=>box.checked);
    list.forEach(box=>box.closest('.iptm-dscp-option')?.classList.toggle('is-selected',box.checked));
    const output=root.querySelector('#iptm-dscp-counter');
    if(output)output.textContent=selected.length+' / '+list.length+' selezionate';
  }
  document.addEventListener('click',function(event){
    if(!(event.target instanceof Element))return;
    const control=event.target.closest('[data-iptm-dscp-bulk]');
    const root=document.getElementById('iptm-dscp-selector');
    if(!control||!root||!root.contains(control))return;
    const operation=control.dataset.iptmDscpBulk;
    const group=control.dataset.iptmDscpGroup;
    choices(root).forEach(box=>{
      if(operation==='all')box.checked=true;
      else if(operation==='none')box.checked=false;
      else if(operation==='essentials')box.checked=box.dataset.iptmDscpEssential==='1';
      else if(operation==='group' && box.closest('.iptm-dscp-section')?.dataset.iptmDscpGroup===group)box.checked=true;
    });
    update(root);
  });
  document.addEventListener('change',function(event){
    if(!(event.target instanceof Element)||!event.target.matches('.iptm-dscp-check'))return;
    update(event.target.closest('#iptm-dscp-selector'));
  });
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',()=>update(document.getElementById('iptm-dscp-selector')));
  else update(document.getElementById('iptm-dscp-selector'));
})();
