/* IPTM 4.2: shared chart interactions. SVG and data table render on server without JS. */
(() => {
 'use strict';
 const encode = value => '"' + String(value).replace(/"/g, '""') + '"';
 async function copyData(button) {
   const chart = button.closest('.iptm-visual');
   if (!chart) return;
   const entries = [...chart.querySelectorAll('.iptm-chart-data tbody tr')].map(tr => {
     const cells = tr.querySelectorAll('th,td');
     return [cells[0]?.textContent || '', cells[1]?.dataset.iptmNum || ''];
   });
   const csv = '\uFEFF' + [['Voce','Valore'], ...entries].map(row => row.map(encode).join(';')).join('\r\n');
   let ok = false;
   try {
     if (navigator.clipboard?.writeText) {await navigator.clipboard.writeText(csv); ok = true;}
     else {
       const temporary = document.createElement('textarea');
       temporary.value = csv;temporary.style.position = 'fixed'; temporary.style.left = '-9999px';
       document.body.append(temporary);temporary.select();ok = document.execCommand('copy');temporary.remove();
     }
   } catch {ok = false;}
   const feedback = chart.querySelector('.iptm-chart-feedback');
   if (feedback) feedback.textContent = ok ? 'Dati copiati negli appunti' : 'Copia non disponibile: espandi la tabella dati per selezionarla';
 }
 document.addEventListener('click', event => {
   const btn = event.target.closest?.('.iptm-chart-copy');
   if (btn) {event.preventDefault();void copyData(btn);}
 });
})();
