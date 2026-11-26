(function(){
const q=s=>document.querySelector(s);
document.querySelectorAll('[data-fill]').forEach(a=>a.onclick=e=>{e.preventDefault();const i=[...document.getElementsByName(a.dataset.fill||'')].find(el=>!el.disabled && 'value' in el);if(!i)return;const v=a.dataset.v;
 i.value=a.dataset.add&&i.value?(i.value.split(',').includes(v)?i.value:i.value+','+v):v;});
function appendRow(template, target) {
 if(!template || !target)return;
 const holder=target.tagName==='TABLE'?(target.tBodies[0]||target.createTBody()):target;
 const used=new Set(Array.from(holder.querySelectorAll('[name]'),e=>e.name));
 let n=1000;
 const names=Array.from(template.content.querySelectorAll('[name]'),e=>e.name);
 while(names.some(name=>used.has(name.replace(/__i__/g,String(n)))))n++;
 holder.insertAdjacentHTML('beforeend',template.innerHTML.replace(/__i__/g,String(n)));
}
function adder(btn,tpl,cont){const b=q(btn),t=q(tpl),c=q(cont);if(b&&t&&c)b.addEventListener('click',()=>appendRow(t,c));}
adder('#fadd','#ftpl','#ftab');adder('#padd','#ptpl','#plist');
document.querySelectorAll('[data-tpl]').forEach(b=>{b.addEventListener('click',()=>appendRow(q(b.dataset.tpl),q(b.dataset.into)));});
})();
