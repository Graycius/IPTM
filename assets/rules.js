(function(){
const q=s=>document.querySelector(s);
document.querySelectorAll('[data-fill]').forEach(a=>a.onclick=e=>{e.preventDefault();const i=q('[name='+a.dataset.fill+']');if(!i)return;const v=a.dataset.v;
 i.value=a.dataset.add&&i.value?(i.value.split(',').includes(v)?i.value:i.value+','+v):v;});
function adder(btn,tpl,cont){const b=q(btn),t=q(tpl),c=q(cont);if(!b)return;let n=1000;b.onclick=()=>{c.insertAdjacentHTML('beforeend',t.innerHTML.replace(/__i__/g,n++));};}
adder('#fadd','#ftpl','#ftab');adder('#padd','#ptpl','#plist');
document.querySelectorAll('[data-tpl]').forEach(b=>{let n=2000;b.onclick=()=>{q(b.dataset.into).insertAdjacentHTML('beforeend',q(b.dataset.tpl).innerHTML.replace(/__i__/g,n++));};});
})();
