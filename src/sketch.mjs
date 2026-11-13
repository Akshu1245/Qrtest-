// v6-sketch direction: hand-drawn frames drawn live with Rough.js (MIT, roughjs.com).
// Design study refs: excalidraw.com, wiredjs.com (rough-stuff), a1.gallery
// hand-drawn collection. Frames are generated at runtime in the browser;
// no copied components or assets. Editorial v5 base (paper, ink, one red) kept.
import rough from 'roughjs';
import './blend.css';

const SVGNS='http://www.w3.org/2000/svg';
const SELECTORS=['.tool','.btn-ink','.btn-ghost','.drop'];

const framed=new Set();
let ro=null,scheduled=false;

function seedFor(el){
  let s=7;const k=el.tagName+el.className;
  for(let i=0;i<k.length;i++)s=(s*31+k.charCodeAt(i))>>>0;
  return s||1;
}

function drawFrame(el){
  if(!el.isConnected){framed.delete(el);if(ro)ro.unobserve(el);return}
  const w=el.offsetWidth,h=el.offsetHeight;
  let svg=el.querySelector(':scope > svg.sketch-frame');
  if(!w||!h){if(svg)svg.remove();return}
  const out=el.classList.contains('btn-ink')?3:0; // filled ink button: frame sits outside
  if(!svg){
    svg=document.createElementNS(SVGNS,'svg');
    svg.classList.add('sketch-frame');
    svg.setAttribute('aria-hidden','true');
    el.prepend(svg);
  }
  svg.setAttribute('width',w+2*out);
  svg.setAttribute('height',h+2*out);
  svg.style.left=(-out)+'px';
  svg.style.top=(-out)+'px';
  while(svg.firstChild)svg.removeChild(svg.firstChild);
  const cs=getComputedStyle(el);
  const stroke=(cs.getPropertyValue('--sketch-color')||'').trim()||'#191712';
  const roughness=el.classList.contains('tool')||el.classList.contains('verdict')?1.7:1.3;
  const rc=rough.svg(svg);
  svg.appendChild(rc.rectangle(1.6,1.6,w+2*out-3.2,h+2*out-3.2,{
    stroke,strokeWidth:el.classList.contains('tool')?1.6:1.15,
    roughness,bowing:1.1,seed:seedFor(el),fill:'none'
  }));
}

function scan(){
  scheduled=false;
  document.querySelectorAll(SELECTORS.join(',')).forEach(el=>{
    if(!framed.has(el)){framed.add(el);if(ro)ro.observe(el)}
  });
  framed.forEach(drawFrame);
}
function schedule(){if(!scheduled){scheduled=true;requestAnimationFrame(scan)}}

export function initSketch(){
  ro=new ResizeObserver(entries=>{for(const e of entries)drawFrame(e.target)});
  new MutationObserver(schedule).observe(document.querySelector('#app'),{childList:true,subtree:true});
  window.addEventListener('resize',schedule);
  requestAnimationFrame(scan);          // after main.js body has rendered
  if(document.fonts&&document.fonts.ready)document.fonts.ready.then(schedule);
}
initSketch();
