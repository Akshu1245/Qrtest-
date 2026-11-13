import jsQR from 'jsqr';
import { analyze } from './analyzer.mjs';
import { checkUrlLive } from './threatintel.mjs';
import { buildReportModel, toText, toPdf } from './report.mjs';
import * as history from './history.mjs';
import './style.css';
import './depth.css';
import './sketch.mjs';
import './mix.css';

const ICONS={
 shield:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"><path d="M12 2.5 4.5 5.5v6c0 4.6 3.2 8.4 7.5 10 4.3-1.6 7.5-5.4 7.5-10v-6L12 2.5Z"/><path d="M8.5 12l2.4 2.4L15.7 9.5" stroke-linecap="round"/></svg>',
 download:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 4v11m0 0 4-4m-4-4-4-4"/><path d="M4 17v2.5h16V17"/></svg>'
};

const app=document.querySelector('#app');
app.innerHTML=`<div class="page">
<header class="bar">
  <a class="logo" href="#top">${ICONS.shield}<span>QRShield<sup>&reg;</sup></span></a>
  <nav class="nav"><a href="#check">Scanner</a><a href="#result">Results</a><a href="#history">History</a><a href="#about">About</a></nav>
</header>
<main id="top" class="wrap">
  <section class="hero">
    <div class="hero-copy">
      <p class="kicker">A QR &amp; link risk checker that runs on your device</p>
      <h1>Inspect before<br>you <em>interact.</em></h1>
      <p class="sub">QR codes hide where they lead. QRShield decodes them in your browser and explains the warning signs (links, UPI payments, Wi-Fi configs) before you pay, log in, or connect.</p>
    </div>
    <section class="tool" id="check" aria-label="Check a link or QR payload">
      <div class="t-head"><span>Check a link or QR payload</span><span id="chip" class="chip idle">Not scanned</span></div>
      <textarea id="text" rows="2" maxlength="12000" aria-label="URL, UPI payment QR or raw QR content" placeholder="https://example.com  or  upi://pay?pa=..." spellcheck="false"></textarea>
      <div class="t-actions">
        <button id="analyze" class="btn-ink"><span>Analyze</span><span class="arrow">&rarr;</span></button>
        <label class="btn-ghost" for="file">Scan image</label>
        <button id="camera" class="btn-ghost">Camera</button>
      </div>
      <input id="file" type="file" accept="image/png,image/jpeg,image/webp" hidden>
      <button id="stop" class="btn-ghost" hidden>Stop camera</button>
      <video id="video" playsinline muted hidden></video>
      <div class="drop" id="drop"><span>Drop a QR image here &middot; PNG, JPG, WebP &middot; max 8 MB</span></div>
      <div id="message" role="status" aria-live="polite"></div>
      <div class="t-meta"><span>Nothing is uploaded</span><span>Decoding happens on this device with jsQR</span></div>
    </section>
  </section>
  <section id="result" class="result">
    <div id="assessment" class="empty"><span class="empty-label">Verdict</span><p class="empty-main">No scan yet.</p><p class="empty-sub">Your findings, risk indicators and recommendations will appear here.</p></div>
    <div class="actions exportrow"><button id="export-txt" class="btn-ghost export" disabled>${ICONS.download}<span>Text report</span></button><button id="export-pdf" class="btn-ghost export" disabled>${ICONS.download}<span>PDF report</span></button></div>
  </section>
  <div class="row2">
    <section id="history" class="hist">
      <h2 class="sec-h">Scan history</h2>
      <div class="hist-controls"><label class="toggle"><input id="histtoggle" type="checkbox" checked> Save scans on this device</label><button id="histclear" class="btn-ghost small">Clear</button></div>
      <div id="histlist" class="histlist"></div>
      <p class="fine">Private to this browser, stored on this device only, never uploaded.</p>
    </section>
    <section id="about" class="about">
      <h2 class="sec-h">How it works</h2>
      <ol class="steps">
        <li><b>Decode</b><p>QR pixels become text on your device with jsQR. Images and camera frames are never uploaded.</p></li>
        <li><b>Inspect</b><p>Transparent rules score URLs and UPI payment details. If configured, a server-side endpoint also checks the link against Google Web Risk.</p></li>
        <li><b>Explain</b><p>Every point in the score is listed. When a check cannot run, the verdict is &ldquo;not checked&rdquo;, never &ldquo;safe&rdquo;.</p></li>
      </ol>
    </section>
  </div>
</main>
<footer class="foot"><span>QRShield &middot; educational cybersecurity prototype</span><span>Open source: jsQR &middot; jsPDF &middot; Vite</span><span>No link or payee is guaranteed safe</span></footer>
</div>`;

const $=s=>document.querySelector(s);
let last=null,stream=null,frame=null,liveSeq=0;
function showMessage(msg){$('#message').textContent=msg}
function safe(t){return String(t).replace(/[&<>"']/g,x=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[x]))}
const TAG={high:'FLAG',caution:'WARN',info:'NOTE',unknown:'NOTE'};

function renderHistory(){
  const list=$('#histlist');const entries=history.list();
  if(!history.isEnabled()){list.innerHTML='<div class="histempty">History is paused. Scans are not being saved.</div>';return}
  if(!entries.length){list.innerHTML='<div class="histempty">No scans saved yet.</div>';return}
  list.innerHTML=entries.map((e,i)=>`<button class="histitem" data-i="${i}"><span class="dot ${safe(e.level)}"></span><span class="histmain"><b>${safe(e.headline||e.type)}</b><small>${safe(e.input.slice(0,60))}${e.input.length>60?'…':''}</small></span><span class="histtime">${safe((e.checkedAt||'').slice(0,16).replace('T',' '))}</span></button>`).join('');
  list.querySelectorAll('.histitem').forEach(btn=>{btn.onclick=()=>{const e=entries[Number(btn.dataset.i)];if(e){$('#text').value=e.input;run(e.input);$('#result').scrollIntoView({behavior:'smooth'})}}});
}

function liveBadgeHtml(live,state){
  if(state==='checking')return `<div class="live checking"><span class="spinner"></span><span>Live threat list: checking&hellip;<small>Only this URL is sent to the check service, never other QR content.</small></span></div>`;
  if(!live||live.status==='unknown')return `<div class="live unknown"><span class="dot"></span><span>Live threat list: <b>not checked</b><small>lookup unavailable or not configured - unknown, not safe</small></span></div>`;
  if(live.status==='flagged')return `<div class="live flagged"><span class="dot"></span><span>Live threat list: <b>listed as dangerous</b><small>${safe((live.threats||[]).join(', '))} - ${safe(live.source||'threat list')}</small></span></div>`;
  return `<div class="live nomatch"><span class="dot"></span><span>Live threat list: <b>not on the list</b><small>${safe(live.source||'threat list')} - still not proof of safety</small></span></div>`;
}

function gaugeSvg(score,level){
  if(score===null)return `<div class="gauge none"><span>N/A</span></div>`;
  const r=44,c=2*Math.PI*r,off=c*(1-Math.min(100,score)/100);
  return `<svg class="gauge ${level}" viewBox="0 0 110 110"><circle class="track" cx="55" cy="55" r="${r}"/><circle class="fill" cx="55" cy="55" r="${r}" stroke-dasharray="${c.toFixed(1)}" stroke-dashoffset="${off.toFixed(1)}" transform="rotate(-90 55 55)"/><text x="55" y="52" class="g-num" text-anchor="middle">${score}</text><text x="55" y="70" class="g-den" text-anchor="middle">/ 100</text></svg>`;
}

function renderAssessment(liveState,live){
  const r=last.analysis;const isUrl=r.type==='url';
  const chipText=(live&&live.status==='flagged')?'LISTED DANGEROUS':r.level==='high'?'HIGH RISK':r.level==='caution'?'CAUTION':'NOT VERIFIED';
  $('#chip').className='chip '+(live&&live.status==='flagged'?'high':r.level);
  $('#chip').textContent=chipText;
  $('#assessment').className='details';
  $('#assessment').innerHTML=`<div class="verdict ${r.level}"><div class="verdict-main"><span class="verdict-kicker">Verdict</span><span class="verdict-word">${chipText}</span><span class="verdict-sub">${safe(r.headline)}</span></div>${gaugeSvg(r.score,r.level)}</div><p class="details-text">${safe(r.details)}</p>${isUrl?liveBadgeHtml(live,liveState):''}<div class="findings">${r.findings.map(x=>`<div class="finding"><span class="tag ${safe(x.level)}">${TAG[x.level]||'NOTE'}</span><span class="finding-text">${safe(x.label)}</span></div>`).join('')}</div><div class="caveat">Educational assessment only. Absence of warnings does not prove safety.</div>`;
}

function run(text){
  stopCamera();
  text=String(text??'');
  $('#text').value=text;
  const btn=$('#analyze');btn.disabled=true;btn.classList.add('busy');
  try{
    last={input:text,analysis:analyze(text),live:null};
    renderAssessment('idle',null);
    $('#export-txt').disabled=false;$('#export-pdf').disabled=false;
    history.add({input:text,type:last.analysis.type,level:last.analysis.level,score:last.analysis.score,headline:last.analysis.headline,checkedAt:last.analysis.checkedAt});
    renderHistory();
    showMessage('Analysis completed locally');
    if(last.analysis.type==='url'){
      const seq=++liveSeq;renderAssessment('checking',null);
      checkUrlLive(text).then(live=>{
        if(seq!==liveSeq||!last)return; // a newer scan replaced this one
        last.live=live;renderAssessment('done',live);
        if(live.status==='flagged')showMessage('Warning: this link is listed on a live threat list.');
      });
    }
  }finally{
    btn.disabled=false;btn.classList.remove('busy');
  }
}

$('#analyze').onclick=()=>run($('#text').value);
$('#text').addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&e.key==='Enter')run($('#text').value)});

async function decodeImage(file){
  try{
    if(!file||!file.type.startsWith('image/'))throw Error('Please select a valid image.');
    if(file.size>8*1024*1024)throw Error('Image too large (maximum 8 MB).');
    showMessage('Decoding image…');
    const bmp=await createImageBitmap(file);
    try{
      const scale=Math.min(1,1800/Math.max(bmp.width,bmp.height));
      const c=document.createElement('canvas');c.width=Math.round(bmp.width*scale);c.height=Math.round(bmp.height*scale);
      const ctx=c.getContext('2d',{willReadFrequently:true});ctx.drawImage(bmp,0,0,c.width,c.height);
      const data=ctx.getImageData(0,0,c.width,c.height);
      const qr=jsQR(data.data,data.width,data.height,{inversionAttempts:'attemptBoth'});
      if(!qr)throw Error('No readable QR code found. Try a sharper image.');
      run(qr.data);
    }finally{bmp.close()}
  }catch(e){showMessage(e.message)}
}
$('#file').onchange=e=>decodeImage(e.target.files[0]);
$('#drop').ondragover=e=>{e.preventDefault();$('#drop').classList.add('drag')};
$('#drop').ondragleave=()=>$('#drop').classList.remove('drag');
$('#drop').ondrop=e=>{e.preventDefault();$('#drop').classList.remove('drag');decodeImage(e.dataTransfer.files[0])};

async function startCamera(){
  if(!navigator.mediaDevices?.getUserMedia){showMessage('Camera requires HTTPS or localhost and browser permission.');return}
  try{
    showMessage('Starting camera…');
    stream=await navigator.mediaDevices.getUserMedia({video:{facingMode:'environment'},audio:false});
    const video=$('#video');video.srcObject=stream;video.hidden=false;$('#stop').hidden=false;
    await video.play();showMessage('Point the camera toward a QR code.');
    const c=document.createElement('canvas'),ctx=c.getContext('2d',{willReadFrequently:true});
    let lastRead=0;
    function tick(now){
      if(!stream)return;
      if(now-lastRead>200&&video.readyState>=2){
        lastRead=now;c.width=video.videoWidth;c.height=video.videoHeight;
        if(c.width&&c.height){
          ctx.drawImage(video,0,0);
          const d=ctx.getImageData(0,0,c.width,c.height),qr=jsQR(d.data,d.width,d.height,{inversionAttempts:'dontInvert'});
          if(qr){run(qr.data);return}
        }
      }
      frame=requestAnimationFrame(tick);
    }
    frame=requestAnimationFrame(tick);
  }catch(e){showMessage('Cannot start camera: '+e.message);stopCamera()}
}
function stopCamera(){if(frame)cancelAnimationFrame(frame);frame=null;if(stream){stream.getTracks().forEach(x=>x.stop());stream=null}$('#video').hidden=true;$('#stop').hidden=true}
$('#camera').onclick=startCamera;$('#stop').onclick=stopCamera;window.addEventListener('pagehide',stopCamera);

function download(name,blob){const url=URL.createObjectURL(blob);const link=document.createElement('a');link.href=url;link.download=name;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000)}
$('#export-txt').onclick=()=>{if(!last)return;download('qrshield-report.txt',new Blob([toText(buildReportModel(last.input,last.analysis,last.live))],{type:'text/plain;charset=utf-8'}))};
$('#export-pdf').onclick=async()=>{
  if(!last)return;
  const btn=$('#export-pdf');btn.disabled=true;btn.querySelector('span:last-child').textContent='Building…';
  try{
    const { jsPDF }=await import('jspdf');
    const doc=toPdf(buildReportModel(last.input,last.analysis,last.live),jsPDF);
    doc.save('qrshield-report.pdf');
  }catch(e){showMessage('PDF export failed: '+e.message)}
  finally{btn.disabled=false;btn.querySelector('span:last-child').textContent='PDF report'}
};

$('#histtoggle').checked=history.isEnabled();
$('#histtoggle').onchange=e=>{history.setEnabled(e.target.checked);if(!e.target.checked)history.clear();renderHistory()};
$('#histclear').onclick=()=>{history.clear();renderHistory();showMessage('Scan history cleared on this device')};
renderHistory();
