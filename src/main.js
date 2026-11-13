import jsQR from 'jsqr';
import { analyze } from './analyzer.mjs';
import { checkUrlLive } from './threatintel.mjs';
import { buildReportModel, toText, toPdf } from './report.mjs';
import * as history from './history.mjs';
import './style.css';

const ICONS={
 shield:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"><path d="M12 2.5 4.5 5.5v6c0 4.6 3.2 8.4 7.5 10 4.3-1.6 7.5-5.4 7.5-10v-6L12 2.5Z"/><path d="M8.5 12l2.4 2.4L15.7 9.5" stroke-linecap="round"/></svg>',
 camera:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"><path d="M3 8h3l2-2.5h8L18 8h3v11H3V8Z"/><circle cx="12" cy="13" r="3.5"/></svg>',
 upload:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 16V4m0 0 4 4m-4-4L8 8"/><path d="M4 16v3.5h16V16"/></svg>',
 link:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M10 14a4 4 0 0 0 6 .4l3-3a4 4 0 0 0-5.6-5.6l-1.5 1.5"/><path d="M14 10a4 4 0 0 0-6-.4l-3 3a4 4 0 0 0 5.6 5.6l1.5-1.5"/></svg>',
 history:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3.5 12a8.5 8.5 0 1 1 2.5 6"/><path d="M3.5 12H1.8m1.7 0 2-2m-2 2 2 2"/><path d="M12 7.5V12l3 2"/></svg>',
 info:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M12 11v5.5"/><circle cx="12" cy="7.8" r=".4" fill="currentColor"/></svg>',
 download:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 4v11m0 0 4-4m-4 4-4-4"/><path d="M4 17v2.5h16V17"/></svg>'
};

const app=document.querySelector('#app');
app.innerHTML=`<div class="app">
<aside class="side">
  <a class="brandrow" href="#top"><span class="mark">${ICONS.shield}</span><span class="wordmark">QRShield<small>THREAT ANALYZER</small></span></a>
  <nav class="topnav"><a href="#scanner"><b>01</b>Scanner</a><a href="#analyzer"><b>02</b>Analyzer</a><a href="#result"><b>03</b>Results</a><a href="#history"><b>04</b>History</a><a href="#about"><b>05</b>About</a></nav>
  <div class="side-foot"><div class="status"><i></i>LOCAL ENGINE READY</div><small>v2.0 &middot; on-device only</small></div>
</aside>
<div class="main">
<div class="tele" id="top"><span><b>ENGINE</b>LOCAL-ONLY</span><span><b>PAYLOADS</b>NEVER UPLOADED</span><span><b>HISTORY</b>STAYS ON THIS DEVICE</span><span><b>LIVE CHECK</b>OPTIONAL &middot; GOOGLE WEB RISK</span></div>
<main>
  <section class="hero">
    <div class="hero-copy">
      <div class="kicker">LOCAL-FIRST &middot; NO ACCOUNT &middot; NO TRACKING</div>
      <h1>Inspect before<br>you <em>interact</em>.</h1>
      <p>QR codes hide their destination. QRShield decodes them on this device and explains the warning signs &mdash; links, UPI payments, Wi-Fi configs &mdash; before you act.</p>
    </div>
    <div class="hero-art" aria-hidden="true">
      <svg viewBox="0 0 200 200" class="qrart"><g fill="currentColor"><rect x="10" y="10" width="50" height="50" rx="4"/><rect x="22" y="22" width="26" height="26" fill="#0a0e17"/><rect x="140" y="10" width="50" height="50" rx="4"/><rect x="152" y="22" width="26" height="26" fill="#0a0e17"/><rect x="10" y="140" width="50" height="50" rx="4"/><rect x="22" y="152" width="26" height="26" fill="#0a0e17"/><rect x="80" y="15" width="12" height="12"/><rect x="100" y="15" width="12" height="12"/><rect x="80" y="35" width="12" height="12"/><rect x="110" y="45" width="12" height="12"/><rect x="15" y="80" width="12" height="12"/><rect x="40" y="95" width="12" height="12"/><rect x="15" y="110" width="12" height="12"/><rect x="70" y="80" width="12" height="12"/><rect x="95" y="80" width="12" height="12"/><rect x="120" y="80" width="12" height="12"/><rect x="145" y="85" width="12" height="12"/><rect x="170" y="80" width="12" height="12"/><rect x="80" y="105" width="12" height="12"/><rect x="105" y="110" width="12" height="12"/><rect x="160" y="110" width="12" height="12"/><rect x="85" y="135" width="12" height="12"/><rect x="140" y="140" width="50" height="12" rx="2"/><rect x="140" y="160" width="12" height="12"/><rect x="165" y="165" width="12" height="12"/><rect x="85" y="165" width="12" height="12"/><rect x="110" y="150" width="12" height="12"/></g><line x1="0" y1="100" x2="200" y2="100" class="scanline"/></svg>
      <div class="hero-note">PAYLOADS NEVER LEAVE THIS DEVICE<span>except URLs you choose to check live</span></div>
    </div>
  </section>
  <div class="grid">
    <div class="col">
      <section id="scanner" class="panel">
        <div class="panel-head"><span class="sec-label">01 / QR SCANNER</span><span class="sec-icon">${ICONS.camera}</span></div>
        <p class="sec-desc">Drop an image or use the camera. Decoding happens locally with jsQR.</p>
        <div class="drop" id="drop"><span class="drop-icon">${ICONS.upload}</span><strong>Drop a QR image here</strong><small>PNG, JPG, WebP &middot; max 8 MB</small><label class="filebtn" for="file">Choose image</label><input id="file" type="file" accept="image/png,image/jpeg,image/webp" hidden></div>
        <div class="actions"><button id="camera" class="primary">${ICONS.camera}<span>Use camera</span></button><button id="stop" class="secondary" hidden>Stop camera</button></div>
        <video id="video" playsinline muted hidden></video>
      </section>
      <section id="analyzer" class="panel">
        <div class="panel-head"><span class="sec-label">02 / URL ANALYZER</span><span class="sec-icon">${ICONS.link}</span></div>
        <p class="sec-desc">Paste a link, UPI payment QR or raw QR content.</p>
        <label class="field-label" for="text">URL / UPI PAYMENT QR / RAW TEXT</label>
        <textarea id="text" rows="3" maxlength="12000" placeholder="https://example.com  or  upi://pay?pa=..." spellcheck="false"></textarea>
        <div class="actions"><button id="analyze" class="primary"><span>Analyze content</span><span class="arrow">&rarr;</span></button></div>
        <div id="message" role="status" aria-live="polite"></div>
      </section>
      <section id="history" class="panel">
        <div class="panel-head"><span class="sec-label">04 / SCAN HISTORY</span><span class="sec-icon">${ICONS.history}</span></div>
        <p class="sec-desc">Private to this browser, stored on this device only, never uploaded.</p>
        <div class="hist-controls"><label class="toggle"><input id="histtoggle" type="checkbox" checked> Save scans on this device</label><button id="histclear" class="secondary small">Clear</button></div>
        <div id="histlist" class="histlist"></div>
      </section>
    </div>
    <div class="col">
      <section id="result" class="panel result">
        <div class="panel-head"><span class="sec-label">03 / SECURITY RESULTS</span><span id="chip" class="chip idle">NOT SCANNED</span></div>
        <div id="assessment" class="empty"><div class="empty-mark">${ICONS.shield}</div><strong>No scan yet</strong><p>Your findings, risk indicators and recommendations will appear here.</p></div>
        <div class="actions exportrow"><button id="export-txt" class="secondary export" disabled>${ICONS.download}<span>Text report</span></button><button id="export-pdf" class="secondary export" disabled>${ICONS.download}<span>PDF report</span></button></div>
      </section>
      <section id="about" class="panel">
        <div class="panel-head"><span class="sec-label">05 / ABOUT PROJECT</span><span class="sec-icon">${ICONS.info}</span></div>
        <ol class="steps">
          <li><b>DECODE</b><p>QR pixels become text on your device with jsQR. Images and camera frames are never uploaded.</p></li>
          <li><b>INSPECT</b><p>Transparent rules score URLs and UPI payment details. If configured, a server-side endpoint also checks the link against Google Web Risk.</p></li>
          <li><b>EXPLAIN</b><p>Every point in the score is listed. When a check cannot run, the verdict is "not checked" &mdash; never "safe".</p></li>
        </ol>
        <div class="foot-note">QRShield &middot; educational cybersecurity prototype &middot; no link or payee is guaranteed safe</div>
      </section>
    </div>
  </div>
</main>
<footer class="foot"><span>QRShield &middot; educational cybersecurity prototype</span><span>Open source credits: jsQR &middot; jsPDF &middot; Vite</span><span>No link or payee is guaranteed safe</span></footer>
</div>
</div>`;

const $=s=>document.querySelector(s);
let last=null,stream=null,frame=null,liveSeq=0;
function showMessage(msg){$('#message').textContent=msg}
function safe(t){return String(t).replace(/[&<>"']/g,x=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[x]))}
const TAG={high:'HIGH',caution:'WARN',info:'INFO',unknown:'NOTE'};

function renderHistory(){
  const list=$('#histlist');const entries=history.list();
  if(!history.isEnabled()){list.innerHTML='<div class="histempty">History is paused. Scans are not being saved.</div>';return}
  if(!entries.length){list.innerHTML='<div class="histempty">No scans saved yet.</div>';return}
  list.innerHTML=entries.map((e,i)=>`<button class="histitem" data-i="${i}"><span class="dot ${safe(e.level)}"></span><span class="histmain"><b>${safe(e.headline||e.type)}</b><small>${safe(e.input.slice(0,60))}${e.input.length>60?'…':''}</small></span><span class="histtime">${safe((e.checkedAt||'').slice(0,16).replace('T',' '))}</span></button>`).join('');
  list.querySelectorAll('.histitem').forEach(btn=>{btn.onclick=()=>{const e=entries[Number(btn.dataset.i)];if(e){$('#text').value=e.input;run(e.input);$('#result').scrollIntoView({behavior:'smooth'})}}});
}

function liveBadgeHtml(live,state){
  if(state==='checking')return `<div class="live checking"><span class="spinner"></span><span>CHECKING LIVE THREAT LIST<small>Only this URL is sent to the check service, never other QR content.</small></span></div>`;
  if(!live||live.status==='unknown')return `<div class="live unknown"><span class="dot"></span><span>LIVE THREAT LIST &middot; <b>NOT CHECKED</b><small>lookup unavailable or not configured - unknown, not safe</small></span></div>`;
  if(live.status==='flagged')return `<div class="live flagged"><span class="dot"></span><span>LIVE THREAT LIST &middot; <b>LISTED AS DANGEROUS</b><small>${safe((live.threats||[]).join(', '))} - ${safe(live.source||'threat list')}</small></span></div>`;
  return `<div class="live nomatch"><span class="dot"></span><span>LIVE THREAT LIST &middot; <b>NOT ON THE LIST</b><small>${safe(live.source||'threat list')} - still not proof of safety</small></span></div>`;
}

function gaugeSvg(score,level){
  if(score===null)return `<div class="gauge none"><span>?</span><small>N/A</small></div>`;
  const r=44,c=2*Math.PI*r,off=c*(1-Math.min(100,score)/100);
  return `<svg class="gauge ${level}" viewBox="0 0 110 110"><circle class="track" cx="55" cy="55" r="${r}"/><circle class="fill" cx="55" cy="55" r="${r}" stroke-dasharray="${c.toFixed(1)}" stroke-dashoffset="${off.toFixed(1)}" transform="rotate(-90 55 55)"/><text x="55" y="52" class="g-num" text-anchor="middle">${score}</text><text x="55" y="70" class="g-den" text-anchor="middle">/ 100</text></svg>`;
}

function renderAssessment(liveState,live){
  const r=last.analysis;const isUrl=r.type==='url';
  const chipText=(live&&live.status==='flagged')?'LISTED DANGEROUS':r.level==='high'?'HIGH RISK':r.level==='caution'?'CAUTION':'NOT VERIFIED';
  $('#chip').className='chip '+(live&&live.status==='flagged'?'high':r.level);
  $('#chip').textContent=chipText;
  $('#assessment').className='details';
  $('#assessment').innerHTML=`<div class="verdict ${r.level}"><div class="verdict-main"><span class="verdict-kicker">VERDICT</span><span class="verdict-word">${chipText}</span><span class="verdict-sub">${safe(r.headline)}</span></div>${gaugeSvg(r.score,r.level)}</div><p class="details-text">${safe(r.details)}</p>${isUrl?liveBadgeHtml(live,liveState):''}<div class="findings">${r.findings.map(x=>`<div class="finding"><span class="tag ${safe(x.level)}">${TAG[x.level]||'NOTE'}</span><span class="finding-text">${safe(x.label)}</span></div>`).join('')}</div><div class="caveat">Educational assessment only. Absence of warnings does not prove safety.</div>`;
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
