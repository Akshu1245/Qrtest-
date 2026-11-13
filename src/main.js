import jsQR from 'jsqr';
import { analyze } from './analyzer.mjs';
import { checkUrlLive } from './threatintel.mjs';
import { buildReportModel, toText, toPdf } from './report.mjs';
import * as history from './history.mjs';
import './style.css';

const app=document.querySelector('#app');
app.innerHTML=`<div class="shell"><aside class="sidebar"><div class="brand"><span class="logo">◈</span><div>QRShield<small>SECURITY LAB</small></div></div><nav><a class="selected" href="#scanner">◈ &nbsp; QR Scanner</a><a href="#analyzer">▤ &nbsp; URL Analyzer</a><a href="#result">▣ &nbsp; Security Results</a><a href="#history">◷ &nbsp; Scan History</a><a href="#about">ⓘ &nbsp; About Project</a></nav><div class="asidefoot">LOCAL FIRST<br><span>QR content is analyzed on your device</span></div></aside><main><header><span class="eyebrow">CYBERSECURITY INTERNSHIP PROJECT</span><span class="status"><i></i> Scanner ready</span></header><section class="hero"><span class="eyebrow accent">SECURITY ANALYSIS</span><h1>Inspect before<br><em>you interact.</em></h1><p>Decode QR codes and check links or UPI payment details for common warning signs. No account required.</p></section><div class="layout"><div class="col"><section id="scanner" class="panel scan"><h2>1 · QR Scanner</h2><p>Scan a QR image or use your camera. Decoding happens on this device.</p><div class="drop" id="drop"><div class="scanIcon">▦</div><strong>Drop a QR image here</strong><small>PNG, JPG, WebP · maximum 8 MB</small><label class="filebtn" for="file">Choose image</label><input id="file" type="file" accept="image/png,image/jpeg,image/webp" hidden></div><div class="actions"><button id="camera" class="primary">Use camera <span>▸</span></button><button id="stop" class="secondary" hidden>Stop camera</button></div><video id="video" playsinline muted hidden></video></section><section id="analyzer" class="panel scan"><h2>2 · URL Analyzer</h2><p>Paste a link, UPI payment QR or raw QR content.</p><label for="text">URL / UPI payment QR / raw text</label><textarea id="text" rows="3" maxlength="12000" placeholder="https://example.com or upi://pay?pa=..." spellcheck="false"></textarea><div class="actions"><button id="analyze" class="primary">Analyze content <span>→</span></button></div><div id="message" role="status" aria-live="polite"></div></section><section id="history" class="panel"><div class="top"><h2>4 · Scan History</h2><button id="histclear" class="secondary small">Clear</button></div><p>Private to this browser, stored on this device only, never uploaded.</p><label class="toggle"><input id="histtoggle" type="checkbox" checked> Save scans on this device</label><div id="histlist" class="histlist"></div></section></div><div class="col"><section id="result" class="panel result"><div class="top"><h2>3 · Security Results</h2><span id="chip" class="chip idle">NOT SCANNED</span></div><div id="assessment" class="empty"><div class="shield">◇</div><strong>No scan yet</strong><p>Your findings, risk indicators and recommendations will appear here.</p></div><div class="actions exportrow"><button id="export-txt" class="secondary export" disabled>Download .txt report</button><button id="export-pdf" class="secondary export" disabled>Download PDF report</button></div></section><section id="about" class="panel info"><h2>5 · About Project</h2><div class="steps"><article><b>01</b><h3>Decode</h3><p>Read QR content locally using browser image processing (jsQR).</p></article><article><b>02</b><h3>Inspect</h3><p>Apply transparent URL and UPI format rules. If configured, a server-side endpoint also checks the link against Google Web Risk.</p></article><article><b>03</b><h3>Explain</h3><p>Show warning indicators, an honest "not checked" when a lookup is unavailable, and cautious advice. Nothing is called "safe".</p></article></div><footer>QRShield • Educational cybersecurity prototype • No link or payee is guaranteed safe.</footer></section></div></div></main></div>`;

const $=s=>document.querySelector(s);
let last=null,stream=null,frame=null,liveSeq=0;
function showMessage(msg){$('#message').textContent=msg}
function safe(t){return String(t).replace(/[&<>"']/g,x=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[x]))}

function renderHistory(){
  const list=$('#histlist');const entries=history.list();
  if(!history.isEnabled()){list.innerHTML='<div class="histempty">History is paused. Scans are not being saved.</div>';return}
  if(!entries.length){list.innerHTML='<div class="histempty">No scans saved yet.</div>';return}
  list.innerHTML=entries.map((e,i)=>`<button class="histitem" data-i="${i}"><span class="dot ${safe(e.level)}"></span><span class="histmain"><b>${safe(e.headline||e.type)}</b><small>${safe(e.input.slice(0,60))}${e.input.length>60?'…':''}</small></span><span class="histtime">${safe((e.checkedAt||'').slice(0,16).replace('T',' '))}</span></button>`).join('');
  list.querySelectorAll('.histitem').forEach(btn=>{btn.onclick=()=>{const e=entries[Number(btn.dataset.i)];if(e){$('#text').value=e.input;run(e.input);$('#result').scrollIntoView({behavior:'smooth'})}}});
}

function liveBadgeHtml(live,state){
  if(state==='checking')return `<div class="live checking"><span class="spinner"></span>Checking live threat list… <small>Only this URL is sent to the check service, never other QR content.</small></div>`;
  if(!live||live.status==='unknown')return `<div class="live unknown"><span class="dot"></span>Live threat list: <b>Not checked</b> <small>lookup unavailable or not configured - unknown, not safe</small></div>`;
  if(live.status==='flagged')return `<div class="live flagged"><span class="dot"></span>Live threat list: <b>LISTED AS DANGEROUS</b> <small>${safe((live.threats||[]).join(', '))} - ${safe(live.source||'threat list')}</small></div>`;
  return `<div class="live nomatch"><span class="dot"></span>Live threat list: <b>not found on the list</b> <small>${safe(live.source||'threat list')} - still not proof of safety</small></div>`;
}

function renderAssessment(liveState,live){
  const r=last.analysis;const isUrl=r.type==='url';
  $('#chip').className='chip '+r.level;
  $('#chip').textContent=(live&&live.status==='flagged')?'LISTED DANGEROUS':r.level==='high'?'HIGH RISK':r.level==='caution'?'CAUTION':'NOT VERIFIED';
  $('#assessment').className='details';
  $('#assessment').innerHTML=`<div class="score"><span>${r.score===null?'?':r.score}</span><small>${r.score===null?'N/A':'/ 100'}<br>Heuristic score</small></div><h3>${safe(r.headline)}</h3><p>${safe(r.details)}</p>${isUrl?liveBadgeHtml(live,liveState):''}<div class="findings">${r.findings.map(x=>`<div class="finding"><span class="dot ${safe(x.level)}"></span>${safe(x.label)}</div>`).join('')}</div><div class="caveat">Educational assessment only. Absence of warnings does not prove safety.</div>`;
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
  const btn=$('#export-pdf');btn.disabled=true;btn.textContent='Building PDF…';
  try{
    const { jsPDF }=await import('jspdf');
    const doc=toPdf(buildReportModel(last.input,last.analysis,last.live),jsPDF);
    doc.save('qrshield-report.pdf');
  }catch(e){showMessage('PDF export failed: '+e.message)}
  finally{btn.disabled=false;btn.textContent='Download PDF report'}
};

$('#histtoggle').checked=history.isEnabled();
$('#histtoggle').onchange=e=>{history.setEnabled(e.target.checked);if(!e.target.checked)history.clear();renderHistory()};
$('#histclear').onclick=()=>{history.clear();renderHistory();showMessage('Scan history cleared on this device')};
renderHistory();
