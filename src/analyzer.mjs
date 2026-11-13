/** Deterministic educational checks. Live threat intelligence, when configured, is layered on top by the caller; these rules never claim a URL is safe. */
const SUSPICIOUS_TLDS = new Set(['zip','mov','top','xyz','click','work','country','gq','tk','cam','rest','quest','cfd','icu']);
const SCAM_WORDS = /(?:verify[-_]?account|reset[-_]?password|urgent[-_]?action|claim[-_]?reward|free[-_]?gift|kyc[-_]?update|account[-_]?blocked|confirm[-_]?identity|suspended[-_]?account|security[-_]?alert)/i;
const SHORTENERS = new Set(['bit.ly','tinyurl.com','t.co','is.gd','cutt.ly','rebrand.ly','rb.gy','tiny.cc','buff.ly','ow.ly','shorturl.at','bitly.com','v.gd','qr.ae']);
const BRANDS = ['google','microsoft','amazon','paypal','netflix','instagram','whatsapp','apple','facebook','sbi','hdfc','icici','paytm','phonepe','gpay'];
const HOMOGLYPHS = {'0':'o','1':'l','3':'e','4':'a','5':'s','7':'t','8':'b','@':'a','$':'s','!':'i'};

function result(type,level,headline,details,findings,score=null){return {type,level,headline,details,findings,score,checkedAt:new Date().toISOString()}}
function add(f,state,label,points,level='caution'){f.push({label,level});state.score+=points}

/** Levenshtein distance, small strings only (brand lookalike check). */
function editDistance(a,b){
  const m=a.length,n=b.length;if(Math.abs(m-n)>2)return 3;
  let prev=Array.from({length:n+1},(_,j)=>j);
  for(let i=1;i<=m;i++){const cur=[i];for(let j=1;j<=n;j++){cur[j]=Math.min(prev[j]+1,cur[j-1]+1,prev[j-1]+(a[i-1]===b[j-1]?0:1))}prev=cur}
  return prev[n];
}
/** Replace common digit/symbol lookalikes with letters: paypa1 -> paypal. */
function unhomoglyph(s){return s.replace(/[0134578@$!]/g,c=>HOMOGLYPHS[c]||c)}
/** Second-level label of a hostname: paypal in www.secure-paypal.com */
function secondLevel(host){const parts=host.split('.');return parts.length>=2?parts[parts.length-2]:host}
/** IP-style hosts: dotted decimal, hex (0x7f...), octal (0177...), single integer, IPv6 literal. */
function ipStyleHost(host){
  if(/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host))return true;
  if(/^\[?[0-9a-f:]*:[0-9a-f:]+\]?$/i.test(host)&&host.includes(':'))return true; // IPv6 literal
  if(/^(?:0x[0-9a-f]+)(?:\.(?:0x[0-9a-f]+))*$/i.test(host))return true; // hex parts
  if(/^0[0-7]+(?:\.0?[0-7]+){0,3}$/.test(host))return true; // octal parts
  if(/^\d{5,}$/.test(host))return true; // single integer form
  return false;
}
function brandHits(host){
  const hits=[];
  for(const brand of BRANDS){
    const official=host===brand+'.com'||host===brand+'.in'||host.endsWith('.'+brand+'.com')||host.endsWith('.'+brand+'.in');
    if(official)continue;
    if(host.includes(brand)){hits.push({brand,why:'Possible brand impersonation involving '+brand});break}
    const rawLabel=secondLevel(host).replace(/-/g,'');
    const label=unhomoglyph(rawLabel);
    if(label===brand&&rawLabel!==brand){hits.push({brand,why:'Lookalike domain resembles '+brand});break}
    if(label!==brand&&(label.includes(brand)||editDistance(label,brand)<=1)){
      hits.push({brand,why:'Lookalike domain resembles '+brand});break;
    }
  }
  return hits;
}

export function analyze(text){
 const raw=String(text??'').trim();
 if(!raw)return result('unknown','unknown','Nothing to analyze','Paste a URL or scan a QR code.',[],null);
 if(raw.length>12000)return result('unknown','caution','Payload unusually large','Inspect this QR content before using it.',[{label:'Long QR payload',level:'caution'}],30);
 if(/^upi:\/\/pay(?:\?|$)/i.test(raw))return analyzeUpi(raw);
 if(/^WIFI:/i.test(raw))return result('wifi','caution','Wi-Fi configuration QR','Check the network name and security mode before connecting.',[{label:'Wi-Fi configuration: confirm you trust the network',level:'caution'}],20);
 if(/^BEGIN:VCARD/i.test(raw))return result('contact','caution','Contact card QR','Review contact details before importing.',[{label:'Contact information can be forged',level:'caution'}],20);
 if(/^(?:javascript|data|file|intent|vbscript):/i.test(raw))return result('unsafe-scheme','high','Potentially unsafe QR payload','Do not open this QR payload.',[{label:'Potentially dangerous URI scheme',level:'high'}],90);
 if(!/^https?:\/\//i.test(raw) && !/^www\./i.test(raw))return result('text','unknown','Non-web QR content','This is text or an unsupported QR format. No link-security verdict is available.',[{label:'Not a supported web URL',level:'unknown'}],null);
 return analyzeUrl(raw);
}

export function analyzeUrl(value){
 const raw=/^www\./i.test(value)?'https://'+value:value;
 let url; try{url=new URL(raw)}catch{return result('url','caution','Invalid URL','This link could not be parsed.',[{label:'Malformed URL',level:'caution'}],30)}
 if(!['http:','https:'].includes(url.protocol))return result('url','high','Unsupported protocol','Do not open unknown protocols.',[{label:'Unexpected URL scheme',level:'high'}],90);
 const host=url.hostname.toLowerCase();const f=[];const state={score:0};
 if(url.protocol==='http:')add(f,state,'Link does not use HTTPS',20);
 if(url.username||url.password)add(f,state,'URL contains embedded credentials',60,'high');
 if(host.includes('xn--'))add(f,state,'Internationalized / punycode domain: verify spelling',25);
 if(ipStyleHost(host))add(f,state,'Link uses an IP address instead of a normal domain',25);
 if(host.split('.').length>4)add(f,state,'Unusually deep subdomain nesting',12);
 const tld=host.split('.').at(-1);if(SUSPICIOUS_TLDS.has(tld))add(f,state,'Domain has a frequently abused top-level domain',15);
 if(SHORTENERS.has(host))add(f,state,'Shortened URL conceals its destination',25);
 if(SCAM_WORDS.test(url.pathname+url.search+host))add(f,state,'Urgency, reward or account-verification wording in link',20);
 const encodes=raw.match(/%[0-9a-f]{2}/gi);
 if(encodes){add(f,state,'Encoded characters in URL: inspect destination carefully',10);
   if(/%25[0-9a-f]{2}/i.test(raw))add(f,state,'Double-encoded characters can hide the real destination',15);
   if(encodes.length>4)add(f,state,'Unusually heavy URL encoding',10);}
 for(const hit of brandHits(host)){add(f,state,hit.why,25)}
 if(host.length>55)add(f,state,'Unusually long domain name',10);
 const score=Math.min(100,state.score);const level=score>=55?'high':score>=20?'caution':'unknown';
 return result('url',level,level==='high'?'High-risk indicators detected':level==='caution'?'Review this link carefully':'No heuristic warning detected',level==='unknown'?'These local checks found no warning signs. This does NOT mean the URL is safe.':'One or more indicators deserve additional verification.',f.length?f:[{label:'No warning from local rules; unknown threats may still exist',level:'unknown'}],score);
}

export function analyzeUpi(value){
 let url;try{url=new URL(value)}catch{return result('upi','caution','Malformed UPI QR','Unable to parse payment details.',[{label:'Invalid UPI format',level:'caution'}],35)}
 const p=url.searchParams;const pa=(p.get('pa')||'').trim(),pn=(p.get('pn')||'').trim(),am=p.get('am'),cu=(p.get('cu')||'INR').toUpperCase(),tn=(p.get('tn')||'').trim();const f=[];const state={score:0};
 if(!/^[\w.\-]{2,}@[\w.\-]{2,}$/.test(pa)){f.push({label:'Missing or malformed payee UPI ID',level:'high'});state.score+=65}
 else f.push({label:'Payee UPI ID: '+pa,level:'info'});
 if(pn)f.push({label:'Displayed recipient name: '+pn+' (not identity-verified)',level:'info'});
 else {f.push({label:'Recipient name not supplied',level:'caution'});state.score+=10}
 if(/https?:\/\//i.test(pn)){f.push({label:'Recipient name contains a link: treat as suspicious',level:'high'});state.score+=60}
 if(am!==null){const n=Number(am);if(!Number.isFinite(n)||n<=0){f.push({label:'Invalid amount',level:'high'});state.score+=45}else{f.push({label:'Requested payment: '+n.toFixed(2)+' '+cu,level:'info'});if(n>10000){f.push({label:'High payment amount: confirm independently',level:'caution'});state.score+=25}}}
 else f.push({label:'Amount is not prefilled; verify before paying',level:'info'});
 if(cu!=='INR'){f.push({label:'Unexpected currency for Indian UPI',level:'caution'});state.score+=30}
 if(tn)f.push({label:'Payment note: '+tn.slice(0,80),level:'info'});
 if(SCAM_WORDS.test(tn)){f.push({label:'Urgency or reward wording in payment note',level:'caution'});state.score+=20}
 const score=Math.min(state.score,100);const level=score>=55?'high':score>=20?'caution':'unknown';
 return result('upi',level,score>=55?'Suspicious UPI payload':score>=20?'Check payment details':'UPI details parsed', 'A QR code cannot confirm the recipient is genuine. Verify the UPI ID and amount in your trusted payment app before paying.',f,score);
}
