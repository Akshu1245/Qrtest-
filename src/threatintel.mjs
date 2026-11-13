/**
 * Optional live phishing check via the server-side endpoint (/api/check-url),
 * which holds the API key. Never decides "safe": any failure, missing endpoint
 * or timeout returns status "unknown" and the UI shows "Not checked".
 * Only http(s) URLs are ever submitted, never UPI, Wi-Fi or text payloads.
 */
export async function checkUrlLive(url,{endpoint='/api/check-url',timeoutMs=7000,fetchImpl=globalThis.fetch}={}){
  if(typeof fetchImpl!=='function')return {status:'unknown',threats:[],reason:'unavailable'};
  if(!/^https?:\/\//i.test(url))return {status:'unknown',threats:[],reason:'not-a-web-url'};
  const ctrl=new AbortController();const timer=setTimeout(()=>ctrl.abort(),timeoutMs);
  try{
    const res=await fetchImpl(endpoint+'?uri='+encodeURIComponent(url),{signal:ctrl.signal,headers:{accept:'application/json'}});
    if(res.status===404||res.status===501)return {status:'unknown',threats:[],reason:'not-configured'};
    if(!res.ok)return {status:'unknown',threats:[],reason:'error-'+res.status};
    const data=await res.json();
    if(data&&data.status==='flagged')return {status:'flagged',threats:Array.isArray(data.threats)?data.threats:[],source:data.source||'threat-list'};
    if(data&&data.status==='no-match')return {status:'no-match',threats:[],source:data.source||'threat-list'};
    return {status:'unknown',threats:[],reason:'bad-response'};
  }catch(e){
    return {status:'unknown',threats:[],reason:e&&e.name==='AbortError'?'timeout':'network'};
  }finally{clearTimeout(timer)}
}
