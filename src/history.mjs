/**
 * Optional, private, local-only scan history. Stored in the browser's
 * localStorage on this device only; never sent anywhere. Can be paused or
 * cleared at any time. Stored payloads are truncated.
 */
const KEY='qrshield.history.v1';
const ENABLED_KEY='qrshield.history.enabled';
const MAX_ENTRIES=50;
const MAX_STORED_INPUT=500;

function storage(custom){return custom||globalThis.localStorage}

function parseList(raw){
  if(!raw)return [];
  let data;try{data=JSON.parse(raw)}catch{return []}
  if(!Array.isArray(data))return [];
  // Whitelist fields per entry so hostile or corrupt storage cannot inject
  // unexpected object shapes (and JSON.parse never touches prototypes here).
  return data.filter(e=>e&&typeof e==='object').map(e=>({
    input:typeof e.input==='string'?e.input.slice(0,MAX_STORED_INPUT):'',
    type:typeof e.type==='string'?e.type:'unknown',
    level:typeof e.level==='string'?e.level:'unknown',
    score:typeof e.score==='number'?e.score:null,
    headline:typeof e.headline==='string'?e.headline:'',
    checkedAt:typeof e.checkedAt==='string'?e.checkedAt:''
  }));
}

export function isEnabled(store){try{return storage(store).getItem(ENABLED_KEY)!=='off'}catch{return false}}
export function setEnabled(on,store){try{storage(store).setItem(ENABLED_KEY,on?'on':'off')}catch{/* storage may be unavailable */}}
export function list(store){try{return parseList(storage(store).getItem(KEY))}catch{return []}}
export function clear(store){try{storage(store).removeItem(KEY)}catch{/* ignore */}}

export function add(entry,store){
  if(!isEnabled(store))return;
  try{
    const s=storage(store);const entries=list(s);
    entries.unshift({
      input:String(entry.input??'').slice(0,MAX_STORED_INPUT),
      type:String(entry.type??'unknown'),
      level:String(entry.level??'unknown'),
      score:typeof entry.score==='number'?entry.score:null,
      headline:String(entry.headline??'').slice(0,140),
      checkedAt:String(entry.checkedAt??new Date().toISOString())
    });
    s.setItem(KEY,JSON.stringify(entries.slice(0,MAX_ENTRIES)));
  }catch{/* storage full or blocked: history is optional, fail silently */}
}
