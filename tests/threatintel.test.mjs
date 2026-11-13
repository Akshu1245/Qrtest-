import test from 'node:test';import assert from 'node:assert/strict';import {checkUrlLive} from '../src/threatintel.mjs';

function fakeFetch(res){return async()=>res}
const jsonRes=(status,body)=>({status,ok:status>=200&&status<300,json:async()=>body});

test('flagged upstream maps to flagged',async()=>{const r=await checkUrlLive('https://bad.example',{fetchImpl:fakeFetch(jsonRes(200,{status:'flagged',threats:['MALWARE'],source:'Google Web Risk'}))});assert.equal(r.status,'flagged');assert.deepEqual(r.threats,['MALWARE'])});
test('no-match upstream maps to no-match, not safe',async()=>{const r=await checkUrlLive('https://ok.example',{fetchImpl:fakeFetch(jsonRes(200,{status:'no-match',source:'Google Web Risk'}))});assert.equal(r.status,'no-match');assert.notEqual(r.status,'safe')});
test('unconfigured endpoint (501) is unknown',async()=>{const r=await checkUrlLive('https://x.example',{fetchImpl:fakeFetch(jsonRes(501,{status:'unknown'}))});assert.equal(r.status,'unknown');assert.equal(r.reason,'not-configured')});
test('server error is unknown',async()=>{const r=await checkUrlLive('https://x.example',{fetchImpl:fakeFetch(jsonRes(503,{}))});assert.equal(r.status,'unknown')});
test('network failure is unknown',async()=>{const r=await checkUrlLive('https://x.example',{fetchImpl:async()=>{throw new Error('down')}});assert.equal(r.status,'unknown');assert.equal(r.reason,'network')});
test('non-URL payloads are never submitted',async()=>{let called=false;const r=await checkUrlLive('upi://pay?pa=a@b',{fetchImpl:async()=>{called=true;return jsonRes(200,{})}});assert.equal(called,false);assert.equal(r.status,'unknown')});
