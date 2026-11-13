import test from 'node:test';
import assert from 'node:assert/strict';
import handler, { validateExplainBody, buildExplainMessages, explainWithLlm } from '../api/explain.js';

const goodBody = { type:'url', level:'high', score:80, headline:'Multiple serious warning signs', findings:[{label:'URL uses an IP address instead of a domain name',level:'high'}] };

function mockRes(){ const r={ code:0, headers:{}, body:null, status(c){r.code=c;return r}, json(o){r.body=o;return r}, setHeader(k,v){r.headers[k]=v} }; return r }

test('validateExplainBody accepts a well-formed summary',()=>{ assert.equal(validateExplainBody(goodBody),null) });
test('validateExplainBody rejects junk',()=>{
  assert.equal(validateExplainBody(null),'bad-body');
  assert.equal(validateExplainBody({...goodBody,findings:'x'}),'bad-findings');
  assert.equal(validateExplainBody({...goodBody,findings:[{label:'x'.repeat(300)}]}),'bad-findings');
});

test('explainWithLlm is unavailable without a key',async()=>{
  const out=await explainWithLlm(goodBody,{key:null,fetchImpl:async()=>{throw new Error('must not be called')}});
  assert.equal(out.status,'unavailable'); assert.equal(out.reason,'not-configured');
});

test('explainWithLlm rewords only the deterministic findings',async()=>{
  const calls=[];
  const fetchImpl=async(url,opts)=>{ calls.push({url,opts}); return { ok:true, json:async()=>({choices:[{message:{content:'This link shows several serious warning signs. Do not open it or enter any details.'}}]}) } };
  const out=await explainWithLlm(goodBody,{key:'k',fetchImpl});
  assert.equal(out.status,'ok');
  assert.match(out.explanation,/warning signs/);
  const sent=JSON.parse(calls[0].opts.body);
  assert.equal(sent.model,'glm-4-7-flash:free');
  // only finding labels and verdict data go out - never the scanned payload
  assert.ok(!JSON.stringify(sent).includes('paypal-verify-account'));
});

test('explainWithLlm reports upstream failure without faking content',async()=>{
  const out=await explainWithLlm(goodBody,{key:'k',fetchImpl:async()=>({ok:false,status:429})});
  assert.equal(out.status,'unavailable'); assert.equal(out.reason,'upstream-429');
});

test('handler: GET is rejected, missing key is 501',async()=>{
  let res=mockRes(); await handler({method:'GET'},res); assert.equal(res.code,405);
  const saved=process.env.KENARI_API_KEY; delete process.env.KENARI_API_KEY;
  res=mockRes(); await handler({method:'POST',body:goodBody},res); assert.equal(res.code,501);
  if(saved)process.env.KENARI_API_KEY=saved;
});

test('handler: bad body is 400',async()=>{
  process.env.KENARI_API_KEY='k';
  const res=mockRes(); await handler({method:'POST',body:{type:1}},res); assert.equal(res.code,400);
  delete process.env.KENARI_API_KEY;
});

test('buildExplainMessages keeps findings as data, with untrusted-data instruction',()=>{
  const msgs=buildExplainMessages(goodBody);
  assert.match(msgs[0].content,/untrusted data/);
  const user=JSON.parse(msgs[1].content);
  assert.equal(user.findings.length,1); assert.equal(user.verdict_level,'high');
});
