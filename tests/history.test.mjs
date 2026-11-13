import test from 'node:test';import assert from 'node:assert/strict';import * as history from '../src/history.mjs';

function memStore(){const m=new Map();return {getItem:k=>m.has(k)?m.get(k):null,setItem:(k,v)=>m.set(k,String(v)),removeItem:k=>m.delete(k)}}

test('history disabled means nothing is saved',()=>{const s=memStore();history.setEnabled(false,s);history.add({input:'https://a.example',type:'url',level:'caution'},s);assert.equal(history.list(s).length,0)});
test('add/list/clear round trip',()=>{const s=memStore();history.setEnabled(true,s);history.add({input:'https://a.example',type:'url',level:'caution',score:25,headline:'h'},s);const l=history.list(s);assert.equal(l.length,1);assert.equal(l[0].input,'https://a.example');history.clear(s);assert.equal(history.list(s).length,0)});
test('history is capped at 50 entries',()=>{const s=memStore();history.setEnabled(true,s);for(let i=0;i<60;i++)history.add({input:'https://e'+i+'.example',type:'url',level:'unknown',score:0,headline:'h'},s);assert.equal(history.list(s).length,50)});
test('stored payload is truncated',()=>{const s=memStore();history.setEnabled(true,s);history.add({input:'x'.repeat(900),type:'text',level:'unknown',score:null,headline:'h'},s);assert.ok(history.list(s)[0].input.length<=500)});
test('corrupt JSON in storage reads as empty',()=>{const s=memStore();s.setItem('qrshield.history.v1','{not json');assert.deepEqual(history.list(s),[])});
test('hostile keys in storage cannot pollute prototypes',()=>{const s=memStore();s.setItem('qrshield.history.v1','[{"__proto__":{"polluted":true},"input":"https://x.example","type":"url","level":"caution"}]');const l=history.list(s);assert.equal({}.polluted,undefined);assert.equal(l.length,1);assert.deepEqual(Object.keys(l[0]).sort(),['checkedAt','headline','input','level','score','type'])});
