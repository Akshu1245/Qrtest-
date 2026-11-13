import test from 'node:test';import assert from 'node:assert/strict';import {analyze} from '../src/analyzer.mjs';import {buildReportModel,toText,toPdf} from '../src/report.mjs';

const sample=analyze('http://paypal-verify-account.xyz/urgent-action');

test('report model carries every required field',()=>{const m=buildReportModel('http://paypal-verify-account.xyz/urgent-action',sample);for(const k of ['title','generatedAt','category','riskLevel','heuristicScore','scannedContent','liveCheck','headline','summary','findings','recommendations','limitations'])assert.ok(k in m,k);assert.equal(m.title,'QRShield Security Assessment')});
test('report truncates very long scanned content',()=>{const long='https://example.com/'+'a'.repeat(5000);const m=buildReportModel(long,analyze(long));assert.ok(m.scannedContent.length<2400);assert.match(m.contentNote,/shortened/i)});
test('report text never promises safety',()=>{const m=buildReportModel('https://example.com',analyze('https://example.com'));const t=toText(m);assert.doesNotMatch(t,/\bguaranteed safe\b/i);assert.doesNotMatch(t,/this (link|url|payee) is safe/i);assert.match(t,/does NOT prove|does NOT mean/i)});
test('flagged live result appears in report',()=>{const m=buildReportModel('https://x.example',sample,{status:'flagged',threats:['MALWARE'],source:'Google Web Risk'});assert.match(m.liveCheck,/dangerous/i);assert.match(m.recommendations.join(' '),/Do not open/i)});
test('unavailable live check is reported as not checked',()=>{const m=buildReportModel('https://x.example',sample,null);assert.match(m.liveCheck,/Not checked/i)});
test('UPI report recommends independent verification',()=>{const a=analyze('upi://pay?pa=shop@okbank&pn=Shop&am=500');const m=buildReportModel('upi://pay?pa=shop@okbank&pn=Shop&am=500',a);assert.match(m.recommendations.join(' '),/trusted payment app/i)});
test('PDF renders locally with jsPDF',async()=>{const {jsPDF}=await import('jspdf');const m=buildReportModel('https://example.com',analyze('https://example.com'));const doc=toPdf(m,jsPDF);const out=doc.output('datauristring');assert.match(out,/^data:application\/pdf/);assert.ok(out.length>2000)});
