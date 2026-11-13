import test from 'node:test';import assert from 'node:assert/strict';import {analyze} from '../src/analyzer.mjs';

test('Hex IP host is flagged as IP-style',()=>{const r=analyze('http://0x7f000001/');assert.ok(r.findings.some(f=>/IP address/i.test(f.label)))});
test('Integer IP host is flagged',()=>{const r=analyze('http://2130706433/');assert.ok(r.findings.some(f=>/IP address/i.test(f.label)))});
test('IPv6 literal host is flagged',()=>{const r=analyze('http://[2001:db8::1]/');assert.ok(r.findings.some(f=>/IP address/i.test(f.label)))});
test('Homoglyph lookalike paypa1 is flagged',()=>{const r=analyze('https://paypa1.com/login');assert.ok(r.findings.some(f=>/lookalike|impersonation/i.test(f.label)))});
test('Near-miss domain gogle.com is flagged',()=>{const r=analyze('https://gogle.com/');assert.ok(r.findings.some(f=>/lookalike|impersonation/i.test(f.label)))});
test('Double-encoded characters raise a finding',()=>{const r=analyze('https://example.com/%252e%252e/');assert.ok(r.findings.some(f=>/double-encoded/i.test(f.label)))});
test('New shortener domain is flagged',()=>{const r=analyze('https://shorturl.at/abcXY');assert.ok(r.findings.some(f=>/shortened/i.test(f.label)))});
test('Official brand domain is not flagged as impersonation',()=>{const r=analyze('https://accounts.google.com/signin');assert.ok(!r.findings.some(f=>/impersonation|lookalike/i.test(f.label)))});
test('Legit https URL still never labelled safe',()=>{const r=analyze('https://example.com');assert.equal(r.level,'unknown');assert.match(r.details,/does NOT mean the URL is safe/i)});
test('vbscript scheme blocked',()=>assert.equal(analyze('vbscript:msgbox(1)').level,'high'));
test('UPI transaction note is shown',()=>{const r=analyze('upi://pay?pa=shop@okbank&pn=Shop&am=10&tn=Order%20123');assert.ok(r.findings.some(f=>/note/i.test(f.label)&&f.label.includes('Order 123')))});
test('UPI payee with spaces is high risk',()=>assert.equal(analyze('upi://pay?pa=bad payee&pn=X').level,'high'));
test('UPI negative amount is high risk',()=>assert.equal(analyze('upi://pay?pa=shop@okbank&am=-5').level,'high'));
test('UPI non-numeric amount is high risk',()=>assert.equal(analyze('upi://pay?pa=shop@okbank&am=abc').level,'high'));
test('UPI recipient name containing a link is high',()=>assert.equal(analyze('upi://pay?pa=shop@okbank&pn=https%3A%2F%2Fevil.example').level,'high'));
test('Oversized payload is capped, not crashing',()=>{const r=analyze('https://example.com/'+'a'.repeat(13000));assert.equal(r.level,'caution');assert.match(r.headline,/unusually large/i)});
