# QRShield — Test Results

Date of run: 13 November 2026 (IST). Environment: Node.js v22.23.4, Vite 6.x, headless Chromium (Puppeteer) on Linux.

## Automated checks

| Check | Command | Result |
| --- | --- | --- |
| Unit tests | `npm test` | **46 / 46 passed** (baseline before this phase: 11 / 11) |
| Production build | `npm run build` | **Pass** (~2.2 s; dist generated; jsPDF code-split into a lazy chunk) |
| Dependency audit | `npm audit` | **0 known vulnerabilities** |

Unit test coverage by area:
- URL rules (16 tests): HTTPS, credentials, dangerous schemes, IP forms (hex/octal/integer/IPv6), punycode, shorteners, double encoding, lookalikes (homoglyph + edit distance), brand false-positive guard, oversized payloads, malformed URLs, non-URL text, "never called safe"
- UPI parsing (7 tests): valid parse, missing payee, spaced payee, negative/non-numeric amount, link in recipient name, unexpected currency, payment note
- Scan history (6 tests): disabled = no save, round trip, 50-entry cap, truncation, corrupt storage, prototype-pollution guard
- Reports (7 tests): required fields, payload truncation, no "safe" promises, flagged/unavailable live-check wording, UPI recommendation, real PDF render via jsPDF
- Threat-intel client (6 tests): flagged / no-match mapping, 501/503/network → "unknown", non-URL payloads never submitted

## Scripted browser verification (headless Chromium, production build via `vite preview`)

| Scenario | Result |
| --- | --- |
| Initial render, desktop 1280px | **Pass** (screenshot verified) |
| Suspicious URL analysis (`http://paypal-verify-account.xyz/urgent-action`) | **Pass** — HIGH RISK chip, 4 findings, "Not checked" live badge (no key on static preview) |
| UPI analysis (`upi://pay?pa=shop@okbank&pn=Shop&am=500&cu=INR`) | **Pass** — details parsed, verification disclaimer shown |
| Real QR image upload (generated QR of the suspicious URL) | **Pass** — decoded to the exact URL, HIGH RISK |
| Scan history save / clear | **Pass** — 2 entries recorded, 0 after clear |
| `.txt` export | **Pass** — file downloaded, contents verified |
| PDF export | **Pass** — valid PDF downloaded and visually verified |
| XSS attempt via pasted content (`<img onerror>`) | **Pass** — rendered as inert text |
| Mobile layout 390px | **Pass** (screenshot verified; sections stack) |
| Console/page errors during runs | None after CSP fix (see note) |

Note: `frame-ancestors` was removed from the CSP meta tag because browsers ignore it there; set it as a response header on the hosting platform instead.

## Verified only by code review / fallback behaviour (not executed)

| Item | Status | Why |
| --- | --- | --- |
| Camera scanning on a physical device | Not executed | No camera in the test environment; code path identical to the verified image-decode path (same jsQR call), permission/error handling in place |
| Live Web Risk API call with a real key | Not executed | Requires the owner's Google Cloud key; client failure modes (501/503/timeout/network) are unit-tested, and the UI was verified to show "Not checked" when the endpoint is absent |
| Deployed URL | Not executed | Deployment happens after the repository push is authorized |

## Honest summary

Everything listed as passing above was executed and observed on the date shown. Nothing is marked complete that was only reviewed. Camera and live-key checks carry the residual risk stated above and should be exercised once on a phone and once after deployment with the key configured.
