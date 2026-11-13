# QRShield — Internship Project Report

**Intern:** K S Akshay (USN U19KU24S0062), New Horizon College, Marathahalli

**Internship:** Cyber Security Internship, Zephyr Technologies and Solutions Pvt. Ltd., Bengaluru — 27 July 2026 to 27 September 2026, conducted offline (per the company's acceptance letter dated 25-07-2026). Structure per the company's training notes: 40 working days — Month 1 networking foundations, Month 2 core cybersecurity — assessed by daily lab work, weekly reviews, and a final practical demonstration with a short security assessment report. QRShield is that final project.

> Still to fill in before submission: mentor/guide name and any college-required template. This report describes only what the code in this repository actually does.

## 1. Problem statement

QR codes are opaque: a user cannot see where a code leads before opening it. Attackers exploit this with phishing links and fraudulent UPI payment codes. QRShield lets a user inspect QR content before interacting with it.

## 2. Objectives

- Decode QR codes from a camera feed or an uploaded image, entirely on the user's device
- Analyse URLs and UPI payment payloads with transparent, explainable rules
- Optionally check links against a real phishing threat list (Google Web Risk) without exposing the API key
- Present honest results: never claim a link or payee is "safe" when it was not verified
- Export a shareable security report (text and PDF)
- Keep all scan data private: no accounts, no server-side storage, local-only optional history

## 3. System design

Single-page application built with Vite (ES modules, no framework):

```
Camera / image upload ──► jsQR decode (in browser) ──► analyzer.mjs (local rules)
Manual paste ────────────────────────────────────────►        │
                                                              ▼
                                              URL? ──► threatintel.mjs ──► /api/check-url
                                                              │            (serverless,
                                                              ▼             Web Risk key
                                              results + history + reports   server-side)
```

- **`src/analyzer.mjs`** — deterministic scoring: each indicator adds documented points; ≥55 is "high", 20–54 is "caution", below 20 is "not verified" (never "safe").
- **`api/check-url.js`** — serverless function holding the `WEBRISK_API_KEY`. Calls Web Risk `uris:search` for MALWARE, SOCIAL_ENGINEERING and UNWANTED_SOFTWARE. Any failure, missing key or quota issue returns "unknown", and the UI shows "Not checked".
- **`src/report.mjs`** — one report model feeds both the `.txt` export and the jsPDF-generated PDF.
- **`src/history.mjs`** — localStorage history, maximum 50 entries, payloads truncated to 500 characters, can be paused or cleared.

## 4. Detection rules implemented

URL checks: missing HTTPS; embedded credentials; IP-style hosts (dotted decimal, hex, octal, single-integer, IPv6 literal); punycode/IDN domains; deep subdomain nesting; frequently abused TLDs; URL shorteners; urgency/reward/KYC wording; encoded and double-encoded characters; unusually long domains; brand impersonation by substring, hyphenation, homoglyph substitution (e.g. `paypa1`) and one-edit lookalikes (e.g. `gogle`).

UPI checks: payee VPA format; recipient name presence; links embedded in the recipient name; amount validity and high amounts; unexpected currency; urgency wording in the payment note.

## 5. Testing summary

46 automated unit tests pass (`npm test`), covering URL rules, UPI parsing (normal, malformed, suspicious), history behaviour, report content and the threat-intel client's failure modes. Production build and `npm audit` pass. Browser verification (headless Chromium): UI render, suspicious-URL analysis, QR image decode, UPI analysis, history save/clear, TXT and PDF export, XSS escaping, mobile layout. Camera capture and the live Web Risk call were verified by code and fallback behaviour, not on a physical device or with a live key. Details in TEST_RESULTS.md.

## 6. Limitations

Educational prototype. Heuristics can miss new phishing kits and can over-flag unusual but legitimate links. The live check requires deployment and an API key. QRShield never visits a scanned destination and never executes a payload.

## 7. Future work

Server-side URL unshortening with user consent, calibrated scoring from a labelled dataset, offline QR decoding tests across more devices, optional Web Risk Update API for privacy-preserving local hash checks.
