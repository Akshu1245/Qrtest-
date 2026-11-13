# Contributions and Attribution

## Third-party open-source dependencies (not original work)

| Package | License | Used for |
| --- | --- | --- |
| [jsQR](https://github.com/cozmo/jsQR) | Apache-2.0 | Decoding QR codes from images and camera frames |
| [jsPDF](https://github.com/parallax/jsPDF) | MIT | Generating PDF reports locally in the browser |
| [Vite](https://github.com/vitejs/vite) | MIT | Development server and production builds |
| [Rough.js](https://github.com/rough-stuff/rough) | MIT | Hand-sketched interface frames and pen marks |
| [Caveat](https://fonts.google.com/specimen/Caveat) | SIL OFL | Handwriting typeface for interface labels |

Licenses are retained via the packages' own distributions (`node_modules`) and their respective repositories.

## External service (optional, configured by the operator)

- **Google Web Risk Lookup API** — live phishing/malware URL checks through `api/check-url.js`. Subject to Google's terms; non-commercial use; free tier 100,000 lookups/month. Not affiliated with this project.

## Project code

All other files in this repository — the rules engine (`src/analyzer.mjs`), UPI parser, threat-intel client (`src/threatintel.mjs`), serverless endpoint (`api/check-url.js`), scan history (`src/history.mjs`), report builders (`src/report.mjs`), user interface (`src/main.js`, `src/style.css`) and the test suite — are project code written for this internship project.

**Author statement:** K S Akshay states (WhatsApp, 13 Nov 2026) that he did the whole project himself. This file records that statement; the commit history and the author's ability to explain and demonstrate every module (see VIVA_GUIDE.md) are the evidence to bring to submission. Third-party libraries and the optional Google Web Risk service remain credited above and are not part of the original work.
