# QRShield — Five-Minute Demo Script

Prepare: `npm install && npm run dev`, open the localhost URL. (For the full live-check demo, deploy with `WEBRISK_API_KEY` set — see README.)

**Minute 1 — What it is.** "QR codes hide their destination. QRShield decodes them on the device and explains the warning signs before anyone taps."

**Minute 2 — Normal QR / link.** Paste `https://example.com`. Point out the verdict: "No heuristic warning" but explicitly **NOT VERIFIED** — clean rules cannot prove safety. Mention the live threat-list badge: "Not checked" when no key is configured, and why that is honest.

**Minute 3 — Suspicious URL.** Paste `http://paypal-verify-account.xyz/urgent-action`. Walk the findings: no HTTPS, abused TLD, urgency wording, brand impersonation, score 80/100, HIGH RISK chip. Explain the scoring is transparent: every point is listed.

**Minute 4 — UPI QR.** Paste `upi://pay?pa=shop@okbank&pn=Shop&am=500&cu=INR`. Show parsed payee ID, name, amount, currency — and stress the line "not identity-verified". Then show a malicious variant: `upi://pay?pa=bad payee&pn=https://evil.example` jumps to high risk.

**Minute 5 — Scan, history, report.** Upload a QR image (or use the camera on HTTPS) to show real decoding. Show Scan History — local-only, clearable. Finish by downloading the **PDF report** and opening it: findings, recommendations, and the limitations disclaimer.

Demo QR tip: generate practice QR codes from the URLs above with any QR generator, or use the included test pattern from the demo session.
