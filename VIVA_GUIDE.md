# QRShield — Viva Guide (20 questions)

**1. What is the aim of QRShield?** To let a user inspect QR content — links and UPI payment details — before opening or paying, using transparent rules and honest wording.

**2. What is QR phishing?** A QR code that leads to a fraudulent destination, for example a fake banking page or a payment code for an attacker's account.

**3. Which technologies does it use?** JavaScript (ES modules), Vite, plain CSS, jsQR for decoding, jsPDF for reports, and a small serverless function for the live threat check.

**4. What is jsQR?** An open-source library (Apache-2.0) that decodes QR pixels into text. It runs fully in the browser.

**5. Where is QR content decoded?** On the user's device. Images and camera frames never leave the browser.

**6. How does the risk score work?** Each indicator adds documented points (for example: no HTTPS +20, embedded credentials +60, shortener +25). A total of 55+ is "high", 20–54 is "caution", below that is "not verified".

**7. Why is nothing labelled "safe"?** Clean heuristics cannot prove safety, and neither can absence from a threat list. The UI and reports say "not verified" or "not checked" instead.

**8. What is a lookalike domain?** A domain imitating a brand: substring tricks (`paypal-secure.xyz`), character swaps (`paypa1.com`), or one-edit typos (`gogle.com`). QRShield checks all three.

**9. Which IP-style hosts are detected?** Dotted decimal, hexadecimal, octal, single-integer forms and IPv6 literals, all unusual for legitimate links.

**10. What is double encoding and why is it flagged?** `%252e` decodes twice to `.`. Attackers use it to hide paths; the rule adds points when it appears.

**11. How does the live threat check work?** The browser asks the serverless endpoint `/api/check-url`, which queries Google Web Risk `uris:search` with a server-side key and returns "flagged", "no-match" or "unknown".

**12. Why is the API key server-side?** A key shipped to the browser can be stolen and abused, running up quota. Only the serverless function sees `WEBRISK_API_KEY`.

**13. What happens when the provider fails or is not configured?** The endpoint answers 501/503, the client treats any error or timeout as "unknown", and the UI shows "Not checked", never a safety verdict.

**14. What privacy limits does the live check have?** Only `http(s)` URLs are sent for checking, and the UI says so. UPI strings, Wi-Fi configs and text payloads are never transmitted.

**15. What does the UPI parser check?** Payee VPA format, displayed recipient name, amount and currency, payment note, links hidden in the name, and unusual amounts. It never claims the payee is verified.

**16. How does scan history stay private?** It uses browser localStorage only (no upload), with at most 50 entries, 500-character payload truncation, and one-click pause or clear.

**17. How is XSS prevented?** Every user-controlled string passes through an HTML escaper before entering the DOM, and a Content-Security-Policy restricts scripts to the app's own bundle.

**18. How was it tested?** 46 automated unit tests plus a production build and dependency audit, and a scripted browser pass (headless Chromium) covering analysis, QR image decode, history, exports and mobile layout. Camera and live-key behaviour were verified through code paths and fallbacks, not on a physical device.

**19. What would you improve next?** Consent-based unshortening, calibrated scoring on a labelled dataset, and Web Risk's Update API for privacy-preserving local hash checks.

**20. Which parts are third-party code?** jsQR (decoding), jsPDF (PDF), Vite (build), all credited with their licenses. The rules engine, UPI parser, threat-intel client, serverless endpoint, history, reports, UI and tests are project code.
