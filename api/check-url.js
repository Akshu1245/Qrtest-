/**
 * Serverless endpoint (Vercel Node runtime): GET /api/check-url?uri=<http(s) URL>
 * Checks one URL against Google Web Risk Lookup API (uris:search).
 *
 * The API key lives ONLY in the WEBRISK_API_KEY environment variable on the
 * server. It is never shipped to the browser. Without a key the endpoint
 * answers 501 and the app shows "Not checked" instead of any verdict.
 *
 * Web Risk Lookup API: free for up to 100,000 calls/month (see
 * https://cloud.google.com/web-risk/pricing). Non-commercial use.
 */

const THREAT_TYPES = ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'];
const MAX_URL_LENGTH = 2000;

export default async function handler(req, res) {
  try {
    if (req.method !== 'GET') {
      res.setHeader('Allow', 'GET');
      return res.status(405).json({ status: 'unknown', error: 'method-not-allowed' });
    }
    const key = process.env.WEBRISK_API_KEY;
    if (!key) return res.status(501).json({ status: 'unknown', error: 'not-configured' });

    const uri = req.query && req.query.uri;
    if (typeof uri !== 'string' || uri.length > MAX_URL_LENGTH || !/^https?:\/\//i.test(uri)) {
      return res.status(400).json({ status: 'unknown', error: 'bad-uri' });
    }

    const params = new URLSearchParams();
    for (const t of THREAT_TYPES) params.append('threatTypes', t);
    params.set('uri', uri);
    params.set('key', key);

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 8000);
    let upstream;
    try {
      upstream = await fetch('https://webrisk.googleapis.com/v1/uris:search?' + params.toString(), { signal: ctrl.signal });
    } finally {
      clearTimeout(timer);
    }

    if (upstream.status === 200) {
      const data = await upstream.json();
      const threats = data && data.threat && Array.isArray(data.threat.threatTypes) ? data.threat.threatTypes : [];
      res.setHeader('Cache-Control', 'private, max-age=300');
      return res.status(200).json(threats.length
        ? { status: 'flagged', threats, source: 'Google Web Risk' }
        : { status: 'no-match', threats: [], source: 'Google Web Risk' });
    }
    // Quota exhaustion (429), auth problems (403) and upstream failures all
    // mean "not checked", never "safe". Do not leak the key or upstream body.
    return res.status(503).json({ status: 'unknown', error: 'upstream-' + upstream.status });
  } catch (e) {
    return res.status(503).json({ status: 'unknown', error: e && e.name === 'AbortError' ? 'timeout' : 'failure' });
  }
}
