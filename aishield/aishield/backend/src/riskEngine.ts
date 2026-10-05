// RiskEngine: weighted signals -> 0-100. Replace `aiScore` with an LLM/ML output later.
export type Cls = 'SAFE' | 'SUSPICIOUS' | 'HIGH RISK' | 'CRITICAL';
const has = (t: string, w: string[]) => w.filter(x => t.includes(x));
export function urlSignals(raw: string) {
  const flags: string[] = []; let u: URL;
  try { u = new URL(/^https?:\/\//i.test(raw) ? raw : 'http://' + raw); } catch { throw new Error('Invalid URL'); }
  const h = u.hostname.toLowerCase(); let s = 0;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(h)) { s += 60; flags.push('IP-based URL'); }
  if (/(bit\.ly|tinyurl|t\.co|goo\.gl|cutt\.ly|is\.gd)/.test(h)) { s += 40; flags.push('URL shortener hides destination'); }
  if (h.split('.').length > 4) { s += 30; flags.push('Excessive subdomains'); }
  if (/\.(xyz|top|tk|click|ml|ga|work|zip)$/.test(h)) { s += 35; flags.push('Suspicious TLD'); }
  if (/[@%]|xn--/.test(raw) || h.split('-').length > 2) { s += 25; flags.push('Suspicious characters'); }
  if (/(login|verify|secure|account|update|bank|pay|wallet|kyc)/.test(h + u.pathname)) { s += 25; flags.push('Login/payment keywords in URL'); }
  if (u.protocol === 'http:') { s += 15; flags.push('No HTTPS encryption'); }
  return { host: h, score: Math.min(100, s), flags };
}
export function textSignals(t0: string) {
  const t = t0.toLowerCase();
  return {
    urg: has(t, ['urgent', 'immediately', 'today', 'within 24', 'last chance', 'blocked', 'suspended', 'expire']),
    cred: has(t, ['otp', 'password', 'pin', 'cvv', 'verify', 'kyc', 'login']),
    fin: has(t, ['bank', 'refund', 'send money', 'transfer', 'prize', 'winner', 'won ', '₹', 'rs ', 'lottery', 'pay ', 'congratulations', 'claim', 'reward', 'gift']),
    link: /https?:\/\/|www\.|bit\.ly/.test(t) || /\bclick\b/.test(t),
  };
}
export const classify = (n: number): Cls => n >= 80 ? 'CRITICAL' : n >= 60 ? 'HIGH RISK' : n >= 30 ? 'SUSPICIOUS' : 'SAFE';
export function analyze(type: string, input: string, aiScore = 0) {
  const t = textSignals(input); const m = input.match(/(https?:\/\/\S+|\b[\w.-]+\.[a-z]{2,}\/\S*)/i);
  let u: ReturnType<typeof urlSignals> | null = null;
  try { if (type === 'url') u = urlSignals(input.trim()); else if (m) u = urlSignals(m[0]); } catch (e) { if (type === 'url') throw e; }
  const cap = (n: number, k = 60) => Math.min(100, n * k); const us = u?.score ?? 0;
  const factors = [
    { name: 'URL reputation', weight: 20, score: us }, { name: 'Domain anomaly', weight: 20, score: us },
    { name: 'Suspicious keywords', weight: 15, score: type === 'url' ? 0 : cap(t.urg.length + t.cred.length + t.fin.length, 35) },
    { name: 'Credential request', weight: 15, score: cap(t.cred.length) }, { name: 'Urgency language', weight: 10, score: cap(t.urg.length) },
    { name: 'Financial manipulation', weight: 10, score: cap(t.fin.length) }, { name: 'AI assessment', weight: 10, score: aiScore },
  ];
  const wsum = us > 0 ? 100 : 60; // ignore URL factors when no URL present
  const raw = factors.reduce((a, x) => a + x.weight * x.score, 0) / wsum;
  const sig = [t.urg.length, t.cred.length, t.fin.length, t.link, us > 30].filter(Boolean).length;
  const benign = /^your otp is \d+\.?$/i.test(input.trim());
  const score = benign ? 10 : Math.round(Math.min(100, raw * 1.9 + (sig >= 3 ? 35 : sig === 2 ? 20 : 0)));
  const indicators = [...(u?.flags ?? []), ...(t.urg.length ? ['Urgency manipulation'] : []), ...(t.cred.length ? ['Credential / OTP request'] : []),
    ...(t.fin.length ? ['Financial request or lure'] : []), ...(t.link && type !== 'url' ? ['Contains link'] : [])];
  const cat = score < 30 ? 'Safe' : t.fin.some(x => /prize|winner|won|lottery/.test(x)) ? 'Financial Scam' : type === 'url' ? 'Suspicious Website' : t.cred.length ? 'Phishing' : 'Social Engineering';
  const bad = score >= 30;
  return {
    riskScore: score, classification: classify(score), threatCategory: cat, confidence: Math.min(98, 70 + sig * 6),
    provider: 'AIShield Demo Analysis', factors, indicators,
    analysis: { host: u?.host, explanation: bad ? indicators.map((x, i) => `${i + 1}. ${x}.`).join(' ') + ' Scammers push you to act before you verify.' : 'No meaningful scam patterns detected.' },
    recommendations: bad ? ['Do not click the link', 'Do not share OTP or card details', 'Do not transfer money', 'Verify the sender independently'] : ['Looks safe, stay alert'],
  };
}
