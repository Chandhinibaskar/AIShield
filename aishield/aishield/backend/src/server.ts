import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors'; import helmet from 'helmet'; import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs'; import jwt from 'jsonwebtoken'; import { Pool } from 'pg';
import { analyze } from './riskEngine';
import path from 'path';
export const db = new Pool({ connectionString: process.env.DATABASE_URL });
const SECRET = process.env.JWT_SECRET || 'dev-secret'; const app = express();
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'", "'unsafe-inline'"], scriptSrcAttr: ["'unsafe-inline'"], styleSrc: ["'self'", "'unsafe-inline'"], imgSrc: ["'self'", 'data:'], connectSrc: ["'self'"] } } }), cors({ origin: process.env.FRONTEND_URL || 'http://localhost:5173' }), express.json({ limit: '6mb' }));
app.use(express.static(path.join(__dirname, '../../frontend')));
app.use('/api', rateLimit({ windowMs: 60_000, limit: 120 }));
const wrap = (fn: any) => (q: Request, s: Response, n: NextFunction) => Promise.resolve(fn(q, s, n)).catch(n);
const auth = (q: any, s: Response, n: NextFunction) => { try { q.uid = (jwt.verify((q.headers.authorization || '').replace('Bearer ', ''), SECRET) as any).uid; n(); } catch { s.status(401).json({ error: 'Please sign in again.' }); } };
const tok = (uid: string) => jwt.sign({ uid }, SECRET, { expiresIn: '7d' });
app.post('/api/auth/register', wrap(async (q: Request, s: Response) => {
  const { name, email, password } = q.body;
  if (!name || !/^\S+@\S+\.\S+$/.test(email) || (password || '').length < 8) return s.status(400).json({ error: 'Valid name, email and 8+ char password required.' });
  const r = await db.query('INSERT INTO users(name,email,password_hash) VALUES($1,$2,$3) ON CONFLICT DO NOTHING RETURNING id,name,email', [name, email.toLowerCase(), await bcrypt.hash(password, 12)]);
  if (!r.rows[0]) return s.status(409).json({ error: 'Email already registered.' });
  s.json({ token: tok(r.rows[0].id), user: r.rows[0] });
}));
app.post('/api/auth/login', wrap(async (q: Request, s: Response) => {
  const u = (await db.query('SELECT * FROM users WHERE email=$1', [String(q.body.email || '').toLowerCase()])).rows[0];
  if (!u || !(await bcrypt.compare(q.body.password || '', u.password_hash))) return s.status(401).json({ error: 'Invalid email or password.' });
  s.json({ token: tok(u.id), user: { id: u.id, name: u.name, email: u.email } });
}));
app.get('/api/auth/me', auth, wrap(async (q: any, s: Response) => s.json((await db.query('SELECT id,name,email,created_at FROM users WHERE id=$1', [q.uid])).rows[0])));
for (const type of ['url', 'message', 'email', 'screenshot', 'qr']) app.post(`/api/scan/${type}`, auth, wrap(async (q: any, s: Response) => {
  const input = String(q.body.input ?? '').slice(0, 5000); // screenshot/qr: OCR / decoded text
  if (!input.trim()) return s.status(400).json({ error: 'Nothing to analyze.' });
  let r; try { r = analyze(type === 'qr' ? 'url' : type, input); } catch (e: any) { return s.status(400).json({ error: e.message }); }
  const row = await db.query('INSERT INTO scans(user_id,type,input,risk_score,classification,threat_category,confidence,analysis,recommendations) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id',
    [q.uid, type, input, r.riskScore, r.classification, r.threatCategory, r.confidence, JSON.stringify({ ...r.analysis, factors: r.factors, indicators: r.indicators, provider: r.provider }), JSON.stringify(r.recommendations)]);
  s.json({ id: row.rows[0].id, ...r });
}));
app.get('/api/scans', auth, wrap(async (q: any, s: Response) => s.json((await db.query('SELECT * FROM scans WHERE user_id=$1 ORDER BY created_at DESC LIMIT 200', [q.uid])).rows)));
app.get('/api/scans/:id', auth, wrap(async (q: any, s: Response) => { const r = await db.query('SELECT * FROM scans WHERE id=$1 AND user_id=$2', [q.params.id, q.uid]); r.rows[0] ? s.json(r.rows[0]) : s.status(404).json({ error: 'Not found' }); }));
app.delete('/api/scans/:id', auth, wrap(async (q: any, s: Response) => { await db.query('DELETE FROM scans WHERE id=$1 AND user_id=$2', [q.params.id, q.uid]); s.json({ ok: true }); }));
app.get('/api/analytics', auth, wrap(async (q: any, s: Response) => s.json({
  byClassification: (await db.query('SELECT classification,count(*)::int c FROM scans WHERE user_id=$1 GROUP BY 1', [q.uid])).rows,
  perDay: (await db.query("SELECT date_trunc('day',created_at)::date d,count(*)::int c FROM scans WHERE user_id=$1 GROUP BY 1 ORDER BY 1", [q.uid])).rows })));
app.use((e: any, _q: Request, s: Response, _n: NextFunction) => { console.error(e); s.status(500).json({ error: 'Something went wrong. Please try again.' }); });
if (require.main === module) app.listen(Number(process.env.PORT) || 4000, () => console.log('AIShield API on :4000'));
