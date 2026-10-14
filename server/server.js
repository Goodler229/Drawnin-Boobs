const express = require('express'), { ImapFlow } = require('imapflow');
const crypto = require('crypto'), fs = require('fs'), path = require('path');

const PORT = +process.env.PORT || 3000;
const DATA = process.env.DATA_DIR || path.join(__dirname, 'data');
const IMAP_HOST = process.env.IMAP_HOST;
const IMAP_PORT = +process.env.IMAP_PORT || 993;
const IMAP_SECURE = process.env.IMAP_SECURE !== 'false';
const REJECT = process.env.IMAP_REJECT_UNAUTHORIZED !== 'false';
const USER_IS_EMAIL = process.env.IMAP_USER_IS_EMAIL !== 'false';
const ALLOWED = (process.env.ALLOWED_DOMAINS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);

fs.mkdirSync(path.join(DATA, 'users'), { recursive: true });
let SECRET = process.env.SECRET;
const sf = path.join(DATA, 'secret');
if (!SECRET) {
  try { SECRET = fs.readFileSync(sf, 'utf8'); }
  catch { SECRET = crypto.randomBytes(32).toString('hex'); fs.writeFileSync(sf, SECRET, { mode: 0o600 }); }
}
const sign = s => crypto.createHmac('sha256', SECRET).update(s).digest('base64url');
const mkTok = email => { const p = Buffer.from(JSON.stringify({ e: email, x: Date.now() + 30 * 864e5 })).toString('base64url'); return p + '.' + sign(p); };
function verify(t) {
  const [p, s] = (t || '').split('.'); if (!p || !s) return null;
  const a = Buffer.from(sign(p)), b = Buffer.from(s);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try { const o = JSON.parse(Buffer.from(p, 'base64url')); return o.x > Date.now() ? o.e : null; } catch { return null; }
}

// Перевірка пароля = вхід на IMAP-сервер. Пароль не зберігається.
async function imapOk(email, pass) {
  const c = new ImapFlow({ host: IMAP_HOST, port: IMAP_PORT, secure: IMAP_SECURE, logger: false,
    auth: { user: USER_IS_EMAIL ? email : email.split('@')[0], pass }, tls: { rejectUnauthorized: REJECT } });
  c.on('error', () => {});
  try { await c.connect(); await c.logout(); return true; }
  catch { try { c.close(); } catch {} return false; }
}

const tries = new Map();
const limited = ip => { const n = Date.now(), a = (tries.get(ip) || []).filter(t => n - t < 6e5); tries.set(ip, a); return a.length >= 10; };
const file = e => path.join(DATA, 'users', crypto.createHash('sha256').update(e).digest('hex') + '.json');
const readDoc = e => { try { return JSON.parse(fs.readFileSync(file(e), 'utf8')); } catch { return { rev: 0, data: { items: [], del: {} } }; } };

const app = express();
app.set('trust proxy', !!process.env.TRUST_PROXY);
app.use((q, r, n) => {
  r.set({ 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET,PUT,POST,OPTIONS' });
  if (q.method === 'OPTIONS') return r.sendStatus(204); n();
});
app.use(express.json({ limit: '20mb' }));

app.post('/api/login', async (q, r) => {
  const { email, password } = q.body || {}, e = String(email || '').trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) || e.length > 254 || typeof password !== 'string' || !password || password.length > 512)
    return r.status(400).json({ error: 'Невірні дані' });
  if (ALLOWED.length && !ALLOWED.includes(e.split('@')[1])) return r.status(403).json({ error: 'Цей домен не дозволено' });
  if (limited(q.ip)) return r.status(429).json({ error: 'Забагато спроб, спробуйте пізніше' });
  if (password !== process.env.LOCAL_LOGIN_PASSWORD) {
  tries.get(q.ip).push(Date.now());
  return r.status(401).json({ error: 'Невірний email або пароль' });
}
  r.json({ token: mkTok(e), email: e });
});

const auth = (q, r, n) => {
  const e = verify((q.get('authorization') || '').replace(/^Bearer /, ''));
  if (!e) return r.status(401).json({ error: 'unauthorized' }); q.email = e; n();
};
app.get('/api/data', auth, (q, r) => r.json(readDoc(q.email)));
app.put('/api/data', auth, (q, r) => {
  const { rev, data } = q.body || {};
  if (!data || !Array.isArray(data.items)) return r.status(400).json({ error: 'bad data' });
  const cur = readDoc(q.email);
  if (rev !== cur.rev) return r.status(409).json({ error: 'conflict', rev: cur.rev });
  const doc = { rev: cur.rev + 1, data: { items: data.items, del: data.del || {} } }, f = file(q.email);
  fs.writeFileSync(f + '.tmp', JSON.stringify(doc)); fs.renameSync(f + '.tmp', f);
  r.json({ rev: doc.rev });
});
app.use(express.static(path.join(__dirname, 'public')));
app.listen(PORT, () => console.log('Neuromap: http://localhost:' + PORT));
