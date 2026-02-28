const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const path    = require('path');
const crypto  = require('crypto');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error('ERROR: SUPABASE_URL and SUPABASE_KEY env vars not set.');
  process.exit(1);
}

const db = createClient(SUPABASE_URL, SUPABASE_KEY);

// ── Sessions ─────────────────────────────────────────────────────
const sessions = new Map();
function makeToken()  { return crypto.randomBytes(32).toString('hex'); }
function sha256(str)  { return crypto.createHash('sha256').update(str).digest('hex'); }

function requireAuth(req, res, next) {
  const token = req.headers['x-session'];
  if (!token || !sessions.has(token)) return res.status(401).json({ error: 'Not logged in.' });
  req.user = sessions.get(token);
  next();
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required.' });
  next();
}

// ── Validators ───────────────────────────────────────────────────
function isUUID(v)  { return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(v)); }
function isPhone(v) { return /^\d{10}$/.test(String(v)); }
function isEmail(v) { return typeof v === 'string' && v.includes('@') && v.length <= 254; }
function sanitize(v){ return String(v).trim().replace(/[<>"'`]/g, '').slice(0, 500); }

// ════════════════════════════════════════════════════════════════
//  AUTH
// ════════════════════════════════════════════════════════════════

// POST /api/login  → returns { token, name, role }
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Missing fields.' });
  if (!isEmail(email))     return res.status(400).json({ error: 'Invalid email.' });

  const hashed = sha256(String(password));

  const { data, error } = await db
    .from('Members')
    .select('id, name, email, role')
    .eq('email', email.toLowerCase().trim())
    .eq('password', hashed)
    .single();

  if (error || !data) return res.status(401).json({ error: 'Invalid email or password.' });

  const token = makeToken();
  sessions.set(token, { id: data.id, name: data.name, email: data.email, role: data.role });
  setTimeout(() => sessions.delete(token), 12 * 60 * 60 * 1000);

  res.json({ token, name: data.name, role: data.role });
});

// POST /api/logout
app.post('/api/logout', requireAuth, (req, res) => {
  sessions.delete(req.headers['x-session']);
  res.json({ ok: true });
});

// ════════════════════════════════════════════════════════════════
//  EVENTS  (read: all auth users | write: admin only)
// ════════════════════════════════════════════════════════════════

app.get('/api/events', requireAuth, async (req, res) => {
  const { data, error } = await db.from('Events').select('id, title, cost').order('title');
  if (error) return res.status(500).json({ error: 'Failed to load events.' });
  res.json(data);
});

app.post('/api/events', requireAuth, requireAdmin, async (req, res) => {
  const title = sanitize(req.body.title || '');
  const cost  = parseFloat(req.body.cost);
  if (!title)            return res.status(400).json({ error: 'Title is required.' });
  if (isNaN(cost) || cost <= 0) return res.status(400).json({ error: 'Cost must be > 0.' });
  const { error } = await db.from('Events').insert({ title, cost });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

app.put('/api/events/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  if (!isUUID(id)) return res.status(400).json({ error: 'Invalid event ID.' });
  const cost = parseFloat(req.body.cost);
  if (isNaN(cost) || cost <= 0) return res.status(400).json({ error: 'Cost must be > 0.' });
  const { error } = await db.from('Events').update({ cost }).eq('id', id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

app.delete('/api/events/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  if (!isUUID(id)) return res.status(400).json({ error: 'Invalid event ID.' });
  const { error } = await db.from('Events').delete().eq('id', id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// ════════════════════════════════════════════════════════════════
//  MEMBERS  (admin only)
// ════════════════════════════════════════════════════════════════

app.get('/api/members', requireAuth, requireAdmin, async (req, res) => {
  const { data, error } = await db
    .from('Members')
    .select('id, name, email, role, created_at')
    .order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: 'Failed to load members.' });
  res.json(data);
});

app.post('/api/members', requireAuth, requireAdmin, async (req, res) => {
  const name  = sanitize(req.body.name || '');
  const email = sanitize(req.body.email || '').toLowerCase();
  const pw    = String(req.body.password || '');
  const role  = req.body.role === 'admin' ? 'admin' : 'member';

  if (!name)           return res.status(400).json({ error: 'Name is required.' });
  if (!isEmail(email)) return res.status(400).json({ error: 'Invalid email.' });
  if (pw.length < 8)   return res.status(400).json({ error: 'Password must be at least 8 characters.' });

  const { error } = await db.from('Members').insert({ name, email, password: sha256(pw), role });
  if (error) {
    if (error.code === '23505') return res.status(400).json({ error: 'Email already exists.' });
    return res.status(500).json({ error: error.message });
  }
  res.json({ ok: true });
});

app.put('/api/members/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  if (!isUUID(id)) return res.status(400).json({ error: 'Invalid ID.' });

  const updates = {};
  if (req.body.role && ['admin','member'].includes(req.body.role)) updates.role = req.body.role;
  if (req.body.password) {
    if (String(req.body.password).length < 8) return res.status(400).json({ error: 'Password too short.' });
    updates.password = sha256(String(req.body.password));
  }
  if (req.body.name)  updates.name  = sanitize(req.body.name);
  if (req.body.email) {
    const e = sanitize(req.body.email).toLowerCase();
    if (!isEmail(e)) return res.status(400).json({ error: 'Invalid email.' });
    updates.email = e;
  }

  if (!Object.keys(updates).length) return res.status(400).json({ error: 'Nothing to update.' });

  const { error } = await db.from('Members').update(updates).eq('id', id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

app.delete('/api/members/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  if (!isUUID(id)) return res.status(400).json({ error: 'Invalid ID.' });
  if (id === req.user.id) return res.status(400).json({ error: "You can't delete yourself." });
  const { error } = await db.from('Members').delete().eq('id', id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// ════════════════════════════════════════════════════════════════
//  REGISTRATIONS
// ════════════════════════════════════════════════════════════════

// GET /api/sales  — member: own sales | admin: all sales
app.get('/api/sales', requireAuth, async (req, res) => {
  let query = db
    .from('Registrations')
    .select(`
      id, payment_method, transaction_id, amount_paid, registered_at,
      Students ( id, name, phone_number, email ),
      Events   ( id, title, cost ),
      Members  ( id, name )
    `)
    .order('registered_at', { ascending: false });

  // Members only see their own; admins see all
  if (req.user.role !== 'admin') query = query.eq('member_id', req.user.id);

  const { data, error } = await query;
  if (error) return res.status(500).json({ error: 'Failed to load sales.' });
  res.json(data);
});

// POST /api/register
app.post('/api/register', requireAuth, async (req, res) => {
  const { name, phone, email, event_id, payment_method, transaction_id } = req.body;

  if (!name || !phone || !email || !event_id || !payment_method)
    return res.status(400).json({ error: 'Missing required fields.' });
  if (!isPhone(phone))  return res.status(400).json({ error: 'Phone must be exactly 10 digits.' });
  if (!isEmail(email))  return res.status(400).json({ error: 'Invalid email address.' });
  if (!isUUID(event_id))return res.status(400).json({ error: 'Invalid event.' });
  if (!['cash','upi'].includes(payment_method)) return res.status(400).json({ error: 'Invalid payment method.' });
  if (payment_method === 'upi' && !transaction_id) return res.status(400).json({ error: 'UPI transaction ID required.' });

  const cleanName  = sanitize(name);
  const cleanEmail = sanitize(email).toLowerCase();
  const cleanTxn   = transaction_id ? sanitize(transaction_id) : null;

  const { data: evData, error: evErr } = await db.from('Events').select('cost').eq('id', event_id).single();
  if (evErr || !evData) return res.status(400).json({ error: 'Event not found.' });

  let studentId;
  const { data: existing } = await db.from('Students').select('id').eq('phone_number', String(phone)).maybeSingle();
  if (existing) {
    studentId = existing.id;
    await db.from('Students').update({ name: cleanName, email: cleanEmail }).eq('id', studentId);
  } else {
    const { data: newStu, error: stuErr } = await db.from('Students')
      .insert({ name: cleanName, email: cleanEmail, phone_number: String(phone) }).select().single();
    if (stuErr) {
      if (stuErr.code === '23505') return res.status(400).json({ error: 'Email already used by another student.' });
      return res.status(500).json({ error: 'Failed to save student.' });
    }
    studentId = newStu.id;
  }

  const { error: regErr } = await db.from('Registrations').insert({
    student_id:     studentId,
    event_id,
    member_id:      req.user.id,
    payment_method,
    transaction_id: payment_method === 'upi' ? cleanTxn : null,
    amount_paid:    evData.cost
  });

  if (regErr) {
    if (regErr.code === '23505') return res.status(400).json({ error: 'Student already registered for this event.' });
    return res.status(500).json({ error: 'Failed to create registration.' });
  }
  res.json({ ok: true });
});

// PUT /api/sales/:id
app.put('/api/sales/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { student_id, name, phone, email, event_id, payment_method, transaction_id } = req.body;

  if (!isUUID(id) || !isUUID(String(student_id)) || !isUUID(String(event_id)))
    return res.status(400).json({ error: 'Invalid IDs.' });
  if (!name || !phone || !email || !payment_method)
    return res.status(400).json({ error: 'Missing fields.' });
  if (!isPhone(phone))  return res.status(400).json({ error: 'Phone must be 10 digits.' });
  if (!isEmail(email))  return res.status(400).json({ error: 'Invalid email.' });
  if (!['cash','upi'].includes(payment_method)) return res.status(400).json({ error: 'Invalid payment method.' });
  if (payment_method === 'upi' && !transaction_id) return res.status(400).json({ error: 'UPI transaction ID required.' });

  // ownership: member can only edit own; admin can edit any
  const { data: check } = await db.from('Registrations').select('member_id').eq('id', id).single();
  if (!check) return res.status(404).json({ error: 'Registration not found.' });
  if (req.user.role !== 'admin' && check.member_id !== req.user.id)
    return res.status(403).json({ error: 'Not authorized.' });

  const { data: evData } = await db.from('Events').select('cost').eq('id', event_id).single();
  if (!evData) return res.status(400).json({ error: 'Event not found.' });

  const cleanName  = sanitize(name);
  const cleanEmail = sanitize(email).toLowerCase();
  const cleanTxn   = transaction_id ? sanitize(transaction_id) : null;

  await db.from('Students').update({ name: cleanName, phone_number: String(phone), email: cleanEmail }).eq('id', student_id);

  const { error: regErr } = await db.from('Registrations').update({
    event_id, payment_method,
    transaction_id: payment_method === 'upi' ? cleanTxn : null,
    amount_paid: evData.cost
  }).eq('id', id);

  if (regErr) return res.status(500).json({ error: regErr.message });
  res.json({ ok: true });
});

// DELETE /api/sales/:id
app.delete('/api/sales/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  if (!isUUID(id)) return res.status(400).json({ error: 'Invalid ID.' });

  const { data: check } = await db.from('Registrations').select('member_id').eq('id', id).single();
  if (!check) return res.status(404).json({ error: 'Not found.' });
  if (req.user.role !== 'admin' && check.member_id !== req.user.id)
    return res.status(403).json({ error: 'Not authorized.' });

  const { error } = await db.from('Registrations').delete().eq('id', id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// Serve SPA
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Accolade portal running on port ${PORT}`));