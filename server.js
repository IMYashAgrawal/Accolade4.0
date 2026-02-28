const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error('ERROR: SUPABASE_URL and SUPABASE_KEY environment variables are not set.');
  process.exit(1);
}

const db = createClient(SUPABASE_URL, SUPABASE_KEY);

// ── Sessions ────────────────────────────────────────────────────
const sessions = new Map();

function makeToken() { return crypto.randomBytes(32).toString('hex'); }

function requireAuth(req, res, next) {
  const token = req.headers['x-session'];
  if (!token || !sessions.has(token)) return res.status(401).json({ error: 'Not logged in.' });
  req.sp = sessions.get(token);
  next();
}

function sha256(str) { return crypto.createHash('sha256').update(str).digest('hex'); }

// ── Input validators ─────────────────────────────────────────────
function isUUID(v)  { return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v); }
function isPhone(v) { return /^\d{10}$/.test(v); }
function isEmail(v) { return typeof v === 'string' && v.includes('@') && v.length <= 254; }
// Strip all HTML-dangerous characters from free-text fields
function sanitize(v) { return String(v).trim().replace(/[<>"'`]/g, '').slice(0, 500); }

// ══════════════════════════════════════════════════════
//  AUTH
// ══════════════════════════════════════════════════════

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Missing fields.' });
  if (!isEmail(email))     return res.status(400).json({ error: 'Invalid email.' });

  const hashed = sha256(String(password));

  const { data, error } = await db
    .from('Members')
    .select('id, name, email')
    .eq('email', email.toLowerCase().trim())
    .eq('password', hashed)
    .single();

  if (error || !data) return res.status(401).json({ error: 'Invalid email or password.' });

  const token = makeToken();
  sessions.set(token, { id: data.id, name: data.name, email: data.email });
  setTimeout(() => sessions.delete(token), 12 * 60 * 60 * 1000);

  res.json({ token, name: data.name });
});

app.post('/api/logout', requireAuth, (req, res) => {
  sessions.delete(req.headers['x-session']);
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════
//  EVENTS
// ══════════════════════════════════════════════════════

app.get('/api/events', requireAuth, async (req, res) => {
  const { data, error } = await db.from('Events').select('id, title, cost').order('title');
  if (error) return res.status(500).json({ error: 'Failed to load events.' });
  res.json(data);
});

// ══════════════════════════════════════════════════════
//  REGISTRATIONS
// ══════════════════════════════════════════════════════

app.get('/api/sales', requireAuth, async (req, res) => {
  const { data, error } = await db
    .from('Registrations')
    .select(`
      id, payment_method, transaction_id, amount_paid, registered_at,
      Students ( id, name, phone_number, email ),
      Events   ( id, title, cost )
    `)
    .eq('member_id', req.sp.id)
    .order('registered_at', { ascending: false });

  if (error) return res.status(500).json({ error: 'Failed to load sales.' });
  res.json(data);
});

app.post('/api/register', requireAuth, async (req, res) => {
  const { name, phone, email, event_id, payment_method, transaction_id } = req.body;

  // ── Strict server-side validation ──
  if (!name || !phone || !email || !event_id || !payment_method)
    return res.status(400).json({ error: 'Missing required fields.' });
  if (!isPhone(String(phone)))
    return res.status(400).json({ error: 'Phone must be exactly 10 digits.' });
  if (!isEmail(email))
    return res.status(400).json({ error: 'Invalid email address.' });
  if (!isUUID(String(event_id)))
    return res.status(400).json({ error: 'Invalid event.' });
  if (!['cash', 'upi'].includes(payment_method))          // whitelist only
    return res.status(400).json({ error: 'Invalid payment method.' });
  if (payment_method === 'upi' && !transaction_id)
    return res.status(400).json({ error: 'UPI transaction ID is required.' });

  // Sanitize free-text fields before storing
  const cleanName  = sanitize(name);
  const cleanEmail = sanitize(email).toLowerCase();
  const cleanTxn   = transaction_id ? sanitize(transaction_id) : null;

  // Get event cost (from DB — never trust client-sent amount)
  const { data: evData, error: evErr } = await db.from('Events').select('cost').eq('id', event_id).single();
  if (evErr || !evData) return res.status(400).json({ error: 'Event not found.' });

  // Upsert student
  let studentId;
  const { data: existing } = await db.from('Students').select('id').eq('phone_number', String(phone)).maybeSingle();
  if (existing) {
    studentId = existing.id;
    await db.from('Students').update({ name: cleanName, email: cleanEmail }).eq('id', studentId);
  } else {
    const { data: newStu, error: stuErr } = await db
      .from('Students').insert({ name: cleanName, email: cleanEmail, phone_number: String(phone) }).select().single();
    if (stuErr) {
      if (stuErr.code === '23505') return res.status(400).json({ error: 'This email is already used by another student.' });
      return res.status(500).json({ error: 'Failed to save student.' });
    }
    studentId = newStu.id;
  }

  // Insert registration
  const { error: regErr } = await db.from('Registrations').insert({
    student_id:      studentId,
    event_id:        event_id,
    member_id: req.sp.id,
    payment_method,
    transaction_id:  payment_method === 'upi' ? cleanTxn : null,
    amount_paid:     evData.cost          // always from DB, never from client
  });

  if (regErr) {
    if (regErr.code === '23505') return res.status(400).json({ error: 'This student is already registered for this event.' });
    return res.status(500).json({ error: 'Failed to create registration.' });
  }

  res.json({ ok: true });
});

app.put('/api/sales/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { student_id, name, phone, email, event_id, payment_method, transaction_id } = req.body;

  // ── Strict validation ──
  if (!name || !phone || !email || !event_id || !payment_method)
    return res.status(400).json({ error: 'Missing required fields.' });
  if (!isUUID(String(id)))
    return res.status(400).json({ error: 'Invalid registration ID.' });
  if (!isUUID(String(student_id)))
    return res.status(400).json({ error: 'Invalid student ID.' });
  if (!isPhone(String(phone)))
    return res.status(400).json({ error: 'Phone must be exactly 10 digits.' });
  if (!isEmail(email))
    return res.status(400).json({ error: 'Invalid email address.' });
  if (!isUUID(String(event_id)))
    return res.status(400).json({ error: 'Invalid event.' });
  if (!['cash', 'upi'].includes(payment_method))
    return res.status(400).json({ error: 'Invalid payment method.' });
  if (payment_method === 'upi' && !transaction_id)
    return res.status(400).json({ error: 'UPI transaction ID is required.' });

  // Ownership check — member can only edit their own registrations
  const { data: check } = await db.from('Registrations').select('member_id').eq('id', id).single();
  if (!check || check.member_id !== req.sp.id) return res.status(403).json({ error: 'Not authorized.' });

  const cleanName  = sanitize(name);
  const cleanEmail = sanitize(email).toLowerCase();
  const cleanTxn   = transaction_id ? sanitize(transaction_id) : null;

  const { data: evData } = await db.from('Events').select('cost').eq('id', event_id).single();
  if (!evData) return res.status(400).json({ error: 'Event not found.' });

  const { error: stuErr } = await db.from('Students')
    .update({ name: cleanName, phone_number: String(phone), email: cleanEmail }).eq('id', student_id);
  if (stuErr) return res.status(500).json({ error: 'Failed to update student.' });

  const { error: regErr } = await db.from('Registrations').update({
    event_id,
    payment_method,
    transaction_id: payment_method === 'upi' ? cleanTxn : null,
    amount_paid:    evData.cost
  }).eq('id', id);

  if (regErr) return res.status(500).json({ error: 'Failed to update registration.' });
  res.json({ ok: true });
});

app.delete('/api/sales/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  if (!isUUID(String(id))) return res.status(400).json({ error: 'Invalid ID.' });

  const { data: check } = await db.from('Registrations').select('member_id').eq('id', id).single();
  if (!check || check.member_id !== req.sp.id) return res.status(403).json({ error: 'Not authorized.' });

  const { error } = await db.from('Registrations').delete().eq('id', id);
  if (error) return res.status(500).json({ error: 'Failed to delete.' });
  res.json({ ok: true });
});

// Serve frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Sales portal running on port ${PORT}`));
