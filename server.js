const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const path    = require('path');
const crypto  = require('crypto');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;
if (!SUPABASE_URL || !SUPABASE_KEY) { console.error('Missing env vars.'); process.exit(1); }

const db = createClient(SUPABASE_URL, SUPABASE_KEY);

// ── Sessions ──────────────────────────────────────────────────────
const sessions = new Map();
function makeToken() { return crypto.randomBytes(32).toString('hex'); }
function sha256(str) { return crypto.createHash('sha256').update(str).digest('hex'); }

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

// ── Validators ────────────────────────────────────────────────────
function isUUID(v)  { return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(v)); }
function isPhone(v) { return /^\d{10}$/.test(String(v)); }
function isEmail(v) { return typeof v === 'string' && v.includes('@') && v.length <= 254; }
function sanitize(v){ return String(v).trim().replace(/[<>"'`]/g, '').slice(0, 500); }

// ════════════════════════════════════════════════════════
//  AUTH
// ════════════════════════════════════════════════════════

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Missing fields.' });
  if (!isEmail(email))     return res.status(400).json({ error: 'Invalid email.' });

  const { data, error } = await db
    .from('Members')
    .select('id, name, email, role')
    .eq('email', email.toLowerCase().trim())
    .eq('password', sha256(String(password)))
    .single();

  if (error || !data) return res.status(401).json({ error: 'Invalid email or password.' });

  const token = makeToken();
  sessions.set(token, { id: data.id, name: data.name, email: data.email, role: data.role });
  setTimeout(() => sessions.delete(token), 12 * 60 * 60 * 1000);
  res.json({ token, name: data.name, role: data.role });
});

app.post('/api/logout', requireAuth, (req, res) => {
  sessions.delete(req.headers['x-session']);
  res.json({ ok: true });
});

// ════════════════════════════════════════════════════════
//  STUDENT LOOKUP — by student_id (college roll number etc.)
//  phone & email still must be unique, checked separately
// ════════════════════════════════════════════════════════

app.post('/api/students/lookup', requireAuth, async (req, res) => {
  const studentId = sanitize(req.body.student_id || '').toUpperCase();
  if (!studentId) return res.status(400).json({ error: 'Enter a Student ID.' });

  // Primary lookup: by student_id
  const { data: byId } = await db
    .from('Students')
    .select('id, name, student_id, phone_number, email')
    .eq('student_id', studentId)
    .maybeSingle();

  if (byId) {
    // Fetch which events this student is CURRENTLY registered for (not deleted)
    const { data: regs } = await db
      .from('Registrations')
      .select('event_id')
      .eq('student_id', byId.id);
    const registeredEventIds = (regs || []).map(r => r.event_id);
    return res.json({ status: 'found', student: byId, registeredEventIds });
  }

  // Not found — new student, all events available
  return res.json({ status: 'new', registeredEventIds: [] });
});

// Check if a phone or email is already used by another student (for new student flow)
app.post('/api/students/check-unique', requireAuth, async (req, res) => {
  const { field, value } = req.body;
  if (!field || !value) return res.status(400).json({ error: 'Missing field or value.' });
  if (field === 'phone') {
    if (!isPhone(value)) return res.status(400).json({ error: 'Invalid phone.' });
    const { data } = await db.from('Students').select('student_id').eq('phone_number', value).maybeSingle();
    return res.json({ unique: !data, student_id: data?.student_id || null });
  }
  if (field === 'email') {
    if (!isEmail(value)) return res.status(400).json({ error: 'Invalid email.' });
    const { data } = await db.from('Students').select('student_id').eq('email', value.toLowerCase()).maybeSingle();
    return res.json({ unique: !data, student_id: data?.student_id || null });
  }
  return res.status(400).json({ error: 'field must be phone or email.' });
});

// ════════════════════════════════════════════════════════
//  EVENTS
// ════════════════════════════════════════════════════════

app.get('/api/events', requireAuth, async (req, res) => {
  const { data, error } = await db.from('Events').select('id, title, cost, created_at').order('title');
  if (error) return res.status(500).json({ error: 'Failed to load events.' });
  res.json(data);
});

app.post('/api/events', requireAuth, requireAdmin, async (req, res) => {
  const title = sanitize(req.body.title || '');
  const cost  = parseFloat(req.body.cost);
  if (!title)              return res.status(400).json({ error: 'Title is required.' });
  if (isNaN(cost)||cost<=0) return res.status(400).json({ error: 'Cost must be > 0.' });
  const { error } = await db.from('Events').insert({ title, cost });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

app.put('/api/events/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  if (!isUUID(id)) return res.status(400).json({ error: 'Invalid event ID.' });
  const cost = parseFloat(req.body.cost);
  if (isNaN(cost)||cost<=0) return res.status(400).json({ error: 'Cost must be > 0.' });
  const { error } = await db.from('Events').update({ cost }).eq('id', id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

app.delete('/api/events/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  if (!isUUID(id)) return res.status(400).json({ error: 'Invalid ID.' });
  const { error } = await db.from('Events').delete().eq('id', id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// ════════════════════════════════════════════════════════
//  MEMBERS (admin only)
// ════════════════════════════════════════════════════════

app.get('/api/members', requireAuth, requireAdmin, async (req, res) => {
  const { data, error } = await db
    .from('Members').select('id, name, email, phone_number, role, created_at')
    .order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: 'Failed to load members.' });
  res.json(data);
});

app.post('/api/members', requireAuth, requireAdmin, async (req, res) => {
  const name    = sanitize(req.body.name || '');
  const email   = sanitize(req.body.email || '').toLowerCase();
  const pw      = String(req.body.password || '');
  const role    = req.body.role === 'admin' ? 'admin' : 'member';
  const phone_m = String(req.body.phone || '').trim();
  if (!name)           return res.status(400).json({ error: 'Name is required.' });
  if (!isEmail(email)) return res.status(400).json({ error: 'Invalid email.' });
  if (pw.length < 8)   return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  if (phone_m && !isPhone(phone_m)) return res.status(400).json({ error: 'Member phone must be 10 digits.' });
  // Check phone uniqueness manually before insert (gives clear message)
  if (phone_m) {
    const { data: ph_taken } = await db.from('Members').select('id').eq('phone_number', phone_m).maybeSingle();
    if (ph_taken) return res.status(400).json({ error: 'Phone number already used by another member.' });
  }
  const { error } = await db.from('Members').insert({ name, email, password: sha256(pw), role, phone_number: phone_m || null });
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
  if (typeof req.body.phone !== 'undefined') {
    const ph = String(req.body.phone).trim();
    if (ph && !isPhone(ph)) return res.status(400).json({ error: 'Phone must be 10 digits.' });
    if (ph) {
      const { data: ph_taken } = await db.from('Members').select('id').eq('phone_number', ph).neq('id', id).maybeSingle();
      if (ph_taken) return res.status(400).json({ error: 'Phone number already used by another member.' });
    }
    updates.phone_number = ph || null;
  }
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

// ════════════════════════════════════════════════════════
//  STUDENTS (admin only)
// ════════════════════════════════════════════════════════

app.get('/api/students', requireAuth, requireAdmin, async (req, res) => {
  const { data, error } = await db
    .from('Students').select('id, student_id, name, phone_number, email, created_at')
    .order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: 'Failed to load students.' });
  res.json(data);
});

app.put('/api/students/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  if (!isUUID(id)) return res.status(400).json({ error: 'Invalid ID.' });
  const name       = sanitize(req.body.name  || '');
  const phone      = String(req.body.phone   || '').trim();
  const email      = sanitize(req.body.email || '').toLowerCase();
  const student_id = sanitize(req.body.student_id || '').toUpperCase();
  if (!name)           return res.status(400).json({ error: 'Name is required.' });
  if (!isPhone(phone)) return res.status(400).json({ error: 'Phone must be 10 digits.' });
  if (!isEmail(email)) return res.status(400).json({ error: 'Invalid email.' });
  if (!student_id)     return res.status(400).json({ error: 'Student ID is required.' });
  const { error } = await db.from('Students')
    .update({ name, phone_number: phone, email, student_id }).eq('id', id);
  if (error) {
    if (error.code === '23505') return res.status(400).json({ error: 'Phone, email, or Student ID already used by another student.' });
    return res.status(500).json({ error: error.message });
  }
  res.json({ ok: true });
});

app.delete('/api/students/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  if (!isUUID(id)) return res.status(400).json({ error: 'Invalid ID.' });
  const { error } = await db.from('Students').delete().eq('id', id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// ════════════════════════════════════════════════════════
//  REGISTRATIONS
// ════════════════════════════════════════════════════════

app.get('/api/sales', requireAuth, async (req, res) => {
  let query = db.from('Registrations')
    .select(`id, payment_method, transaction_id, amount_paid, registered_at,
      Students ( id, student_id, name, phone_number, email ),
      Events   ( id, title, cost ),
      Members  ( id, name, phone_number )`)
    .order('registered_at', { ascending: false });
  if (req.user.role !== 'admin') query = query.eq('member_id', req.user.id);
  const { data, error } = await query;
  if (error) return res.status(500).json({ error: 'Failed to load sales.' });
  res.json(data);
});

// POST /api/register — supports multiple events in one call
app.post('/api/register', requireAuth, async (req, res) => {
  const { student_id, name, phone, email, event_ids, payment_method, transaction_id } = req.body;

  if (!student_id || !name || !phone || !email || !event_ids?.length || !payment_method)
    return res.status(400).json({ error: 'Missing required fields.' });
  if (!isPhone(phone))  return res.status(400).json({ error: 'Phone must be 10 digits.' });
  if (!isEmail(email))  return res.status(400).json({ error: 'Invalid email.' });
  if (!Array.isArray(event_ids) || event_ids.some(id => !isUUID(id)))
    return res.status(400).json({ error: 'Invalid event selection.' });
  if (!['cash','upi'].includes(payment_method)) return res.status(400).json({ error: 'Invalid payment method.' });
  if (payment_method === 'upi' && !transaction_id) return res.status(400).json({ error: 'UPI transaction ID required.' });

  const cleanName     = sanitize(name);
  const cleanEmail    = sanitize(email).toLowerCase();
  const cleanStudId   = sanitize(student_id).toUpperCase();
  const cleanTxn      = transaction_id ? sanitize(transaction_id) : null;

  // Get all event costs
  const { data: eventsData, error: evErr } = await db
    .from('Events').select('id, cost').in('id', event_ids);
  if (evErr || !eventsData?.length) return res.status(400).json({ error: 'One or more events not found.' });

  // Upsert student by student_id
  let studentDbId;
  const { data: existing } = await db.from('Students')
    .select('id').eq('student_id', cleanStudId).maybeSingle();

  if (existing) {
    studentDbId = existing.id;
    await db.from('Students')
      .update({ name: cleanName, email: cleanEmail, phone_number: String(phone) })
      .eq('id', studentDbId);
  } else {
    const { data: newStu, error: stuErr } = await db.from('Students')
      .insert({ student_id: cleanStudId, name: cleanName, email: cleanEmail, phone_number: String(phone) })
      .select().single();
    if (stuErr) {
      if (stuErr.code === '23505') return res.status(400).json({ error: 'Phone or email already used by another student.' });
      return res.status(500).json({ error: 'Failed to save student.' });
    }
    studentDbId = newStu.id;
  }

  // Check which of the requested events the student is ALREADY registered for
  const { data: existingRegs } = await db
    .from('Registrations')
    .select('event_id')
    .eq('student_id', studentDbId)
    .in('event_id', event_ids);

  const alreadyRegistered = new Set((existingRegs || []).map(r => r.event_id));
  const newEventIds = event_ids.filter(eid => !alreadyRegistered.has(eid));

  if (newEventIds.length === 0) {
    return res.status(400).json({ error: 'Student is already registered for all selected events.' });
  }

  // Insert only for events not already registered
  const eventMap = Object.fromEntries(eventsData.map(e => [e.id, e.cost]));
  const registrations = newEventIds.map(eid => ({
    student_id:     studentDbId,
    event_id:       eid,
    member_id:      req.user.id,
    payment_method,
    transaction_id: payment_method === 'upi' ? cleanTxn : null,
    amount_paid:    eventMap[eid]
  }));

  const { error: regErr } = await db.from('Registrations').insert(registrations);
  if (regErr) {
    return res.status(500).json({ error: 'Failed to create registration: ' + regErr.message });
  }
  const skipped = alreadyRegistered.size;
  res.json({ ok: true, count: registrations.length, skipped });
});

app.put('/api/sales/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { student_id, name, phone, email, event_id, payment_method, transaction_id } = req.body;
  if (!isUUID(id)||!isUUID(String(student_id))||!isUUID(String(event_id)))
    return res.status(400).json({ error: 'Invalid IDs.' });
  if (!name||!phone||!email||!payment_method) return res.status(400).json({ error: 'Missing fields.' });
  if (!isPhone(phone)) return res.status(400).json({ error: 'Phone must be 10 digits.' });
  if (!isEmail(email)) return res.status(400).json({ error: 'Invalid email.' });
  if (!['cash','upi'].includes(payment_method)) return res.status(400).json({ error: 'Invalid payment method.' });
  if (payment_method==='upi' && !transaction_id) return res.status(400).json({ error: 'UPI transaction ID required.' });

  const { data: check } = await db.from('Registrations').select('member_id').eq('id', id).single();
  if (!check) return res.status(404).json({ error: 'Not found.' });
  if (req.user.role !== 'admin' && check.member_id !== req.user.id)
    return res.status(403).json({ error: 'Not authorized.' });

  const { data: evData } = await db.from('Events').select('cost').eq('id', event_id).single();
  if (!evData) return res.status(400).json({ error: 'Event not found.' });

  await db.from('Students').update({
    name: sanitize(name), phone_number: String(phone), email: sanitize(email).toLowerCase()
  }).eq('id', student_id);

  const { error } = await db.from('Registrations').update({
    event_id, payment_method,
    transaction_id: payment_method==='upi' ? sanitize(transaction_id) : null,
    amount_paid: evData.cost
  }).eq('id', id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

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

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Accolade portal running on port ${PORT}`));