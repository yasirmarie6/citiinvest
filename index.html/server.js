const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cors = require('cors');
const fs = require('fs');
require('dotenv').config();
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'changeme_in_prod';

app.use(cors());
app.use('/api/stripe/webhook', express.raw({type: 'application/json'}));
app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

const db = new sqlite3.Database('./citi_invest.db');
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, phone TEXT, password TEXT, role TEXT DEFAULT 'customer',
    kyc_status TEXT DEFAULT 'pending', created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS loans (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, category TEXT, amount REAL,
    term_months INTEGER, has_guarantor BOOLEAN, upfront_fee REAL, upfront_paid BOOLEAN DEFAULT 0,
    stripe_session_id TEXT, status TEXT DEFAULT 'pending', kyc_docs TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS otps (
    id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, phone TEXT, code TEXT,
    type TEXT, expires_at DATETIME, used BOOLEAN DEFAULT 0
  )`);
});

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = './uploads/kyc';
    fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage });

const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({error: 'No token'});
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({error: 'Invalid token'}); }
};

const adminOnly = (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({error: 'Admin only'});
  next();
};

const sendOTP = async (type, dest, code) => {
  console.log(`[DEV] OTP for ${dest}: ${code}`);
  return true;
};

app.post('/api/register', async (req, res) => {
  const { email, phone, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  db.run('INSERT INTO users (email, phone, password) VALUES (?,?,?)', 
    [email, phone, hash], function(err) {
      if (err) return res.status(400).json({error: 'Email exists'});
      res.json({id: this.lastID});
    });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (!user || !await bcrypt.compare(password, user.password)) 
      return res.status(401).json({error: 'Invalid creds'});
    const token = jwt.sign({id: user.id, role: user.role}, JWT_SECRET);
    res.json({token, role: user.role, email: user.email});
  });
});

app.post('/api/otp/request', (req, res) => {
  const { email, phone, type } = req.body;
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const expires = new Date(Date.now() + 10*60000);
  db.run('INSERT INTO otps (email, phone, code, type, expires_at) VALUES (?,?,?,?,?)',
    [email, phone, code, type, expires], () => {
      sendOTP(type, email || phone, code);
      res.json({success: true});
    });
});

app.post('/api/otp/verify', (req, res) => {
  const { email, phone, code } = req.body;
  db.get('SELECT * FROM otps WHERE (email=? OR phone=?) AND code=? AND used=0 AND expires_at > datetime("now")',
    [email, phone, code], (err, otp) => {
      if (!otp) return res.status(400).json({error: 'Invalid OTP'});
      db.run('UPDATE otps SET used=1 WHERE id=?', [otp.id]);
      res.json({verified: true});
    });
});

app.post('/api/loan/apply', auth, upload.array('kyc_docs', 5), (req, res) => {
  const { category, amount, term_months, has_guarantor } = req.body;
  const upfront_fee = has_guarantor === 'false' ? parseFloat(amount) * 0.035 : 0;
  const docs = req.files.map(f => f.path).join(',');
  db.run(`INSERT INTO loans (user_id, category, amount, term_months, has_guarantor, upfront_fee, kyc_docs) 
          VALUES (?,?,?,?,?,?,?)`,
    [req.user.id, category, amount, term_months, has_guarantor === 'true', upfront_fee, docs],
    function(err) {
      if (err) return res.status(500).json({error: err.message});
      res.json({loan_id: this.lastID, upfront_fee, needs_payment: upfront_fee > 0});
    });
});

app.post('/api/stripe/create-checkout', auth, async (req, res) => {
  const { loan_id } = req.body;
  db.get('SELECT * FROM loans WHERE id=? AND user_id=?', [loan_id, req.user.id], async (err, loan) => {
    if (!loan || loan.upfront_fee <= 0) return res.status(400).json({error: 'No fee required'});
    try {
      const session = await stripe.checkout.sessions.create({
        payment_method_types: ['card'],
        line_items: [{
          price_data: {
            currency: 'aud',
            product_data: { name: `Citi Invest Upfront Fee - ${loan.category} Loan` },
            unit_amount: Math.round(loan.upfront_fee * 100),
          },
          quantity: 1,
        }],
        mode: 'payment',
        success_url: `${process.env.FRONTEND_URL}/success?loan_id=${loan_id}`,
        cancel_url: `${process.env.FRONTEND_URL}/cancel`,
        metadata: { loan_id: loan_id.toString() }
      });
      db.run('UPDATE loans SET stripe_session_id=? WHERE id=?', [session.id, loan_id]);
      res.json({url: session.url});
    } catch(e) { res.status(500).json({error: e.message}); }
  });
});

app.post('/api/stripe/webhook', (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) { return res.status(400).send(`Webhook Error: ${err.message}`); }
  
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const loan_id = session.metadata.loan_id;
    db.run('UPDATE loans SET upfront_paid=1, status="payment_received" WHERE id=?', [loan_id]);
  }
  res.json({received: true});
});

app.get('/api/admin/users', auth, adminOnly, (req, res) => {
  db.all('SELECT id, email, phone, role, kyc_status, created_at FROM users', (err, rows) => res.json(rows));
});

app.get('/api/admin/loans', auth, adminOnly, (req, res) => {
  db.all(`SELECT loans.*, users.email FROM loans JOIN users ON loans.user_id = users.id ORDER BY loans.created_at DESC`, 
    (err, rows) => res.json(rows));
});

app.post('/api/admin/user/create', auth, adminOnly, async (req, res) => {
  const { email, phone, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  db.run('INSERT INTO users (email, phone, password) VALUES (?,?,?)',
    [email, phone, hash], function(err) {
      if (err) return res.status(400).json({error: err.message});
      res.json({id: this.lastID});
    });
});

app.put('/api/admin/loan/:id/status', auth, adminOnly, (req, res) => {
  const { status } = req.body;
  db.run('UPDATE loans SET status=? WHERE id=?', [status, req.params.id], (err) => {
    if (err) return res.status(500).json({error: err.message});
    res.json({success: true});
  });
});

const createAdmin = async () => {
  const hash = await bcrypt.hash('admin123', 10);
  db.run('INSERT OR IGNORE INTO users (email, password, role) VALUES (?,?,?)',
    ['admin@citiinvest.com', hash, 'admin']);
};
createAdmin();

app.listen(PORT, () => console.log(`Citi Invest API running on ${PORT}`));
