// routes/auth.js
const express = require('express');
const bcrypt = require('bcrypt');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');

const db = require('../db');

const router = express.Router();
const BCRYPT_ROUNDS = 12;
const MAX_FAILED_ATTEMPTS = 5;
const LOCK_TIME_MS = 15 * 60 * 1000; // 15 minutes

// ---------------------------------------------------------------------------
// Rate limiting: slows down brute-force / credential-stuffing attempts.
// ---------------------------------------------------------------------------
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: 'Too many login attempts from this IP. Please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: 'Too many accounts created from this IP. Please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

// ---------------------------------------------------------------------------
// Validation chains
// ---------------------------------------------------------------------------
const registerValidation = [
  body('email')
    .trim()
    .isEmail().withMessage('Please provide a valid email address.')
    .normalizeEmail(),
  body('password')
    .isLength({ min: 10 }).withMessage('Password must be at least 10 characters long.')
    .matches(/[a-z]/).withMessage('Password must contain a lowercase letter.')
    .matches(/[A-Z]/).withMessage('Password must contain an uppercase letter.')
    .matches(/[0-9]/).withMessage('Password must contain a number.'),
  body('confirmPassword').custom((value, { req }) => {
    if (value !== req.body.password) {
      throw new Error('Passwords do not match.');
    }
    return true;
  }),
];

const loginValidation = [
  body('email').trim().isEmail().withMessage('Please provide a valid email address.').normalizeEmail(),
  body('password').notEmpty().withMessage('Password is required.'),
];

// Helper to require an authenticated session
function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  next();
}

// ---------------------------------------------------------------------------
// GET /register
// ---------------------------------------------------------------------------
router.get('/register', (req, res) => {
  if (req.session.userId) return res.redirect('/dashboard');
  res.render('register', { errors: [], oldEmail: '' });
});

// ---------------------------------------------------------------------------
// POST /register
// ---------------------------------------------------------------------------
router.post('/register', registerLimiter, registerValidation, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).render('register', {
      errors: errors.array().map((e) => e.msg),
      oldEmail: req.body.email || '',
    });
  }

  const { email, password } = req.body;

  try {
    // Parameterized query -- the email value is bound, never concatenated,
    // so this is not vulnerable to SQL injection.
    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (existing) {
      return res.status(400).render('register', {
        errors: ['An account with that email already exists.'],
        oldEmail: email,
      });
    }

    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

    db.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)').run(email, passwordHash);

    res.redirect('/login?registered=1');
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).render('register', { errors: ['Something went wrong. Please try again.'], oldEmail: email });
  }
});

// ---------------------------------------------------------------------------
// GET /login
// ---------------------------------------------------------------------------
router.get('/login', (req, res) => {
  if (req.session.userId) return res.redirect('/dashboard');
  res.render('login', { errors: [], registered: req.query.registered === '1' });
});

// ---------------------------------------------------------------------------
// POST /login
// ---------------------------------------------------------------------------
router.post('/login', loginLimiter, loginValidation, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).render('login', { errors: errors.array().map((e) => e.msg), registered: false });
  }

  const { email, password } = req.body;
  const genericError = 'Invalid email or password.';

  try {
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

    // Always compare against a dummy hash if no user is found so that the
    // response time doesn't reveal whether the account exists (timing
    // side-channel mitigation).
    const dummyHash = '$2b$12$CwTycUXWue0Thq9StjUM0uJ8h6/qKJ6qXe3qzq9yYQfKp1Rz1H0S6';
    const hashToCheck = user ? user.password_hash : dummyHash;

    if (user && user.locked_until && user.locked_until > Date.now()) {
      const minutesLeft = Math.ceil((user.locked_until - Date.now()) / 60000);
      return res.status(423).render('login', {
        errors: [`Account temporarily locked. Try again in ${minutesLeft} minute(s).`],
        registered: false,
      });
    }

    const passwordMatches = await bcrypt.compare(password, hashToCheck);

    if (!user || !passwordMatches) {
      if (user) {
        const attempts = user.failed_attempts + 1;
        const lockedUntil = attempts >= MAX_FAILED_ATTEMPTS ? Date.now() + LOCK_TIME_MS : null;
        db.prepare('UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?')
          .run(attempts, lockedUntil, user.id);
      }
      return res.status(401).render('login', { errors: [genericError], registered: false });
    }

    // Successful password check -- reset failed attempt counter.
    db.prepare('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?').run(user.id);

    if (user.totp_enabled) {
      // Password correct but 2FA still required -- store a pending state,
      // not a full login, until the TOTP code is verified.
      req.session.pending2FAUserId = user.id;
      return res.redirect('/login/2fa');
    }

    req.session.regenerate((err) => {
      if (err) {
        console.error(err);
        return res.status(500).render('login', { errors: ['Something went wrong.'], registered: false });
      }
      req.session.userId = user.id;
      req.session.email = user.email;
      res.redirect('/dashboard');
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).render('login', { errors: ['Something went wrong. Please try again.'], registered: false });
  }
});

// ---------------------------------------------------------------------------
// GET /login/2fa  -- prompt for TOTP code after password success
// ---------------------------------------------------------------------------
router.get('/login/2fa', (req, res) => {
  if (!req.session.pending2FAUserId) return res.redirect('/login');
  res.render('login-2fa', { errors: [] });
});

router.post(
  '/login/2fa',
  loginLimiter,
  body('token').trim().isLength({ min: 6, max: 6 }).isNumeric().withMessage('Enter the 6-digit code.'),
  (req, res) => {
    const pendingId = req.session.pending2FAUserId;
    if (!pendingId) return res.redirect('/login');

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).render('login-2fa', { errors: errors.array().map((e) => e.msg) });
    }

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(pendingId);
    if (!user) return res.redirect('/login');

    const verified = speakeasy.totp.verify({
      secret: user.totp_secret,
      encoding: 'base32',
      token: req.body.token,
      window: 1, // allow 1 step of clock drift (~30s)
    });

    if (!verified) {
      return res.status(401).render('login-2fa', { errors: ['Invalid authentication code.'] });
    }

    delete req.session.pending2FAUserId;
    req.session.regenerate((err) => {
      if (err) {
        console.error(err);
        return res.status(500).render('login-2fa', { errors: ['Something went wrong.'] });
      }
      req.session.userId = user.id;
      req.session.email = user.email;
      res.redirect('/dashboard');
    });
  }
);

// ---------------------------------------------------------------------------
// Dashboard (protected)
// ---------------------------------------------------------------------------
router.get('/dashboard', requireAuth, (req, res) => {
  const user = db.prepare('SELECT email, totp_enabled FROM users WHERE id = ?').get(req.session.userId);
  res.render('dashboard', { email: user.email, totpEnabled: !!user.totp_enabled });
});

// ---------------------------------------------------------------------------
// 2FA setup (protected)
// ---------------------------------------------------------------------------
router.get('/2fa/setup', requireAuth, async (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);

  if (user.totp_enabled) return res.redirect('/dashboard');

  const secret = speakeasy.generateSecret({ name: `SecureLoginApp (${user.email})` });
  db.prepare('UPDATE users SET totp_secret = ? WHERE id = ?').run(secret.base32, user.id);

  const qrDataUrl = await QRCode.toDataURL(secret.otpauth_url);
  res.render('2fa-setup', { qrDataUrl, secret: secret.base32, errors: [] });
});

router.post(
  '/2fa/setup',
  requireAuth,
  body('token').trim().isLength({ min: 6, max: 6 }).isNumeric().withMessage('Enter the 6-digit code.'),
  async (req, res) => {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const qrDataUrl = await QRCode.toDataURL(
        speakeasy.otpauthURL({ secret: user.totp_secret, label: user.email, encoding: 'base32' })
      );
      return res.status(400).render('2fa-setup', {
        errors: errors.array().map((e) => e.msg),
        qrDataUrl,
        secret: user.totp_secret,
      });
    }

    const verified = speakeasy.totp.verify({
      secret: user.totp_secret,
      encoding: 'base32',
      token: req.body.token,
      window: 1,
    });

    if (!verified) {
      const qrDataUrl = await QRCode.toDataURL(
        speakeasy.otpauthURL({ secret: user.totp_secret, label: user.email, encoding: 'base32' })
      );
      return res.status(400).render('2fa-setup', {
        errors: ['Invalid code. Please try again.'],
        qrDataUrl,
        secret: user.totp_secret,
      });
    }

    db.prepare('UPDATE users SET totp_enabled = 1 WHERE id = ?').run(user.id);
    res.redirect('/dashboard');
  }
);

router.post('/2fa/disable', requireAuth, (req, res) => {
  db.prepare('UPDATE users SET totp_enabled = 0, totp_secret = NULL WHERE id = ?').run(req.session.userId);
  res.redirect('/dashboard');
});

// ---------------------------------------------------------------------------
// Logout
// ---------------------------------------------------------------------------
router.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) console.error('Logout error:', err);
    res.clearCookie('connect.sid');
    res.redirect('/login');
  });
});

module.exports = { router, requireAuth };
