// server.js
require('dotenv').config();

const path = require('path');
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const helmet = require('helmet');

const { router: authRouter, requireAuth } = require('./routes/auth');

const app = express();
const PORT = process.env.PORT || 3000;
const isProd = process.env.NODE_ENV === 'production';

if (!process.env.SESSION_SECRET) {
  console.error('FATAL: SESSION_SECRET is not set. Copy .env.example to .env and set a random secret.');
  process.exit(1);
}

// Trust the first proxy hop if deployed behind one (needed for secure cookies).
app.set('trust proxy', 1);

// -----------------------------------------------------------------------
// Security headers
// -----------------------------------------------------------------------
app.use(helmet());

// -----------------------------------------------------------------------
// Body parsing
// -----------------------------------------------------------------------
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// -----------------------------------------------------------------------
// View engine
// -----------------------------------------------------------------------
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// -----------------------------------------------------------------------
// Static files
// -----------------------------------------------------------------------
app.use('/static', express.static(path.join(__dirname, 'public')));

// -----------------------------------------------------------------------
// Sessions -- stored server-side in SQLite (not just a signed cookie),
// so session data can be revoked and doesn't bloat the cookie.
// -----------------------------------------------------------------------
app.use(
  session({
    store: new SQLiteStore({ db: 'sessions.db', dir: path.join(__dirname, 'db') }),
    name: 'sid',
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: isProd, // requires HTTPS in production
      sameSite: 'lax',
      maxAge: 1000 * 60 * 60 * 2, // 2 hours
    },
  })
);

// -----------------------------------------------------------------------
// Routes
// -----------------------------------------------------------------------
app.get('/', (req, res) => res.redirect(req.session.userId ? '/dashboard' : '/login'));
app.use('/', authRouter);

// 404
app.use((req, res) => res.status(404).render('404'));

// Generic error handler -- never leak stack traces to the client.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).send('Something went wrong.');
});

app.listen(PORT, () => {
  console.log(`Secure login app running at http://localhost:${PORT}`);
});
