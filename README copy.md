# Secure Login System

A Node.js/Express web app implementing secure user registration, login, session
management, and optional TOTP-based two-factor authentication (2FA).

## Security features

- **Password hashing**: bcrypt with 12 salt rounds. Passwords are never stored or logged in plaintext.
- **SQL injection protection**: all database queries use `better-sqlite3` **parameterized statements** (`?` placeholders) — user input is never concatenated into SQL strings.
- **Input validation**: `express-validator` checks email format and enforces a strong password policy (10+ chars, upper/lowercase, number) on the server side.
- **Session management**: server-side sessions stored in SQLite (`connect-sqlite3`), `httpOnly` + `sameSite=lax` cookies, `secure` cookies auto-enabled in production, sessions regenerated on login to prevent session fixation, and a logout route that fully destroys the session.
- **Brute-force protection**: per-IP rate limiting on login/register, plus per-account lockout after 5 failed attempts (15 min lockout).
- **Timing-attack mitigation**: a dummy bcrypt hash is compared even when the email doesn't exist, so response time doesn't reveal valid accounts.
- **Generic error messages**: login failures always say "Invalid email or password" rather than revealing which field was wrong.
- **Security headers**: `helmet` sets sensible defaults (CSP, HSTS, etc.).
- **Optional 2FA**: TOTP (Google Authenticator / Authy compatible) via `speakeasy`, with QR-code enrollment. When enabled, a correct password alone is not enough to log in — a valid 6-digit code is also required.

## Project structure

```
secure-login-app/
├── server.js              # App entry point, middleware, session config
├── routes/auth.js         # Register / login / logout / 2FA routes
├── db/index.js            # SQLite connection + schema
├── views/                 # EJS templates
├── public/css/style.css   # Styling
├── .env.example           # Copy to .env and fill in
└── package.json
```

## Setup

1. Install dependencies:
   ```bash
   npm install
   ```

2. Create your environment file:
   ```bash
   cp .env.example .env
   ```
   Then open `.env` and set `SESSION_SECRET` to a random string, e.g.:
   ```bash
   node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
   ```

3. Start the app:
   ```bash
   npm start
   ```
   or, for auto-reload during development:
   ```bash
   npm run dev
   ```

4. Visit **http://localhost:3000** — you'll be redirected to `/login`.

The SQLite database file is created automatically at `db/app.db` on first run — no separate setup needed.

## Using 2FA

1. Register and log in.
2. On the dashboard, click **Enable 2FA**.
3. Scan the QR code with an authenticator app (Google Authenticator, Authy, 1Password, etc.), or type in the manual code shown.
4. Enter the 6-digit code to confirm and activate 2FA.
5. From then on, logging in requires the password **and** a fresh 6-digit code.
6. You can disable 2FA anytime from the dashboard.

## Deploying to production

- Set `NODE_ENV=production` — this enables `secure` cookies, which **require HTTPS**. Put the app behind a reverse proxy (e.g. Nginx) or a host that terminates TLS for you.
- Use a real, long, random `SESSION_SECRET` and keep it out of source control (`.env` is gitignored).
- Consider moving from SQLite to Postgres/MySQL for multi-instance deployments (the parameterized-query pattern in `routes/auth.js` carries over directly to any SQL library).
- Put the whole app behind a reverse proxy that also rate-limits and logs at the network level for defense in depth.

## Notes on the SQL injection protection

Every query in `routes/auth.js` looks like this:

```js
db.prepare('SELECT * FROM users WHERE email = ?').get(email);
```

The `?` is a bound parameter — `better-sqlite3` sends the query and the value
separately to the SQLite engine, so `email` is always treated as data, never
as part of the SQL syntax. This is what actually prevents SQL injection (as
opposed to escaping/sanitizing strings by hand, which is easy to get wrong).
Never modify this code to build queries via string concatenation or template
literals with user input.
