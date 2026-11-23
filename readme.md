# 🏛️ Nepal E-Governance Web Application

A full-stack Flask application that digitises a government service workflow: citizens register with **email OTP verification**, submit applications with a **PDF document**, and track their status, while an administrator reviews, approves or rejects each application (with a reason) and the citizen is notified by email.

**Live demo:** https://nepal-egov-system.onrender.com

---

## ✨ Features

| Area | What it does |
|---|---|
| 🔐 Authentication | Email-OTP registration (6-digit code, 10-minute expiry, 5 attempts, resend cooldown), hashed passwords, separate admin login |
| 👥 Roles | Citizen and Administrator, enforced on every route against the database |
| 📁 Documents | PDF-only uploads (5 MB max), validated by file signature, stored under random names |
| 🛡️ Private files | A document can only be opened by the citizen who uploaded it and by an administrator |
| 🔄 Workflow | Pending → Approved / Rejected; rejections require a reason that the citizen can see |
| 📧 Notifications | Email on approval / rejection |
| 📊 Admin dashboard | Filterable applications, user management, statistics chart |

## 🛠️ Tech stack

Python 3.10+ · Flask · SQLite · Jinja2 templates · vanilla CSS · Chart.js (self-hosted) · Gunicorn

---

## 🚀 Run it locally

```bash
git clone https://github.com/SynthenCoder/E-Governance-Project.git
cd E-Governance-Project

python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env              # then edit .env (see below)
python app.py                     # http://127.0.0.1:5000
```

**No email account yet?** Put `DEV_PRINT_OTP=1` in `.env` (and leave `EMAIL_USER` / `EMAIL_PASS` empty). Verification codes are then printed in the terminal instead of being emailed. Never use this in production.

### Create the administrator

1. Set `ADMIN_SETUP_CODE` in `.env` to a long secret value.
2. Open `/admin-register` and enter that code together with the admin details.
3. Only **one** administrator can be created. The page disappears once an admin exists.

If `ADMIN_SETUP_CODE` is empty, admin registration is disabled entirely.

---

## ⚙️ Configuration (environment variables)

**Secrets are never stored in the code or in git.** Copy `.env.example` to `.env` locally, or set these in your host's dashboard.

| Variable | Required | Purpose |
|---|---|---|
| `SECRET_KEY` | **Yes** (production) | Signs session cookies. Generate: `python -c "import secrets; print(secrets.token_hex(32))"` |
| `EMAIL_USER` | For email | Gmail address used to send OTP / notification emails |
| `EMAIL_PASS` | For email | Gmail **App Password** (Google Account → Security → App passwords) |
| `ADMIN_SETUP_CODE` | To create the admin | Secret code required at `/admin-register` |
| `DATA_DIR` | Optional | Folder for `database.db` and `uploads/` (use a persistent disk in production) |
| `DEV_PRINT_OTP` | Dev only | Print OTP codes to the log when email is not configured |
| `SMTP_HOST` / `SMTP_PORT` | Optional | Defaults: `smtp.gmail.com` / `465` |
| `COOKIE_SECURE`, `TRUST_PROXY` | Optional | Auto-enabled on Render; set manually for other HTTPS hosts / proxies |

---

## ☁️ Deploy on Render

1. Push the repo to GitHub and create a **Web Service** (or use the included `render.yaml` Blueprint).
2. Start command: `gunicorn app:app --workers 1 --threads 4 --bind 0.0.0.0:$PORT` (already in `Procfile` / `render.yaml`).
3. Add the environment variables above in the dashboard (`SECRET_KEY`, `EMAIL_USER`, `EMAIL_PASS`, `ADMIN_SETUP_CODE`).
4. Health check path: `/healthz`.

> **Data persistence:** SQLite and uploaded files live on the server's disk. On Render's free tier the disk is wiped on every deploy/restart. For real use, attach a persistent disk, set `DATA_DIR` to its mount path, or move to a hosted database.

> **Why one worker?** Login/OTP rate limiting is kept in memory per process, so a single worker (with threads) keeps the limits accurate.

---

## 🧪 Tests

```bash
python -m unittest discover -s tests -v
```

45 end-to-end tests cover CSRF, OTP registration, login rate limiting, admin setup, upload validation, document access control, the review workflow, user deletion and database migration.

---

## 🔒 Security measures

- Passwords hashed with Werkzeug (PBKDF2); minimum 8 characters, common passwords rejected
- Email OTP stored only as an HMAC, expiring, attempt-limited, with resend cooldown
- CSRF token required on every POST
- Brute-force protection on login, admin login, admin setup and registration
- Single-admin setup protected by a server-side secret code (race-free)
- Uploads: `.pdf` extension **and** `%PDF-` signature checked, 5 MB cap, random UUID filenames, files served only to owner/admin, directory traversal impossible
- Sessions: `HttpOnly`, `SameSite=Lax`, `Secure` in production, 2-hour lifetime, rebuilt on login, role re-checked against the database on each request
- Security headers: Content-Security-Policy, `X-Frame-Options`, `X-Content-Type-Options`, HSTS (HTTPS), `Referrer-Policy`; private pages are never cached
- Parameterised SQL everywhere; Jinja auto-escaping against XSS
- No third-party scripts: Chart.js is self-hosted

## ⚠️ Known limitations

- Rate limits are per process and reset on restart
- The CSP allows inline scripts/styles because the templates use them
- Email depends on a Gmail App Password; for high volume use a transactional email provider

---

## 📂 Project structure

```
app.py              Flask application (routes, auth, security, DB)
templates/          Jinja2 pages (+ error.html)
static/             style.css, vendor/chart.umd.js (Chart.js 4.4.7, MIT)
tests/test_app.py   End-to-end test suite
Procfile, render.yaml, runtime.txt, requirements.txt
.env.example        Template for local configuration
```

---

## 📬 Author

Sarthak Bhattarai  
📧 sarthakbhattarai121@gmail.com  
🔗 https://github.com/SynthenCoder
