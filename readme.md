# 🏛️ Nepal E-Governance Web Application

[![Tests](https://github.com/SynthenCoder/E-Governance-Project/actions/workflows/tests.yml/badge.svg)](https://github.com/SynthenCoder/E-Governance-Project/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Flask](https://img.shields.io/badge/Flask-3.x-lightgrey)

A full-stack Flask application that digitises a government service workflow. Citizens register, submit an application with a **PDF document**, and track its status; an administrator reviews each application, approves or rejects it (with a reason), and the citizen sees the decision.

**🌐 Live demo:** https://nepal-egov-system.onrender.com
*(hosted on Render's free plan, so the first load can take ~50 seconds while the service wakes up)*

---

## ✨ Features

| Area | What it does |
|---|---|
| 🔐 Authentication | Hashed passwords, separate admin login, optional email-OTP registration (6-digit code, 10-minute expiry, 5 attempts, resend cooldown) |
| 👥 Roles | Citizen and Administrator, enforced on every route against the database |
| 📁 Documents | PDF-only uploads (5 MB max), validated by file signature, stored under random names |
| 🛡️ Private files | A document can only be opened by the citizen who uploaded it and by an administrator |
| 🔄 Workflow | Pending → Approved / Rejected; rejections require a reason the citizen can see |
| 📧 Notifications | Optional email on approval / rejection |
| 📊 Admin dashboard | Filterable applications, user management, statistics chart |

## 🛠️ Tech stack

Python 3.10+ · Flask · SQLite · Jinja2 · vanilla CSS · Chart.js (self-hosted) · Gunicorn · GitHub Actions

---

## 🚀 Run it locally

```bash
git clone https://github.com/SynthenCoder/E-Governance-Project.git
cd E-Governance-Project

python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env              # then edit .env (see below)
python3 app.py                    # http://127.0.0.1:5000
```

**Quick start without email:** set `REQUIRE_EMAIL_OTP=false` in `.env`. Accounts are then created immediately. To try the OTP flow without an email account, set `DEV_PRINT_OTP=1` instead and the code is printed in the terminal (development only).

### Create the administrator

1. Set `ADMIN_SETUP_CODE` in `.env` to a long secret value.
2. Open `/admin-register`, enter that code plus the admin details.
3. Only **one** administrator can be created, and the page closes once an admin exists.

If `ADMIN_SETUP_CODE` is empty, admin registration is disabled entirely.

---

## ⚙️ Configuration (environment variables)

**Secrets are never stored in the code or in git.** Copy `.env.example` to `.env` locally, or set these in your host's dashboard.

| Variable | Required | Purpose |
|---|---|---|
| `SECRET_KEY` | **Yes** (production) | Signs session cookies. Generate: `python3 -c "import secrets; print(secrets.token_hex(32))"` |
| `ADMIN_SETUP_CODE` | To create the admin | Secret code required at `/admin-register` |
| `REQUIRE_EMAIL_OTP` | Optional | `false` = register without an emailed code (default `true`) |
| `EMAIL_USER` | For email | Gmail address used to send OTP / notification emails |
| `EMAIL_PASS` | For email | Gmail **App Password** (Google Account → Security → App passwords) |
| `DATA_DIR` | Optional | Folder for `database.db` and `uploads/` (use a persistent disk in production) |
| `DEV_PRINT_OTP` | Dev only | Print OTP codes to the log when email is not configured |
| `SMTP_HOST` / `SMTP_PORT` | Optional | Defaults: `smtp.gmail.com` / `465` |
| `COOKIE_SECURE`, `TRUST_PROXY` | Optional | Auto-enabled on Render; set manually for other HTTPS hosts / proxies |

---

## ☁️ Deploy on Render

1. Push the repo to GitHub and create a **Web Service** (or use the included `render.yaml` Blueprint).
2. Start command: `gunicorn app:app --workers 1 --threads 4 --bind 0.0.0.0:$PORT`
3. Add the environment variables above in the dashboard.
4. Health check path: `/healthz`

> **Email on Render's free plan:** free web services block outbound SMTP ports (25, 465, 587), so Gmail SMTP cannot work there. Either upgrade the service, send email through an HTTPS email API, or set `REQUIRE_EMAIL_OTP=false` (the live demo does this).

> **Data persistence:** SQLite and uploaded files live on the server's disk. On Render's free plan the disk is wiped on every deploy or restart, so the admin account must be recreated after each deploy. For real use, attach a persistent disk and set `DATA_DIR` to its mount path, or move to a hosted database.

> **Why one worker?** Rate limiting is kept in memory per process, so a single worker (with threads) keeps the limits accurate.

---

## 🧪 Tests

```bash
python3 -m unittest discover -s tests -v
```

48 end-to-end tests cover CSRF, OTP registration (on and off), login rate limiting, admin setup, upload validation, document access control, the review workflow, user deletion and database migration. They also run automatically on every push through GitHub Actions.

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

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## ⚠️ Known limitations

- Rate limits are per process and reset on restart
- The CSP allows inline scripts/styles because the templates use them
- Email depends on SMTP, which some hosts block; an HTTPS email API would be more robust

## 🗺️ Ideas for the future

- Email through an HTTPS API (Brevo, Resend, …) so OTP works on free hosting
- PostgreSQL instead of SQLite for persistent hosting
- Application editing / re-submission after rejection
- Pagination and search in the admin panel

---

## 📂 Project structure

```
app.py                  Flask application (routes, auth, security, DB)
templates/              Jinja2 pages (+ error.html)
static/                 style.css, vendor/chart.umd.js (Chart.js 4.4.7, MIT)
tests/test_app.py       End-to-end test suite
.github/workflows/      CI: runs the tests on every push
Procfile, render.yaml, runtime.txt, requirements.txt
.env.example            Template for local configuration
```

---

## 📄 License

Released under the [MIT License](LICENSE).

## 📬 Author

**Sarthak Bhattarai**
📧 sarthakbhattarai121@gmail.com
🔗 https://github.com/SynthenCoder
