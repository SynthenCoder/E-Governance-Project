"""
Nepal E-Governance Portal
=========================
A Flask web application for submitting and reviewing government service
applications, with email-OTP registration, role-based access (user / admin),
protected document storage and an admin review workflow.

All secrets and deployment settings come from environment variables
(see `.env.example`). Nothing sensitive is hard-coded in this file.
"""

import hashlib
import hmac
import logging
import os
import re
import secrets
import smtplib
import sqlite3
import ssl
import threading
import time
import uuid
from collections import defaultdict, deque
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from email.utils import formataddr
from functools import wraps

from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

try:  # optional: load a local .env file during development
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # pragma: no cover
    pass

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)
log = logging.getLogger("egov")


# =============================================================================
# CONFIGURATION
# =============================================================================
def env_flag(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# DATA_DIR holds the database, uploads and (if generated) the secret key.
# On Render, point it at a persistent disk (e.g. /var/data) so data survives deploys.
DATA_DIR = os.environ.get("DATA_DIR") or BASE_DIR
UPLOAD_FOLDER = os.path.join(DATA_DIR, "uploads")
DB_PATH = os.path.join(DATA_DIR, "database.db")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

APP_NAME = "Nepal E-Governance"
IS_PRODUCTION = env_flag("RENDER") or os.environ.get("APP_ENV") == "production"
COOKIE_SECURE = env_flag("COOKIE_SECURE", IS_PRODUCTION)

EMAIL_USER = (os.environ.get("EMAIL_USER") or "").strip()
EMAIL_PASS = (os.environ.get("EMAIL_PASS") or "").replace(" ", "")  # Gmail shows app passwords in groups
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "465"))
ADMIN_SETUP_CODE = os.environ.get("ADMIN_SETUP_CODE", "")
# Local development only: print OTP codes to the server log instead of emailing.
DEV_PRINT_OTP = env_flag("DEV_PRINT_OTP")
# Set REQUIRE_EMAIL_OTP=false to let people register without an emailed code
# (useful while email sending is unavailable, e.g. Render's free plan blocks SMTP).
REQUIRE_EMAIL_OTP = env_flag("REQUIRE_EMAIL_OTP", True)

MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5 MB per PDF
MAX_PENDING_PER_USER = 5
ALLOWED_EXTENSIONS = {"pdf"}
UPLOAD_NAME_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.pdf$")

OTP_TTL_SECONDS = 10 * 60
OTP_MAX_ATTEMPTS = 5
OTP_RESEND_COOLDOWN = 60

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,30}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
OTP_RE = re.compile(r"^\d{6}$")
COMMON_PASSWORDS = {
    "password", "password1", "password123", "12345678", "123456789",
    "1234567890", "qwertyui", "qwerty123", "11111111", "iloveyou", "admin123",
}


def load_secret_key():
    """SECRET_KEY from the environment, else a persisted random key."""
    key = os.environ.get("SECRET_KEY")
    if key:
        return key
    path = os.path.join(DATA_DIR, ".secret_key")
    for _ in range(2):
        try:
            with open(path, encoding="utf-8") as fh:
                existing = fh.read().strip()
            if existing:
                return existing
        except FileNotFoundError:
            pass
        generated = secrets.token_hex(32)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(generated)
            log.warning(
                "SECRET_KEY is not set; generated one and saved it to %s. "
                "Set SECRET_KEY in your environment for production.", path,
            )
            return generated
        except FileExistsError:
            continue  # another worker created it first; read it
        except OSError:
            log.warning("SECRET_KEY is not set and could not be saved; sessions reset on restart.")
            return generated
    return secrets.token_hex(32)  # pragma: no cover


app = Flask(__name__)
app.config.update(
    SECRET_KEY=load_secret_key(),
    # Hard cap on the whole request; the per-file limit is enforced separately.
    MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES + 256 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=COOKIE_SECURE,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    UPLOAD_FOLDER=UPLOAD_FOLDER,
)

# Behind Render / any reverse proxy, trust one hop of X-Forwarded-* headers so
# client IPs (used for rate limiting) and HTTPS detection are correct.
if env_flag("TRUST_PROXY", env_flag("RENDER")):
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


# =============================================================================
# SMALL HELPERS
# =============================================================================
def now_ts():
    return int(time.time())


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def client_ip():
    return request.remote_addr or "unknown"


class RateLimiter:
    """Tiny in-memory sliding-window limiter (per process)."""

    def __init__(self):
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, key, window, now):
        q = self._hits[key]
        while q and q[0] <= now - window:
            q.popleft()
        if not q:
            self._hits.pop(key, None)
            return deque()
        return q

    def is_blocked(self, key, limit, window):
        with self._lock:
            return len(self._prune(key, window, time.monotonic())) >= limit

    def record(self, key):
        with self._lock:
            self._hits[key].append(time.monotonic())
            if len(self._hits) > 20000:  # keep memory bounded
                cutoff = time.monotonic() - 3600
                for k in [k for k, q in self._hits.items() if not q or q[-1] < cutoff]:
                    self._hits.pop(k, None)

    def clear(self, key):
        with self._lock:
            self._hits.pop(key, None)


limiter = RateLimiter()


# =============================================================================
# EMAIL
# =============================================================================
def email_configured():
    return bool(EMAIL_USER and EMAIL_PASS)


def send_email(to_email, subject, body):
    """Send a plain-text email. Returns True on success, never raises."""
    if not email_configured():
        log.warning("Email not sent: EMAIL_USER / EMAIL_PASS are not configured.")
        return False
    if not EMAIL_RE.match(to_email or ""):
        log.warning("Email not sent: invalid recipient address.")
        return False

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = formataddr((APP_NAME, EMAIL_USER))
    msg["To"] = to_email

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=15, context=context) as server:
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(msg)
        return True
    except Exception as exc:  # network/auth problems must not crash a request
        log.error("Email delivery failed (%s).", type(exc).__name__)
        return False


def send_email_async(to_email, subject, body):
    threading.Thread(target=send_email, args=(to_email, subject, body), daemon=True).start()


# =============================================================================
# DATABASE
# =============================================================================
@contextmanager
def db():
    """Connection that commits on success and rolls back on error."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _ensure_column(conn, table, column, ddl):
    existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in existing:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


def init_db():
    with db() as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE COLLATE NOCASE,
                email TEXT UNIQUE COLLATE NOCASE,
                password TEXT,
                role TEXT,
                created_at TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS applications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                full_name TEXT,
                file TEXT,
                status TEXT,
                reason TEXT,
                created_at TEXT,
                reviewed_by TEXT,
                reviewed_at TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS pending_registrations (
                email TEXT PRIMARY KEY COLLATE NOCASE,
                username TEXT COLLATE NOCASE,
                password TEXT,
                otp_hash TEXT,
                expires_at INTEGER,
                attempts INTEGER DEFAULT 0,
                last_sent INTEGER
            )
            """
        )
        # Upgrade databases created by older versions of the app.
        _ensure_column(conn, "users", "created_at", "TEXT")
        for col in ("reason", "created_at", "reviewed_by", "reviewed_at"):
            _ensure_column(conn, "applications", col, "TEXT")

        conn.execute("CREATE INDEX IF NOT EXISTS idx_apps_username ON applications(username)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_apps_status ON applications(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_apps_file ON applications(file)")


init_db()


def admin_exists(conn=None):
    if conn is not None:
        return conn.execute("SELECT 1 FROM users WHERE role='admin' LIMIT 1").fetchone() is not None
    with db() as c:
        return admin_exists(c)


# =============================================================================
# VALIDATION
# =============================================================================
def validate_password(password, username=""):
    if len(password) < 8:
        return "Password must be at least 8 characters."
    if len(password) > 128:
        return "Password must be at most 128 characters."
    if password.lower() in COMMON_PASSWORDS:
        return "That password is too common. Please choose another."
    if username and password.lower() == username.lower():
        return "Password must not be the same as your username."
    return None


def validate_identity(username, email):
    if not USERNAME_RE.match(username):
        return "Username must be 3–30 characters: letters, numbers, dot, dash or underscore."
    if len(email) > 254 or not EMAIL_RE.match(email):
        return "Please enter a valid email address."
    return None


# =============================================================================
# SECURITY: CSRF, HEADERS, AUTH DECORATORS
# =============================================================================
def get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = get_csrf_token


@app.before_request
def csrf_protect():
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        sent = request.form.get("csrf_token") or request.headers.get("X-CSRFToken", "")
        expected = session.get("csrf_token", "")
        if not expected or not sent or not hmac.compare_digest(sent, expected):
            abort(400, description="Your session expired or the form was invalid. Please go back, refresh the page and try again.")


CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src https://fonts.gstatic.com; "
    "img-src 'self' data:; "
    "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
)


@app.after_request
def set_security_headers(response):
    h = response.headers
    h["X-Content-Type-Options"] = "nosniff"
    h["X-Frame-Options"] = "DENY"
    h["Referrer-Policy"] = "same-origin"
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if COOKIE_SECURE:
        h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.endpoint != "static":  # pages and documents are private: never cache
        h["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        h["Pragma"] = "no-cache"
        h["Expires"] = "0"
    if response.mimetype == "text/html":
        h["Content-Security-Policy"] = CSP
    return response


def current_user():
    name = session.get("user")
    if not name:
        return None
    with db() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE username=? COLLATE NOCASE", (name,)
        ).fetchone()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if user is None:
            session.clear()
            flash("Please log in to continue.", "info")
            return redirect(url_for("login"))
        session["role"] = user["role"]  # always trust the database, not a stale cookie
        g.user = user
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if user is None:
            session.clear()
            flash("Please log in as administrator.", "info")
            return redirect(url_for("admin_login"))
        session["role"] = user["role"]
        if user["role"] != "admin":
            flash("That page is for administrators only.", "error")
            return redirect(url_for("dashboard"))
        g.user = user
        return view(*args, **kwargs)

    return wrapped


# =============================================================================
# ERROR PAGES
# =============================================================================
def render_error(code, title, message):
    return render_template("error.html", code=code, title=title, message=message), code


@app.errorhandler(400)
def bad_request(err):
    return render_error(400, "Request could not be completed", getattr(err, "description", None) or "Bad request.")


@app.errorhandler(404)
def not_found(_err):
    return render_error(404, "Page not found", "The page you are looking for does not exist.")


@app.errorhandler(RequestEntityTooLarge)
def too_large(_err):
    if request.endpoint == "apply":
        flash("File too large (max 5 MB).", "error")
        return redirect(url_for("apply"))
    return render_error(413, "Upload too large", "The file you sent is too large (max 5 MB).")


@app.errorhandler(500)
def server_error(_err):
    return render_error(500, "Something went wrong", "An unexpected error occurred. Please try again later.")


# =============================================================================
# PUBLIC PAGES
# =============================================================================
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/healthz")
def healthz():
    with db() as conn:
        conn.execute("SELECT 1").fetchone()
    return "ok", 200, {"Content-Type": "text/plain; charset=utf-8"}


# =============================================================================
# REGISTRATION WITH EMAIL OTP
# =============================================================================
def hash_otp(email, otp):
    key = app.config["SECRET_KEY"].encode()
    return hmac.new(key, f"{email.lower()}:{otp}".encode(), hashlib.sha256).hexdigest()


def deliver_otp(email, otp):
    if email_configured():
        body = (
            f"Your {APP_NAME} verification code is: {otp}\n\n"
            "It expires in 10 minutes. If you did not try to register, you can ignore this email."
        )
        return send_email(email, f"{APP_NAME} verification code", body)
    if DEV_PRINT_OTP:
        log.warning("DEV_PRINT_OTP: verification code for %s is %s", email, otp)
        return True
    log.error("Cannot send OTP: EMAIL_USER / EMAIL_PASS are not configured.")
    return False


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if limiter.is_blocked(f"register:{client_ip()}", 10, 3600):
            flash("Too many registration attempts. Please try again later.", "error")
            return redirect(url_for("register"))
        limiter.record(f"register:{client_ip()}")

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        error = validate_identity(username, email) or validate_password(password, username)
        if not error and password != confirm:
            error = "Passwords do not match."
        if error:
            flash(error, "error")
            return redirect(url_for("register"))

        otp = f"{secrets.randbelow(10 ** 6):06d}"
        with db() as conn:
            conn.execute("DELETE FROM pending_registrations WHERE expires_at < ?", (now_ts(),))
            if conn.execute("SELECT 1 FROM users WHERE username=? COLLATE NOCASE", (username,)).fetchone():
                flash("Username already exists.", "error")
                return redirect(url_for("register"))
            if conn.execute("SELECT 1 FROM users WHERE email=? COLLATE NOCASE", (email,)).fetchone():
                flash("Email already registered.", "error")
                return redirect(url_for("register"))

            if not REQUIRE_EMAIL_OTP:  # OTP switched off: create the account straight away
                try:
                    conn.execute(
                        "INSERT INTO users (username, email, password, role, created_at) VALUES (?, ?, ?, 'user', ?)",
                        (username, email, generate_password_hash(password), now_iso()),
                    )
                except sqlite3.IntegrityError:
                    flash("Username or email already exists.", "error")
                    return redirect(url_for("register"))
                flash("Account created. You can now log in.", "success")
                return redirect(url_for("login"))

            if conn.execute(
                "SELECT 1 FROM pending_registrations WHERE username=? COLLATE NOCASE AND email<>? COLLATE NOCASE",
                (username, email),
            ).fetchone():
                flash("Username already exists.", "error")
                return redirect(url_for("register"))

            conn.execute(
                """
                INSERT INTO pending_registrations
                    (email, username, password, otp_hash, expires_at, attempts, last_sent)
                VALUES (?, ?, ?, ?, ?, 0, ?)
                ON CONFLICT(email) DO UPDATE SET
                    username=excluded.username, password=excluded.password,
                    otp_hash=excluded.otp_hash, expires_at=excluded.expires_at,
                    attempts=0, last_sent=excluded.last_sent
                """,
                (email, username, generate_password_hash(password),
                 hash_otp(email, otp), now_ts() + OTP_TTL_SECONDS, now_ts()),
            )

        if not deliver_otp(email, otp):
            with db() as conn:
                conn.execute("DELETE FROM pending_registrations WHERE email=? COLLATE NOCASE", (email,))
            flash("We could not send the verification email. Please try again later.", "error")
            return redirect(url_for("register"))

        session["pending_email"] = email
        flash("We sent a 6-digit code to your email.", "success")
        return redirect(url_for("verify"))

    return render_template("register.html", show_admin_link=not admin_exists())


def _pending_for_session(conn):
    email = session.get("pending_email")
    if not email:
        return None
    row = conn.execute(
        "SELECT * FROM pending_registrations WHERE email=? COLLATE NOCASE", (email,)
    ).fetchone()
    if row is None or row["expires_at"] < now_ts():
        return None
    return row


@app.route("/verify", methods=["GET", "POST"])
def verify():
    with db() as conn:
        pending = _pending_for_session(conn)
        if pending is None:
            session.pop("pending_email", None)
            flash("Your verification session expired. Please register again.", "error")
            return redirect(url_for("register"))

        if request.method == "POST":
            otp = request.form.get("otp", "").strip()
            email = pending["email"]

            if pending["attempts"] >= OTP_MAX_ATTEMPTS:
                conn.execute("DELETE FROM pending_registrations WHERE email=? COLLATE NOCASE", (email,))
                session.pop("pending_email", None)
                flash("Too many incorrect codes. Please register again.", "error")
                return redirect(url_for("register"))

            if not OTP_RE.match(otp) or not hmac.compare_digest(pending["otp_hash"], hash_otp(email, otp)):
                conn.execute(
                    "UPDATE pending_registrations SET attempts=attempts+1 WHERE email=? COLLATE NOCASE", (email,)
                )
                flash("Incorrect code. Please check your email and try again.", "error")
                return redirect(url_for("verify"))

            try:
                conn.execute(
                    "INSERT INTO users (username, email, password, role, created_at) VALUES (?, ?, ?, 'user', ?)",
                    (pending["username"], email, pending["password"], now_iso()),
                )
            except sqlite3.IntegrityError:
                conn.execute("DELETE FROM pending_registrations WHERE email=? COLLATE NOCASE", (email,))
                session.pop("pending_email", None)
                flash("That username or email was just taken. Please register again.", "error")
                return redirect(url_for("register"))

            conn.execute("DELETE FROM pending_registrations WHERE email=? COLLATE NOCASE", (email,))
            session.pop("pending_email", None)
            flash("Email verified — your account is ready. Please log in.", "success")
            return redirect(url_for("login"))

        return render_template("verify.html", email=pending["email"])


@app.route("/resend-otp", methods=["POST"])
def resend_otp():
    with db() as conn:
        pending = _pending_for_session(conn)
        if pending is None:
            session.pop("pending_email", None)
            flash("Your verification session expired. Please register again.", "error")
            return redirect(url_for("register"))

        email = pending["email"]
        wait = OTP_RESEND_COOLDOWN - (now_ts() - (pending["last_sent"] or 0))
        if wait > 0:
            flash(f"Please wait {wait} seconds before requesting another code.", "error")
            return redirect(url_for("verify"))
        if limiter.is_blocked(f"resend:{email}", 5, 3600):
            flash("Too many codes requested. Please try again later.", "error")
            return redirect(url_for("verify"))
        limiter.record(f"resend:{email}")

        otp = f"{secrets.randbelow(10 ** 6):06d}"
        conn.execute(
            "UPDATE pending_registrations SET otp_hash=?, expires_at=?, attempts=0, last_sent=? WHERE email=? COLLATE NOCASE",
            (hash_otp(email, otp), now_ts() + OTP_TTL_SECONDS, now_ts(), email),
        )

    if deliver_otp(email, otp):
        flash("A new code has been sent.", "success")
    else:
        flash("We could not send the email. Please try again later.", "error")
    return redirect(url_for("verify"))


# =============================================================================
# ADMIN REGISTRATION (protected by a server-side setup code)
# =============================================================================
@app.route("/admin-register", methods=["GET", "POST"])
def admin_register():
    if not ADMIN_SETUP_CODE:
        flash("Administrator registration is disabled on this server.", "error")
        return redirect(url_for("admin_login"))
    if admin_exists():
        flash("An administrator already exists.", "error")
        return redirect(url_for("admin_login"))

    if request.method == "POST":
        key = f"admin-setup:{client_ip()}"
        if limiter.is_blocked(key, 5, 900):
            flash("Too many attempts. Please try again later.", "error")
            return redirect(url_for("admin_register"))

        code = request.form.get("setup_code", "")
        if not hmac.compare_digest(code.encode(), ADMIN_SETUP_CODE.encode()):
            limiter.record(key)
            log.warning("Rejected admin registration attempt from %s (bad setup code).", client_ip())
            flash("Invalid setup code.", "error")
            return redirect(url_for("admin_register"))

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        error = validate_identity(username, email) or validate_password(password, username)
        if error:
            flash(error, "error")
            return redirect(url_for("admin_register"))

        with db() as conn:
            conn.execute("BEGIN IMMEDIATE")  # make "only one admin" race-free
            if admin_exists(conn):
                flash("An administrator already exists.", "error")
                return redirect(url_for("admin_login"))
            try:
                conn.execute(
                    "INSERT INTO users (username, email, password, role, created_at) VALUES (?, ?, ?, 'admin', ?)",
                    (username, email, generate_password_hash(password), now_iso()),
                )
            except sqlite3.IntegrityError:
                flash("Username or email already exists.", "error")
                return redirect(url_for("admin_register"))

        log.info("Administrator account '%s' created.", username)
        flash("Administrator account created. Please log in.", "success")
        return redirect(url_for("admin_login"))

    return render_template("admin_register.html")


# =============================================================================
# LOGIN / LOGOUT
# =============================================================================
_DUMMY_HASH = generate_password_hash(secrets.token_hex(16))  # equalises timing for unknown users


def _authenticate(username, password):
    with db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username=? COLLATE NOCASE", (username,)
        ).fetchone()
    valid = check_password_hash(user["password"] if user else _DUMMY_HASH, password)
    return user if (user is not None and valid) else None


def _start_session(user):
    session.clear()  # prevents session fixation
    session.permanent = True
    session["user"] = user["username"]
    session["role"] = user["role"]


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        key = f"login:{client_ip()}"
        if limiter.is_blocked(key, 10, 900):
            flash("Too many failed attempts. Please wait a few minutes and try again.", "error")
            return redirect(url_for("login"))

        user = _authenticate(request.form.get("username", "").strip(), request.form.get("password", ""))
        if user is None:
            limiter.record(key)
            flash("Invalid username or password.", "error")
            return redirect(url_for("login"))
        if user["role"] == "admin":
            flash("Administrators must use the admin login.", "error")
            return redirect(url_for("admin_login"))

        limiter.clear(key)
        _start_session(user)
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/admin-login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        key = f"admin-login:{client_ip()}"
        if limiter.is_blocked(key, 5, 900):
            flash("Too many failed attempts. Please wait a few minutes and try again.", "error")
            return redirect(url_for("admin_login"))

        user = _authenticate(request.form.get("username", "").strip(), request.form.get("password", ""))
        if user is None or user["role"] != "admin":
            limiter.record(key)
            flash("Invalid administrator credentials.", "error")
            return redirect(url_for("admin_login"))

        limiter.clear(key)
        _start_session(user)
        return redirect(url_for("admin"))

    return render_template("admin_login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


# =============================================================================
# CITIZEN PAGES
# =============================================================================
@app.route("/dashboard")
@login_required
def dashboard():
    if g.user["role"] == "admin":
        return redirect(url_for("admin"))
    with db() as conn:
        apps = conn.execute(
            "SELECT * FROM applications WHERE username=? COLLATE NOCASE ORDER BY id DESC",
            (g.user["username"],),
        ).fetchall()
    return render_template("dashboard.html", applications=apps)


@app.route("/status")
@login_required
def status():
    if g.user["role"] == "admin":
        return redirect(url_for("admin"))
    with db() as conn:
        data = conn.execute(
            "SELECT * FROM applications WHERE username=? COLLATE NOCASE ORDER BY id DESC",
            (g.user["username"],),
        ).fetchall()
    return render_template("status.html", applications=data)


def _is_real_pdf(file_storage):
    """Check size and the %PDF- signature (the extension alone proves nothing)."""
    stream = file_storage.stream
    stream.seek(0, os.SEEK_END)
    size = stream.tell()
    stream.seek(0)
    head = stream.read(5)
    stream.seek(0)
    if size == 0:
        return False, "The uploaded file is empty."
    if size > MAX_UPLOAD_BYTES:
        return False, "File too large (max 5 MB)."
    if head != b"%PDF-":
        return False, "That file is not a valid PDF."
    return True, None


@app.route("/apply", methods=["GET", "POST"])
@login_required
def apply():
    if g.user["role"] == "admin":
        return redirect(url_for("admin"))

    if request.method == "POST":
        full_name = " ".join(request.form.get("full_name", "").split())
        file = request.files.get("file")

        if not 2 <= len(full_name) <= 100 or any(ord(c) < 32 for c in full_name):
            flash("Please enter your full name (2–100 characters).", "error")
            return redirect(url_for("apply"))
        if not file or not file.filename:
            flash("Please upload a PDF.", "error")
            return redirect(url_for("apply"))
        if "." not in file.filename or file.filename.rsplit(".", 1)[1].lower() not in ALLOWED_EXTENSIONS:
            flash("Only PDF files are allowed.", "error")
            return redirect(url_for("apply"))

        ok, problem = _is_real_pdf(file)
        if not ok:
            flash(problem, "error")
            return redirect(url_for("apply"))

        with db() as conn:
            pending = conn.execute(
                "SELECT COUNT(*) FROM applications WHERE username=? COLLATE NOCASE AND status='Pending'",
                (g.user["username"],),
            ).fetchone()[0]
            if pending >= MAX_PENDING_PER_USER:
                flash(f"You already have {MAX_PENDING_PER_USER} applications awaiting review. Please wait for a decision.", "error")
                return redirect(url_for("apply"))

            unique_name = f"{uuid.uuid4()}.pdf"
            path = os.path.join(app.config["UPLOAD_FOLDER"], unique_name)
            file.save(path)
            try:
                conn.execute(
                    "INSERT INTO applications (username, full_name, file, status, created_at) VALUES (?, ?, ?, 'Pending', ?)",
                    (g.user["username"], full_name, unique_name, now_iso()),
                )
            except Exception:
                try:
                    os.remove(path)
                except OSError:
                    pass
                raise

        flash("Application submitted successfully.", "success")
        return redirect(url_for("status"))

    return render_template("apply.html")


@app.route("/uploads/<filename>")
@login_required
def uploaded_file(filename):
    """Documents are visible only to their owner and to administrators."""
    if not UPLOAD_NAME_RE.match(filename):
        abort(404)
    with db() as conn:
        row = conn.execute("SELECT username FROM applications WHERE file=?", (filename,)).fetchone()
    if row is None:
        abort(404)
    is_owner = row["username"].lower() == g.user["username"].lower()
    if not (is_owner or g.user["role"] == "admin"):
        abort(404)  # 404 rather than 403: don't reveal that the file exists
    return send_from_directory(
        app.config["UPLOAD_FOLDER"], filename, mimetype="application/pdf", as_attachment=False
    )


# =============================================================================
# ADMIN PANEL
# =============================================================================
@app.route("/admin")
@admin_required
def admin():
    filter_status = request.args.get("filter", "pending").lower()
    if filter_status not in {"pending", "approved", "rejected"}:
        filter_status = "pending"

    with db() as conn:
        applications = conn.execute(
            "SELECT * FROM applications WHERE status=? ORDER BY id DESC",
            (filter_status.capitalize(),),
        ).fetchall()
        users = conn.execute("SELECT * FROM users ORDER BY id DESC").fetchall()
        counts = {
            row["status"]: row["n"]
            for row in conn.execute("SELECT status, COUNT(*) AS n FROM applications GROUP BY status")
        }
        total_users = len(users)

    return render_template(
        "admin.html",
        applications=applications,
        users=users,
        total_users=total_users,
        total_apps=sum(counts.values()),
        pending=counts.get("Pending", 0),
        approved=counts.get("Approved", 0),
        rejected=counts.get("Rejected", 0),
        filter_status=filter_status,
    )


def _review(app_id, new_status, reason=None):
    with db() as conn:
        row = conn.execute(
            """
            SELECT a.id, a.username, u.email
            FROM applications a
            LEFT JOIN users u ON u.username = a.username COLLATE NOCASE
            WHERE a.id=?
            """,
            (app_id,),
        ).fetchone()
        if row is None:
            flash("Application not found.", "error")
            return redirect(url_for("admin"), code=303)

        cur = conn.execute(
            """
            UPDATE applications
            SET status=?, reason=?, reviewed_by=?, reviewed_at=?
            WHERE id=? AND status='Pending'
            """,
            (new_status, reason, g.user["username"], now_iso(), app_id),
        )
        if cur.rowcount == 0:
            flash("That application has already been reviewed.", "error")
            return redirect(url_for("admin"), code=303)

    log.info("Application #%s %s by %s.", app_id, new_status.lower(), g.user["username"])

    if row["email"]:
        if new_status == "Approved":
            body = f"Hello {row['username']},\n\nYour application #{app_id} has been approved.\n\n{APP_NAME}"
        else:
            body = (
                f"Hello {row['username']},\n\nYour application #{app_id} has been rejected.\n"
                f"Reason: {reason}\n\n{APP_NAME}"
            )
        send_email_async(row["email"], f"Application {new_status}", body)

    flash(f"Application #{app_id} {new_status.lower()}.", "success")
    return redirect(url_for("admin"), code=303)


@app.route("/approve/<int:app_id>", methods=["POST"])
@admin_required
def approve(app_id):
    return _review(app_id, "Approved")


@app.route("/reject/<int:app_id>", methods=["POST"])
@admin_required
def reject(app_id):
    reason = " ".join(request.form.get("reason", "").split())
    if not reason:
        flash("Please give a reason for the rejection.", "error")
        return redirect(url_for("admin"), code=303)
    return _review(app_id, "Rejected", reason[:300])


@app.route("/delete-user/<int:user_id>", methods=["POST"])
@admin_required
def delete_user(user_id):
    files = []
    with db() as conn:
        user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if user is None:
            flash("User not found.", "error")
        elif user["role"] == "admin":
            flash("Administrator accounts cannot be deleted.", "error")
        else:
            files = [
                r["file"]
                for r in conn.execute(
                    "SELECT file FROM applications WHERE username=? COLLATE NOCASE", (user["username"],)
                )
            ]
            conn.execute("DELETE FROM applications WHERE username=? COLLATE NOCASE", (user["username"],))
            conn.execute("DELETE FROM users WHERE id=?", (user_id,))
            log.info("User '%s' deleted by %s.", user["username"], g.user["username"])
            flash("User and their applications were deleted.", "success")

    for name in files:  # remove the PDFs from disk once the DB change is committed
        if name and UPLOAD_NAME_RE.match(name):
            try:
                os.remove(os.path.join(app.config["UPLOAD_FOLDER"], name))
            except OSError:
                pass
    return redirect(url_for("admin"), code=303)


# =============================================================================
# RUN (development only — production uses gunicorn, see Procfile)
# =============================================================================
if __name__ == "__main__":
    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", 5000)),
        debug=env_flag("FLASK_DEBUG"),
    )
