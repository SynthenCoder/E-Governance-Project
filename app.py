import os
import uuid
import smtplib
import random
from email.mime.text import MIMEText
from flask import Flask, render_template, request, redirect, session, flash, send_from_directory
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.urandom(24)

# =========================
# 🔥 FORCE NO CACHE (NEW)
# =========================
@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

# =========================
# OTP STORE (NEW 🔥)
# =========================
otp_store = {}

# =========================
# FILE UPLOAD CONFIG
# =========================
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"pdf"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# =========================
# EMAIL SYSTEM
# =========================
def send_email(to_email, subject, body):
    sender_email = "sarthakbhattarai121@gmail.com"
    sender_password = "wkyictsuriynniwk"

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = to_email

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, sender_password)
            server.send_message(msg)
        return True
    except Exception as e:
        print("Email error:", e)
        return False


# =========================
# DATABASE
# =========================
def get_db():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    return conn

# =========================
# 🔥 DB INIT FIX (NEW)
# =========================
def init_db():
    conn = sqlite3.connect("database.db")

    conn.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        password TEXT,
        role TEXT
    )
    """)

    conn.execute("""
    CREATE TABLE IF NOT EXISTS applications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        full_name TEXT,
        file TEXT,
        status TEXT
    )
    """)

    conn.commit()
    conn.close()

# 🔥 CALL INIT (IMPORTANT)
init_db()


# =========================
# HOME
# =========================
@app.route("/")
def home():
    return render_template("index.html")


# =========================
# REGISTER (UPDATED WITH OTP 🔥)
# =========================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        user = request.form["username"].strip()
        email = request.form["email"].strip()
        password = request.form["password"]
        confirm = request.form["confirm_password"]

        if password != confirm:
            flash("Passwords do not match ❌")
            return redirect("/register")

        if not user or not password or not email:
            flash("All fields required ❌")
            return redirect("/register")

        conn = get_db()

        existing = conn.execute(
            "SELECT * FROM users WHERE username=?",
            (user,)
        ).fetchone()

        if existing:
            conn.close()
            flash("Username already exists ❌")
            return redirect("/register")

        existing_email = conn.execute(
            "SELECT * FROM users WHERE email=?",
            (email,)
        ).fetchone()

        if existing_email:
            conn.close()
            flash("Email already registered ❌")
            return redirect("/register")

        conn.close()

        # 🔥 GENERATE OTP
        otp = str(random.randint(100000, 999999))

        otp_store[email] = {
            "otp": otp,
            "user": user,
            "password": generate_password_hash(password)
        }

        send_email(
            email,
            "Your OTP Code",
            f"Your verification code is: {otp}"
        )

        flash("OTP sent to your email 📩")
        return redirect(f"/verify?email={email}")

    return render_template("register.html")


# =========================
# VERIFY OTP (NEW 🔥)
# =========================
@app.route("/verify", methods=["GET", "POST"])
def verify():
    email = request.args.get("email")

    if request.method == "POST":
        entered_otp = request.form["otp"]

        data = otp_store.get(email)

        if not data:
            flash("Session expired ❌")
            return redirect("/register")

        if entered_otp != data["otp"]:
            flash("Invalid OTP ❌")
            return redirect(f"/verify?email={email}")

        conn = get_db()
        conn.execute(
            "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
            (data["user"], email, data["password"], "user")
        )
        conn.commit()
        conn.close()

        otp_store.pop(email)

        flash("Account created ✅")
        return redirect("/login")

    return render_template("verify.html", email=email)


# =========================
# ADMIN REGISTER
# =========================
@app.route("/admin-register", methods=["GET", "POST"])
def admin_register():
    if request.method == "POST":
        user = request.form["username"].strip()
        email = request.form["email"].strip()
        password = request.form["password"]

        if not user or not password or not email:
            flash("All fields required ❌")
            return redirect("/admin-register")

        conn = get_db()

        existing_admin = conn.execute(
            "SELECT * FROM users WHERE role='admin'"
        ).fetchone()

        if existing_admin:
            conn.close()
            flash("Admin already exists ⚠️")
            return redirect("/admin-login")

        existing_user = conn.execute(
            "SELECT * FROM users WHERE username=?",
            (user,)
        ).fetchone()

        if existing_user:
            conn.close()
            flash("Username already exists ❌")
            return redirect("/admin-register")

        conn.execute(
            "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
            (user, email, generate_password_hash(password), "admin")
        )

        conn.commit()
        conn.close()

        flash("Admin created 👑")
        return redirect("/admin-login")

    return render_template("admin_register.html")


# =========================
# LOGIN (USER)
# =========================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        result = conn.execute(
            "SELECT * FROM users WHERE username=?",
            (user,)
        ).fetchone()
        conn.close()

        if result and check_password_hash(result["password"], password):

            if result["role"] == "admin":
                flash("Use admin login ⚠️")
                return redirect("/login")

            session["user"] = result["username"]
            session["role"] = "user"

            flash("Login successful 🎉")
            return redirect("/dashboard")

        flash("Invalid credentials ❌")
        return redirect("/login")

    return render_template("login.html")


# =========================
# ADMIN LOGIN
# =========================
@app.route("/admin-login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        user = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        result = conn.execute(
            "SELECT * FROM users WHERE username=?",
            (user,)
        ).fetchone()
        conn.close()

        if result and check_password_hash(result["password"], password):

            if result["role"] != "admin":
                flash("Not admin ❌")
                return redirect("/admin-login")

            session["user"] = user
            session["role"] = "admin"

            flash("Welcome Admin 👑")
            return redirect("/admin")

        flash("Invalid credentials ❌")
        return redirect("/admin-login")

    return render_template("admin_login.html")


# =========================
# LOGOUT
# =========================
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# =========================
# DASHBOARD
# =========================
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/login")

    if session["role"] == "admin":
        return redirect("/admin")

    conn = get_db()
    apps = conn.execute(
        "SELECT * FROM applications WHERE username=?",
        (session["user"],)
    ).fetchall()
    conn.close()

    return render_template("dashboard.html", applications=apps)


# =========================
# APPLY
# =========================
@app.route("/apply", methods=["GET", "POST"])
def apply():
    if "user" not in session:
        return redirect("/login")

    if session["role"] == "admin":
        return redirect("/admin")

    if request.method == "POST":
        full_name = request.form["full_name"].strip()
        file = request.files.get("file")

        if request.content_length and request.content_length > 5 * 1024 * 1024:
            flash("File too large (max 5MB) ❌")
            return redirect("/apply")

        if not full_name:
            flash("Name required ❌")
            return redirect("/apply")

        if not file or file.filename == "":
            flash("Please upload a PDF ❌")
            return redirect("/apply")

        if not allowed_file(file.filename):
            flash("Only PDF allowed ❌")
            return redirect("/apply")

        safe_name = secure_filename(file.filename)
        ext = safe_name.rsplit(".", 1)[1].lower()
        unique_name = str(uuid.uuid4()) + "." + ext

        filepath = os.path.join(app.config["UPLOAD_FOLDER"], unique_name)
        file.save(filepath)

        conn = get_db()
        conn.execute(
            "INSERT INTO applications (username, full_name, file, status) VALUES (?, ?, ?, ?)",
            (session["user"], full_name, unique_name, "Pending")
        )
        conn.commit()
        conn.close()

        flash("Application submitted 🚀")
        return redirect("/status")

    return render_template("apply.html")


# =========================
# VIEW FILE
# =========================
@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


# =========================
# STATUS
# =========================
@app.route("/status")
def status():
    if "user" not in session:
        return redirect("/login")

    conn = get_db()
    data = conn.execute(
        "SELECT * FROM applications WHERE username=?",
        (session["user"],)
    ).fetchall()
    conn.close()

    return render_template("status.html", applications=data)


# =========================
# ADMIN PANEL
# =========================
@app.route("/admin")
def admin():
    if session.get("role") != "admin":
        return redirect("/login")

    filter_status = request.args.get("filter", "pending")

    conn = get_db()

    if filter_status == "approved":
        applications = conn.execute(
            "SELECT * FROM applications WHERE status='Approved' ORDER BY id DESC"
        ).fetchall()
    elif filter_status == "rejected":
        applications = conn.execute(
            "SELECT * FROM applications WHERE status='Rejected' ORDER BY id DESC"
        ).fetchall()
    else:
        applications = conn.execute(
            "SELECT * FROM applications WHERE status='Pending' ORDER BY id DESC"
        ).fetchall()
        filter_status = "pending"

    users = conn.execute("SELECT * FROM users ORDER BY id DESC").fetchall()

    total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    total_apps = conn.execute("SELECT COUNT(*) FROM applications").fetchone()[0]
    pending = conn.execute("SELECT COUNT(*) FROM applications WHERE status='Pending'").fetchone()[0]
    approved = conn.execute("SELECT COUNT(*) FROM applications WHERE status='Approved'").fetchone()[0]
    rejected = conn.execute("SELECT COUNT(*) FROM applications WHERE status='Rejected'").fetchone()[0]

    conn.close()

    return render_template(
        "admin.html",
        applications=applications,
        users=users,
        total_users=total_users,
        total_apps=total_apps,
        pending=pending,
        approved=approved,
        rejected=rejected,
        filter_status=filter_status
    )


# =========================
# APPROVE
# =========================
@app.route("/approve/<int:id>", methods=["POST"])
def approve(id):
    if session.get("role") != "admin":
        return redirect("/login")

    conn = get_db()

    app_data = conn.execute(
        "SELECT * FROM applications WHERE id=?",
        (id,)
    ).fetchone()

    if not app_data:
        conn.close()
        flash("Application not found ❌")
        return redirect("/admin")

    user = conn.execute(
        "SELECT * FROM users WHERE username=?",
        (app_data["username"],)
    ).fetchone()

    conn.execute(
        "UPDATE applications SET status='Approved' WHERE id=?",
        (id,)
    )

    conn.commit()
    conn.close()

    if user and user["email"]:
        send_email(
            user["email"],
            "Application Approved",
            f"Hello {user['username']},\n\nYour application has been approved.\n\nNepal E-Governance"
        )

    flash("Approved ✅")
    return redirect("/admin", code=303)


# =========================
# REJECT
# =========================
@app.route("/reject/<int:id>", methods=["POST"])
def reject(id):
    if session.get("role") != "admin":
        return redirect("/login")

    conn = get_db()

    app_data = conn.execute(
        "SELECT * FROM applications WHERE id=?",
        (id,)
    ).fetchone()

    if not app_data:
        conn.close()
        flash("Application not found ❌")
        return redirect("/admin")

    user = conn.execute(
        "SELECT * FROM users WHERE username=?",
        (app_data["username"],)
    ).fetchone()

    conn.execute(
        "UPDATE applications SET status='Rejected' WHERE id=?",
        (id,)
    )

    conn.commit()
    conn.close()

    if user and user["email"]:
        send_email(
            user["email"],
            "Application Rejected",
            f"Hello {user['username']},\n\nYour application has been rejected.\n\nNepal E-Governance"
        )

    flash("Rejected ❌")
    return redirect("/admin", code=303)


# =========================
# DELETE USER
# =========================
@app.route("/delete-user/<int:id>", methods=["POST"])
def delete_user(id):
    if session.get("role") != "admin":
        return redirect("/login")

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (id,)).fetchone()

    if user and user["role"] != "admin":
        conn.execute("DELETE FROM applications WHERE username=?", (user["username"],))
        conn.execute("DELETE FROM users WHERE id=?", (id,))
        conn.commit()
        flash("User deleted 🗑️")

    conn.close()
    return redirect("/admin")


# =========================
# RUN
# =========================pip install gunicorn
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)