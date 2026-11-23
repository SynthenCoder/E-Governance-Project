"""End-to-end tests (standard library only):  python -m unittest discover -s tests -v"""
import io
import os
import re
import sys
import tempfile
import unittest

# Configure the app BEFORE importing it.
_TMP = tempfile.mkdtemp(prefix="egov-test-")
os.environ.update(
    DATA_DIR=_TMP,
    SECRET_KEY="test-secret-key",
    ADMIN_SETUP_CODE="setup-code-123",
    EMAIL_USER="portal@example.com",
    EMAIL_PASS="dummy-app-password",
)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app as egov  # noqa: E402

PDF = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"
STRONG = "Correct-Horse-9"


class Base(unittest.TestCase):
    def setUp(self):
        egov.app.config.update(TESTING=False, PROPAGATE_EXCEPTIONS=False)
        egov.limiter._hits.clear()
        with egov.db() as c:
            for table in ("users", "applications", "pending_registrations"):
                c.execute(f"DELETE FROM {table}")
        for name in os.listdir(egov.UPLOAD_FOLDER):
            os.remove(os.path.join(egov.UPLOAD_FOLDER, name))
        self.sent = []
        self._orig_send = egov.send_email
        egov.send_email = lambda to, subject, body: self.sent.append((to, subject, body)) or True
        self.client = egov.app.test_client()

    def tearDown(self):
        egov.send_email = self._orig_send

    # -- helpers -------------------------------------------------------------
    def token(self, client=None):
        client = client or self.client
        with client.session_transaction() as s:
            s.setdefault("csrf_token", "test-csrf-token")
            return s["csrf_token"]

    def post(self, url, data=None, client=None, **kw):
        client = client or self.client
        data = dict(data or {})
        data["csrf_token"] = self.token(client)
        return client.post(url, data=data, **kw)

    def make_user(self, username="alice", email=None, password=STRONG, role="user"):
        with egov.db() as c:
            c.execute(
                "INSERT INTO users (username, email, password, role, created_at) VALUES (?,?,?,?,?)",
                (username, email or f"{username}@example.com",
                 egov.generate_password_hash(password), role, egov.now_iso()),
            )

    def login(self, username="alice", password=STRONG, admin=False):
        client = egov.app.test_client()
        self.post("/admin-login" if admin else "/login",
                  {"username": username, "password": password}, client=client)
        return client

    def upload(self, client, content=PDF, filename="doc.pdf", name="Alice Sharma"):
        return self.post("/apply", {"full_name": name, "file": (io.BytesIO(content), filename)},
                         client=client, content_type="multipart/form-data")

    def last_app_file(self):
        with egov.db() as c:
            return c.execute("SELECT file FROM applications ORDER BY id DESC").fetchone()["file"]

    def otp_from_email(self):
        return re.search(r"\b(\d{6})\b", self.sent[-1][2]).group(1)


class TestSecurityBasics(Base):
    def test_post_without_csrf_is_rejected(self):
        r = self.client.post("/login", data={"username": "a", "password": "b"})
        self.assertEqual(r.status_code, 400)

    def test_post_with_wrong_csrf_is_rejected(self):
        self.token()
        r = self.client.post("/login", data={"username": "a", "password": "b", "csrf_token": "nope"})
        self.assertEqual(r.status_code, 400)

    def test_every_form_has_csrf_field(self):
        for url in ("/login", "/register", "/admin-login", "/admin-register"):
            html = self.client.get(url, follow_redirects=True).get_data(as_text=True)
            if "<form" in html:
                self.assertIn('name="csrf_token"', html, url)

    def test_security_headers(self):
        r = self.client.get("/")
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        self.assertIn("frame-ancestors 'none'", r.headers["Content-Security-Policy"])
        self.assertIn("no-store", r.headers["Cache-Control"])

    def test_static_files_are_cacheable_and_local_chartjs_exists(self):
        r = self.client.get("/static/vendor/chart.umd.js")
        r.close()
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("no-store", r.headers.get("Cache-Control", ""))

    def test_no_external_script_sources_in_templates(self):
        tdir = os.path.join(os.path.dirname(egov.__file__), "templates")
        for f in os.listdir(tdir):
            with open(os.path.join(tdir, f), encoding="utf-8") as fh:
                text = fh.read()
            self.assertNotRegex(text, r"<script[^>]+src=[\"']https?://", f)

    def test_404_page(self):
        r = self.client.get("/nope")
        self.assertEqual(r.status_code, 404)
        self.assertIn("Page not found", r.get_data(as_text=True))

    def test_no_secrets_in_source(self):
        with open(egov.__file__, encoding="utf-8") as fh:
            src = fh.read()
        self.assertNotRegex(src, r"[A-Za-z0-9._]+@gmail\.com")
        self.assertNotRegex(src, r"environ\.get\(\s*[\"'][^\"']*@")

    def test_healthz(self):
        self.assertEqual(self.client.get("/healthz").get_data(as_text=True), "ok")

    def test_session_cookie_flags(self):
        self.make_user()
        c = egov.app.test_client()
        r = self.post("/login", {"username": "alice", "password": STRONG}, client=c)
        cookie = r.headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)


class TestRegistrationOtp(Base):
    def register(self, **over):
        data = dict(username="bob", email="bob@example.com", password=STRONG, confirm_password=STRONG)
        data.update(over)
        return self.post("/register", data)

    def test_full_registration_flow(self):
        r = self.register()
        self.assertEqual(r.headers["Location"], "/verify")
        self.assertEqual(self.sent[-1][0], "bob@example.com")
        with egov.db() as c:  # no account exists before verification
            self.assertIsNone(c.execute("SELECT 1 FROM users WHERE username='bob'").fetchone())
        r = self.post("/verify", {"otp": self.otp_from_email()})
        self.assertEqual(r.headers["Location"], "/login")
        self.assertEqual(self.login("bob").get("/dashboard").status_code, 200)

    def test_otp_not_stored_in_plaintext(self):
        self.register()
        otp = self.otp_from_email()
        with egov.db() as c:
            row = c.execute("SELECT * FROM pending_registrations").fetchone()
        self.assertNotIn(otp, "".join(str(v) for v in dict(row).values()))

    def test_wrong_otp_locks_after_five_attempts(self):
        self.register()
        good = self.otp_from_email()
        bad = "000000" if good != "000000" else "111111"
        for _ in range(5):
            self.post("/verify", {"otp": bad})
        r = self.post("/verify", {"otp": good})  # correct code, but locked out
        self.assertEqual(r.headers["Location"], "/register")
        with egov.db() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM users").fetchone()[0], 0)

    def test_expired_otp(self):
        self.register()
        with egov.db() as c:
            c.execute("UPDATE pending_registrations SET expires_at=1")
        r = self.post("/verify", {"otp": self.otp_from_email()})
        self.assertEqual(r.headers["Location"], "/register")

    def test_verify_requires_pending_session(self):
        self.assertEqual(self.client.get("/verify").headers["Location"], "/register")

    def test_resend_cooldown_then_new_code(self):
        self.register()
        first = self.otp_from_email()
        r = self.post("/resend-otp")
        self.assertEqual(len(self.sent), 1)  # blocked by cooldown
        with egov.db() as c:
            c.execute("UPDATE pending_registrations SET last_sent=1")
        self.post("/resend-otp")
        self.assertEqual(len(self.sent), 2)
        self.post("/verify", {"otp": self.otp_from_email()})
        with egov.db() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM users").fetchone()[0], 1)

    def test_validation_errors(self):
        for over in (dict(password="short", confirm_password="short"),
                     dict(password="password123", confirm_password="password123"),
                     dict(confirm_password="Different-9"),
                     dict(username="x"), dict(username="bad name!"),
                     dict(email="not-an-email")):
            r = self.register(**over)
            self.assertEqual(r.headers["Location"], "/register", over)
        self.assertEqual(self.sent, [])

    def test_duplicate_username_and_email_case_insensitive(self):
        self.make_user("carol", "carol@example.com")
        self.assertEqual(self.register(username="CAROL", email="x@example.com").headers["Location"], "/register")
        self.assertEqual(self.register(username="dave", email="Carol@Example.com").headers["Location"], "/register")
        self.assertEqual(self.sent, [])

    def test_email_failure_does_not_leave_pending_row(self):
        egov.send_email = lambda *a: False
        r = self.register()
        self.assertEqual(r.headers["Location"], "/register")
        with egov.db() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM pending_registrations").fetchone()[0], 0)


class TestRegistrationWithoutOtp(Base):
    """REQUIRE_EMAIL_OTP=false: accounts are created immediately, no email involved."""

    def setUp(self):
        super().setUp()
        self._orig_flag = egov.REQUIRE_EMAIL_OTP
        egov.REQUIRE_EMAIL_OTP = False

    def tearDown(self):
        egov.REQUIRE_EMAIL_OTP = self._orig_flag
        super().tearDown()

    def register(self, **over):
        data = dict(username="bob", email="bob@example.com", password=STRONG, confirm_password=STRONG)
        data.update(over)
        return self.post("/register", data)

    def test_account_created_immediately_without_email(self):
        r = self.register()
        self.assertEqual(r.headers["Location"], "/login")
        self.assertEqual(self.sent, [])
        with egov.db() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM pending_registrations").fetchone()[0], 0)
            self.assertEqual(c.execute("SELECT role FROM users WHERE username='bob'").fetchone()["role"], "user")
        self.assertEqual(self.login("bob").get("/dashboard").status_code, 200)

    def test_validation_and_duplicates_still_enforced(self):
        self.assertEqual(self.register(password="short", confirm_password="short").headers["Location"], "/register")
        self.assertEqual(self.register(confirm_password="Different-9").headers["Location"], "/register")
        self.register()
        self.assertEqual(self.register(email="other@example.com").headers["Location"], "/register")  # same username
        self.assertEqual(self.register(username="bob2").headers["Location"], "/register")  # same email
        with egov.db() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM users").fetchone()[0], 1)

    def test_verify_page_not_reachable(self):
        self.register()
        self.assertEqual(self.client.get("/verify").headers["Location"], "/register")


class TestLogin(Base):
    def test_success_and_failure_messages_are_generic(self):
        self.make_user()
        r = self.post("/login", {"username": "alice", "password": "wrong"})
        r2 = self.post("/login", {"username": "ghost", "password": "wrong"})
        self.assertEqual(r.headers["Location"], r2.headers["Location"])
        page = self.client.get("/login").get_data(as_text=True)
        self.assertIn("Invalid username or password", page)

    def test_login_rate_limit(self):
        self.make_user()
        for _ in range(10):
            self.post("/login", {"username": "alice", "password": "wrong"})
        c = self.login("alice", STRONG)  # correct password but blocked
        self.assertEqual(c.get("/dashboard").status_code, 302)

    def test_admin_cannot_use_user_login_and_user_cannot_use_admin_login(self):
        self.make_user("root", role="admin")
        self.make_user("alice")
        self.assertEqual(self.login("root").get("/admin").status_code, 302)
        self.assertEqual(self.login("alice", admin=True).get("/admin").status_code, 302)

    def test_protected_pages_redirect_when_logged_out(self):
        for url in ("/dashboard", "/apply", "/status"):
            self.assertEqual(self.client.get(url).headers["Location"], "/login", url)
        self.assertEqual(self.client.get("/admin").headers["Location"], "/admin-login")

    def test_user_cannot_open_admin(self):
        self.make_user()
        r = self.login().get("/admin")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers["Location"], "/dashboard")

    def test_deleted_user_session_is_invalidated(self):
        self.make_user()
        c = self.login()
        self.assertEqual(c.get("/dashboard").status_code, 200)
        with egov.db() as conn:
            conn.execute("DELETE FROM users")
        self.assertEqual(c.get("/dashboard").status_code, 302)

    def test_logout_clears_session(self):
        self.make_user()
        c = self.login()
        c.get("/logout")
        self.assertEqual(c.get("/dashboard").status_code, 302)

    def test_all_pages_render_for_user_and_admin(self):
        self.make_user()
        self.make_user("root", role="admin")
        u, a = self.login(), self.login("root", admin=True)
        for url in ("/dashboard", "/apply", "/status"):
            self.assertEqual(u.get(url).status_code, 200, url)
        self.assertEqual(a.get("/admin").status_code, 200)
        for f in ("pending", "approved", "rejected", "bogus"):
            self.assertEqual(a.get(f"/admin?filter={f}").status_code, 200)


class TestAdminSetup(Base):
    DATA = dict(username="boss", email="boss@example.com", password=STRONG)

    def test_wrong_code_rejected(self):
        self.post("/admin-register", dict(self.DATA, setup_code="wrong"))
        with egov.db() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM users").fetchone()[0], 0)

    def test_correct_code_creates_single_admin(self):
        self.post("/admin-register", dict(self.DATA, setup_code="setup-code-123"))
        with egov.db() as c:
            self.assertEqual(c.execute("SELECT role FROM users").fetchone()["role"], "admin")
        self.post("/admin-register", dict(self.DATA, username="boss2", email="b2@example.com", setup_code="setup-code-123"))
        with egov.db() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM users").fetchone()[0], 1)
        self.assertEqual(self.client.get("/admin-register").status_code, 302)

    def test_setup_code_brute_force_is_limited(self):
        for _ in range(5):
            self.post("/admin-register", dict(self.DATA, setup_code="guess"))
        self.post("/admin-register", dict(self.DATA, setup_code="setup-code-123"))  # blocked
        with egov.db() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM users").fetchone()[0], 0)

    def test_disabled_without_setup_code(self):
        original = egov.ADMIN_SETUP_CODE
        egov.ADMIN_SETUP_CODE = ""
        try:
            self.assertEqual(self.client.get("/admin-register").status_code, 302)
        finally:
            egov.ADMIN_SETUP_CODE = original


class TestUploadsAndAccessControl(Base):
    def setUp(self):
        super().setUp()
        self.make_user("alice")
        self.make_user("eve")
        self.make_user("root", role="admin")
        self.alice, self.eve, self.root = self.login("alice"), self.login("eve"), self.login("root", admin=True)

    def test_valid_pdf_is_accepted(self):
        r = self.upload(self.alice)
        self.assertEqual(r.headers["Location"], "/status")
        self.assertTrue(re.match(egov.UPLOAD_NAME_RE, self.last_app_file()))

    def test_fake_pdf_wrong_extension_empty_and_oversize_rejected(self):
        for content, fname in ((b"<?php evil ?>", "shell.pdf"), (PDF, "doc.exe"), (b"", "empty.pdf"),
                               (b"%PDF-" + b"0" * (5 * 1024 * 1024 + 10), "big.pdf")):
            self.upload(self.alice, content, fname)
        with egov.db() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM applications").fetchone()[0], 0)
        self.assertEqual(os.listdir(egov.UPLOAD_FOLDER), [])

    def test_oversized_request_is_blocked_by_server_limit(self):
        r = self.upload(self.alice, b"%PDF-" + b"0" * (6 * 1024 * 1024))
        self.assertIn(r.status_code, (302, 413))
        with egov.db() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM applications").fetchone()[0], 0)

    def test_pending_cap_per_user(self):
        for _ in range(egov.MAX_PENDING_PER_USER + 2):
            self.upload(self.alice)
        with egov.db() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM applications").fetchone()[0], egov.MAX_PENDING_PER_USER)

    def test_only_owner_and_admin_can_read_pdf(self):
        self.upload(self.alice)
        url = "/uploads/" + self.last_app_file()
        r = self.alice.get(url)
        self.assertEqual((r.status_code, r.mimetype), (200, "application/pdf"))
        self.assertEqual(r.data, PDF)
        r.close()
        r2 = self.root.get(url)
        r2.close()
        self.assertEqual(r2.status_code, 200)
        self.assertEqual(self.eve.get(url).status_code, 404)
        self.assertEqual(egov.app.test_client().get(url).status_code, 302)

    def test_path_traversal_and_unknown_files(self):
        for bad in ("../app.py", "..%2fapp.py", "x.pdf", "00000000-0000-0000-0000-000000000000.pdf"):
            self.assertEqual(self.root.get("/uploads/" + bad).status_code, 404, bad)

    def test_html_in_name_is_escaped(self):
        self.upload(self.alice, name="<script>alert(1)</script>")
        page = self.alice.get("/status").get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;", page)


class TestReviewWorkflow(Base):
    def setUp(self):
        super().setUp()
        self.make_user("alice")
        self.make_user("root", role="admin")
        self.alice, self.root = self.login("alice"), self.login("root", admin=True)
        self.upload(self.alice)
        with egov.db() as c:
            self.app_id = c.execute("SELECT id FROM applications").fetchone()["id"]
        self.sent.clear()

    def status(self):
        with egov.db() as c:
            return dict(c.execute("SELECT * FROM applications WHERE id=?", (self.app_id,)).fetchone())

    def wait_for_email(self):
        import time
        for _ in range(50):
            if self.sent:
                return
            time.sleep(0.02)

    def test_approve(self):
        self.post("/approve/%d" % self.app_id, client=self.root)
        s = self.status()
        self.assertEqual((s["status"], s["reviewed_by"]), ("Approved", "root"))
        self.wait_for_email()
        self.assertEqual(self.sent[0][0], "alice@example.com")

    def test_reject_requires_reason_and_shows_it_to_user(self):
        self.post("/reject/%d" % self.app_id, {"reason": "  "}, client=self.root)
        self.assertEqual(self.status()["status"], "Pending")
        self.post("/reject/%d" % self.app_id, {"reason": "Document is blurry"}, client=self.root)
        self.assertEqual(self.status()["status"], "Rejected")
        self.assertIn("Document is blurry", self.alice.get("/status").get_data(as_text=True))
        self.wait_for_email()
        self.assertIn("Document is blurry", self.sent[0][2])

    def test_cannot_review_twice(self):
        self.post("/approve/%d" % self.app_id, client=self.root)
        self.post("/reject/%d" % self.app_id, {"reason": "late"}, client=self.root)
        self.assertEqual(self.status()["status"], "Approved")

    def test_normal_user_cannot_review_or_delete(self):
        self.post("/approve/%d" % self.app_id, client=self.alice)
        self.assertEqual(self.status()["status"], "Pending")
        self.post("/delete-user/1", client=self.alice)
        with egov.db() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM users").fetchone()[0], 2)

    def test_review_unknown_application(self):
        self.assertEqual(self.post("/approve/9999", client=self.root).status_code, 303)

    def test_delete_user_removes_rows_and_files_but_not_admin(self):
        fname = self.last_app_file()
        with egov.db() as c:
            uid = c.execute("SELECT id FROM users WHERE username='alice'").fetchone()["id"]
            aid = c.execute("SELECT id FROM users WHERE username='root'").fetchone()["id"]
        self.post("/delete-user/%d" % aid, client=self.root)
        self.post("/delete-user/%d" % uid, client=self.root)
        with egov.db() as c:
            self.assertEqual([r["username"] for r in c.execute("SELECT username FROM users")], ["root"])
            self.assertEqual(c.execute("SELECT COUNT(*) FROM applications").fetchone()[0], 0)
        self.assertFalse(os.path.exists(os.path.join(egov.UPLOAD_FOLDER, fname)))


class TestMigration(unittest.TestCase):
    def test_old_schema_is_upgraded(self):
        import sqlite3
        path = os.path.join(_TMP, "old.db")
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, password TEXT, role TEXT)")
        conn.execute("CREATE TABLE applications (id INTEGER PRIMARY KEY, username TEXT, full_name TEXT, file TEXT, status TEXT)")
        conn.commit(); conn.close()
        original = egov.DB_PATH
        egov.DB_PATH = path
        try:
            egov.init_db()
            with egov.db() as c:
                cols = {r["name"] for r in c.execute("PRAGMA table_info(applications)")}
            self.assertTrue({"reason", "created_at", "reviewed_by", "reviewed_at"} <= cols)
        finally:
            egov.DB_PATH = original


if __name__ == "__main__":
    unittest.main()
