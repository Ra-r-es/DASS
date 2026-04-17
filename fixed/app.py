from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

def utcnow() -> datetime:

    return datetime.now(timezone.utc).replace(tzinfo=None)
from functools import wraps

import bcrypt
from flask import (
    Flask, abort, g, make_response, redirect,
    render_template, request, url_for,
)

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "deskly_fixed.db")
SESSION_COOKIE = "session_id"

SESSION_INACTIVITY_MINUTES = 30
RESET_TOKEN_TTL_MINUTES = 60
LOCKOUT_MINUTES = 15
MAX_FAILED_ATTEMPTS = 5

PASSWORD_POLICY_RE = re.compile(
    r"^(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$"
)
PASSWORD_POLICY_MSG = (
    "Password must be at least 8 characters and contain an uppercase "
    "letter, a digit, and a special character."
)
GENERIC_AUTH_ERROR = "Invalid credentials"

_DUMMY_BCRYPT = bcrypt.hashpw(b"dummy-do-not-use", bcrypt.gensalt(rounds=12))

app = Flask(__name__)

app.secret_key = os.environ.get("DESKLY_SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",

    SESSION_COOKIE_SECURE=os.environ.get("DESKLY_SECURE_COOKIE") == "1",
)
COOKIE_FLAGS = dict(
    httponly=True,
    samesite="Lax",
    secure=os.environ.get("DESKLY_SECURE_COOKIE") == "1",
)

def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'ANALYST',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            locked INTEGER NOT NULL DEFAULT 0,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            lock_until TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            severity TEXT NOT NULL DEFAULT 'LOW',
            status TEXT NOT NULL DEFAULT 'OPEN',
            owner_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (owner_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            resource TEXT,
            resource_id TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT
        );
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            csrf_token TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS reset_tokens (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        """
    )
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        manager_pw = bcrypt.hashpw(b"Manager123!", bcrypt.gensalt(rounds=12)).decode()
        analyst_pw = bcrypt.hashpw(b"Analyst123!", bcrypt.gensalt(rounds=12)).decode()
        cur.execute(
            "INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)",
            ("manager@deskly.local", manager_pw, "MANAGER"),
        )
        manager_id = cur.lastrowid
        cur.execute(
            "INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)",
            ("analyst@deskly.local", analyst_pw, "ANALYST"),
        )
        analyst_id = cur.lastrowid
        cur.execute(
            "INSERT INTO tickets (title, description, severity, status, owner_id) "
            "VALUES (?, ?, ?, ?, ?)",
            ("Internal report", "A leaked admin password was found.",
             "HIGH", "OPEN", manager_id),
        )
        cur.execute(
            "INSERT INTO tickets (title, description, severity, status, owner_id) "
            "VALUES (?, ?, ?, ?, ?)",
            ("Phishing email", "Suspicious email received in support inbox.",
             "MED", "OPEN", analyst_id),
        )
    conn.commit()
    conn.close()

def parse_dt(value) -> datetime | None:
    if not value:
        return None
    s = str(value).replace(" ", "T")
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None

def audit(action, resource=None, resource_id=None, user_id=None) -> None:
    if user_id is None:
        u = current_user()
        user_id = u["id"] if u else None
    db = get_db()
    db.execute(
        "INSERT INTO audit_logs (user_id, action, resource, resource_id, ip_address) "
        "VALUES (?, ?, ?, ?, ?)",
        (
            user_id,
            action,
            resource,
            str(resource_id) if resource_id is not None else None,
            request.remote_addr,
        ),
    )
    db.commit()

_SQLITE_TS_FMT = "%Y-%m-%d %H:%M:%S"

def _sql_ts(when: datetime | None = None) -> str:
    return (when or utcnow()).strftime(_SQLITE_TS_FMT)

def _expire_stale_sessions(db) -> None:
    cutoff = _sql_ts(utcnow() - timedelta(minutes=SESSION_INACTIVITY_MINUTES))
    db.execute("DELETE FROM sessions WHERE last_active < ?", (cutoff,))

def current_user():
    if hasattr(g, "_user_cache"):
        return g._user_cache
    g._user_cache = None
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    db = get_db()
    _expire_stale_sessions(db)
    row = db.execute(
        "SELECT u.*, s.csrf_token AS _csrf, s.id AS _sid "
        "FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ?",
        (token,),
    ).fetchone()
    if row is None:
        return None
    db.execute(
        "UPDATE sessions SET last_active = ? WHERE id = ?",
        (_sql_ts(), token),
    )
    db.commit()
    g._user_cache = row
    return row

def login_required(view):
    @wraps(view)
    def wrapper(*a, **kw):
        if current_user() is None:
            return redirect(url_for("login"))
        return view(*a, **kw)
    return wrapper

def issue_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    db = get_db()
    db.execute(
        "INSERT INTO sessions (id, user_id, csrf_token) VALUES (?, ?, ?)",
        (token, user_id, csrf),
    )
    db.commit()
    return token

def revoke_session(token: str) -> None:
    db = get_db()
    db.execute("DELETE FROM sessions WHERE id = ?", (token,))
    db.commit()

def revoke_all_sessions(user_id: int) -> None:
    db = get_db()
    db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    db.commit()

@app.before_request
def csrf_protect():

    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        user = current_user()
        if user is None:
            return
        token = request.form.get("csrf_token", "")
        expected = user["_csrf"]
        if not expected or not hmac.compare_digest(token, expected):
            abort(403)

@app.context_processor
def inject_user():
    return {"current_user": current_user()}

def password_ok(pw: str) -> bool:
    return bool(PASSWORD_POLICY_RE.match(pw or ""))

def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode()

def verify_password(pw: str, pw_hash: str) -> bool:
    try:
        return bcrypt.checkpw(pw.encode("utf-8"), pw_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False

@app.route("/")
def index():
    return redirect(url_for("dashboard") if current_user() else url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        if not email or not password:
            error = "Email and password required"
        elif not password_ok(password):
            error = PASSWORD_POLICY_MSG
        elif password != confirm:
            error = "Passwords do not match"
        else:
            try:
                db = get_db()
                cur = db.execute(
                    "INSERT INTO users (email, password_hash, role) "
                    "VALUES (?, ?, 'ANALYST')",
                    (email, hash_password(password)),
                )
                db.commit()
                audit("REGISTER", "auth", resource_id=email, user_id=cur.lastrowid)
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:

                error = "Registration failed"
    return render_template("register.html", error=error)

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()

        if user is not None:
            lock_until = parse_dt(user["lock_until"])
            if lock_until and lock_until > utcnow():

                bcrypt.checkpw(password.encode("utf-8"), _DUMMY_BCRYPT)
                audit(
                    "LOGIN_LOCKED", "auth",
                    resource_id=email, user_id=user["id"],
                )
                return render_template("login.html", error=GENERIC_AUTH_ERROR)

        if user is None:

            bcrypt.checkpw(password.encode("utf-8"), _DUMMY_BCRYPT)
            audit("LOGIN_FAIL_UNKNOWN", "auth", resource_id=email)
            error = GENERIC_AUTH_ERROR
        elif verify_password(password, user["password_hash"]):
            db.execute(
                "UPDATE users SET failed_attempts = 0, lock_until = NULL WHERE id = ?",
                (user["id"],),
            )
            db.commit()

            revoke_all_sessions(user["id"])
            token = issue_session(user["id"])
            audit("LOGIN", "auth", user_id=user["id"])
            resp = make_response(redirect(url_for("dashboard")))
            resp.set_cookie(
                SESSION_COOKIE, token,
                max_age=SESSION_INACTIVITY_MINUTES * 60,
                **COOKIE_FLAGS,
            )
            return resp
        else:
            attempts = (user["failed_attempts"] or 0) + 1
            lock_until = None
            if attempts >= MAX_FAILED_ATTEMPTS:
                lock_until = (
                    utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
                ).isoformat()
                attempts = 0
            db.execute(
                "UPDATE users SET failed_attempts = ?, lock_until = ? WHERE id = ?",
                (attempts, lock_until, user["id"]),
            )
            db.commit()
            audit("LOGIN_FAIL", "auth", resource_id=email, user_id=user["id"])
            error = GENERIC_AUTH_ERROR
    return render_template("login.html", error=error)

@app.route("/logout", methods=["GET", "POST"])
def logout():
    user = current_user()
    token = request.cookies.get(SESSION_COOKIE)
    if user and token:
        audit("LOGOUT", "auth", user_id=user["id"])
        revoke_session(token)
    resp = make_response(redirect(url_for("login")))
    resp.set_cookie(SESSION_COOKIE, "", expires=0, **COOKIE_FLAGS)
    return resp

@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    sent = False
    token = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()
        if user is not None:
            raw_token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
            expires_at = (
                utcnow() + timedelta(minutes=RESET_TOKEN_TTL_MINUTES)
            ).isoformat()
            db.execute(
                "INSERT INTO reset_tokens (token_hash, user_id, expires_at) "
                "VALUES (?, ?, ?)",
                (token_hash, user["id"], expires_at),
            )
            db.commit()
            audit("RESET_REQUEST", "auth", user_id=user["id"])

            token = raw_token

        sent = True
    return render_template("forgot.html", sent=sent, token=token)

@app.route("/reset/<token>", methods=["GET", "POST"])
def reset(token):
    db = get_db()
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    row = db.execute(
        "SELECT * FROM reset_tokens WHERE token_hash = ? AND used = 0",
        (token_hash,),
    ).fetchone()
    expires = parse_dt(row["expires_at"]) if row else None

    if row is None or not expires or expires < utcnow():
        return render_template(
            "reset.html",
            error="Invalid or expired token",
            token=token,
            valid=False,
        )

    error = None
    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        if not password_ok(password):
            error = PASSWORD_POLICY_MSG
        elif password != confirm:
            error = "Passwords do not match"
        else:
            db.execute(
                "UPDATE users SET password_hash = ?, failed_attempts = 0, "
                "lock_until = NULL WHERE id = ?",
                (hash_password(password), row["user_id"]),
            )

            db.execute(
                "UPDATE reset_tokens SET used = 1 WHERE token_hash = ?",
                (token_hash,),
            )

            db.execute("DELETE FROM sessions WHERE user_id = ?", (row["user_id"],))
            db.commit()
            audit("PASSWORD_RESET", "auth", user_id=row["user_id"])
            return redirect(url_for("login"))
    return render_template("reset.html", error=error, token=token, valid=True)

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

@app.route("/tickets")
@login_required
def tickets():
    user = current_user()
    db = get_db()
    if user["role"] == "MANAGER":
        rows = db.execute("SELECT * FROM tickets ORDER BY id DESC").fetchall()
    else:
        rows = db.execute(
            "SELECT * FROM tickets WHERE owner_id = ? ORDER BY id DESC",
            (user["id"],),
        ).fetchall()
    return render_template("tickets.html", tickets=rows)

@app.route("/ticket/<int:ticket_id>")
@login_required
def ticket_detail(ticket_id):
    user = current_user()
    db = get_db()
    row = db.execute(
        "SELECT * FROM tickets WHERE id = ?", (ticket_id,)
    ).fetchone()
    if row is None:
        abort(404)

    if row["owner_id"] != user["id"] and user["role"] != "MANAGER":
        audit("AUTHZ_DENY", "ticket", resource_id=ticket_id, user_id=user["id"])
        abort(403)
    audit("VIEW_TICKET", "ticket", resource_id=ticket_id, user_id=user["id"])
    return render_template("ticket_detail.html", ticket=row)

@app.route("/ticket/create", methods=["GET", "POST"])
@login_required
def ticket_create():
    user = current_user()
    error = None
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "")
        severity = request.form.get("severity", "LOW")
        if severity not in ("LOW", "MED", "HIGH"):
            severity = "LOW"
        if not title:
            error = "Title is required"
        else:
            db = get_db()
            cur = db.execute(
                "INSERT INTO tickets (title, description, severity, owner_id) "
                "VALUES (?, ?, ?, ?)",
                (title[:200], description[:5000], severity, user["id"]),
            )
            db.commit()
            audit(
                "CREATE_TICKET", "ticket",
                resource_id=cur.lastrowid, user_id=user["id"],
            )
            return redirect(url_for("tickets"))
    return render_template("ticket_create.html", error=error)

@app.route("/ticket/search")
@login_required
def ticket_search():
    user = current_user()
    q = request.args.get("q", "").strip()
    rows = []
    if q:
        like = f"%{q}%"
        db = get_db()
        if user["role"] == "MANAGER":
            rows = db.execute(
                "SELECT * FROM tickets "
                "WHERE title LIKE ? OR description LIKE ? "
                "ORDER BY id DESC LIMIT 100",
                (like, like),
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT * FROM tickets "
                "WHERE owner_id = ? AND (title LIKE ? OR description LIKE ?) "
                "ORDER BY id DESC LIMIT 100",
                (user["id"], like, like),
            ).fetchall()
        audit("SEARCH", "ticket", resource_id=q, user_id=user["id"])
    return render_template("ticket_search.html", q=q, tickets=rows)

@app.route("/audit")
@login_required
def audit_view():
    user = current_user()
    if user["role"] != "MANAGER":
        abort(403)
    db = get_db()
    rows = db.execute(
        "SELECT a.*, u.email FROM audit_logs a "
        "LEFT JOIN users u ON u.id = a.user_id "
        "ORDER BY a.id DESC LIMIT 200"
    ).fetchall()
    return render_template("audit.html", logs=rows)

@app.after_request
def security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; frame-ancestors 'none'",
    )
    return resp

@app.errorhandler(403)
def err_403(e):
    return render_template("error.html", code=403, message="Forbidden"), 403

@app.errorhandler(404)
def err_404(e):
    return render_template("error.html", code=404, message="Not found"), 404

@app.errorhandler(500)
def err_500(e):

    app.logger.exception("Unhandled exception")
    return render_template(
        "error.html", code=500, message="Internal server error"
    ), 500

if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
