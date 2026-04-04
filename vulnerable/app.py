from __future__ import annotations

import base64
import hashlib
import os
import secrets
import sqlite3
import time
from functools import wraps

from flask import (
    Flask, abort, g, make_response, redirect,
    render_template, request, url_for,
)

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "deskly_vuln.db")
SESSION_COOKIE = "session_id"

app = Flask(__name__)

app.secret_key = "vulnerable-dev-key"

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
            locked INTEGER NOT NULL DEFAULT 0
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
            action TEXT,
            resource TEXT,
            resource_id TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT
        );
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        """
    )
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:

        cur.execute(
            "INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)",
            ("manager@deskly.local", hashlib.md5(b"Manager123!").hexdigest(), "MANAGER"),
        )
        manager_id = cur.lastrowid
        cur.execute(
            "INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)",
            ("analyst@deskly.local", hashlib.md5(b"Analyst123!").hexdigest(), "ANALYST"),
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

def hash_password(password: str) -> str:
    return hashlib.md5(password.encode("utf-8")).hexdigest()

def verify_password(password: str, password_hash: str) -> bool:
    return hash_password(password) == password_hash

def current_user():
    if hasattr(g, "_user_cache"):
        return g._user_cache
    g._user_cache = None
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    db = get_db()
    row = db.execute(
        "SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ?",
        (token,),
    ).fetchone()
    g._user_cache = row
    return row

def login_required(view):
    @wraps(view)
    def wrapper(*a, **kw):
        if current_user() is None:
            return redirect(url_for("login"))
        return view(*a, **kw)
    return wrapper

@app.context_processor
def inject_user():
    return {"current_user": current_user()}

@app.route("/")
def index():
    return redirect(url_for("dashboard") if current_user() else url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if not email or not password:
            error = "Email and password required"
        elif password != confirm:
            error = "Passwords do not match"
        else:
            try:
                db = get_db()
                db.execute(
                    "INSERT INTO users (email, password_hash, role) "
                    "VALUES (?, ?, 'ANALYST')",
                    (email, hash_password(password)),
                )
                db.commit()
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:

                error = "Email already registered"
    return render_template("register.html", error=error)

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        if user is None:
            error = "User does not exist"
        elif not verify_password(password, user["password_hash"]):

            error = "Incorrect password"
        else:

            token = secrets.token_hex(16)
            db.execute(
                "INSERT INTO sessions (id, user_id) VALUES (?, ?)",
                (token, user["id"]),
            )
            db.commit()
            resp = make_response(redirect(url_for("dashboard")))
            resp.set_cookie(SESSION_COOKIE, token, max_age=30 * 24 * 3600)
            return resp
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():

    resp = make_response(redirect(url_for("login")))
    resp.set_cookie(SESSION_COOKIE, "", expires=0)
    return resp

@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    token = None
    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if user is None:

            error = "User does not exist"
        else:

            payload = f"{user['id']}:{int(time.time())}".encode("utf-8")
            token = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    return render_template("forgot.html", token=token, error=error)

@app.route("/reset/<token>", methods=["GET", "POST"])
def reset(token):

    try:
        padded = token + "=" * (-len(token) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        user_id_str, _ts = decoded.split(":", 1)
        user_id = int(user_id_str)
    except Exception:
        return render_template("reset.html", token=token, error="Invalid token")

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user is None:
        return render_template("reset.html", token=token, error="Invalid token")

    error = None
    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if not password or password != confirm:
            error = "Passwords do not match"
        else:
            db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (hash_password(password), user_id),
            )
            db.commit()
            return redirect(url_for("login"))
    return render_template("reset.html", token=token, error=error)

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
    db = get_db()

    row = db.execute(
        "SELECT * FROM tickets WHERE id = ?", (ticket_id,)
    ).fetchone()
    if row is None:
        abort(404)
    return render_template("ticket_detail.html", ticket=row)

@app.route("/ticket/create", methods=["GET", "POST"])
@login_required
def ticket_create():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "")
        severity = request.form.get("severity", "LOW")
        db = get_db()
        db.execute(
            "INSERT INTO tickets (title, description, severity, owner_id) "
            "VALUES (?, ?, ?, ?)",
            (title, description, severity, current_user()["id"]),
        )
        db.commit()
        return redirect(url_for("tickets"))
    return render_template("ticket_create.html")

@app.route("/ticket/search")
@login_required
def ticket_search():
    q = request.args.get("q", "")
    db = get_db()

    sql = (
        "SELECT id, title, description, severity, status, owner_id "
        "FROM tickets WHERE title LIKE '%" + q + "%' "
        "OR description LIKE '%" + q + "%'"
    )
    error = None
    rows = []
    try:
        rows = db.execute(sql).fetchall()
    except sqlite3.Error as e:

        error = f"SQL error: {e}"
    return render_template(
        "ticket_search.html",
        q=q,
        tickets=rows,
        error=error,
    )

if __name__ == "__main__":
    init_db()

    app.run(host="127.0.0.1", port=5000, debug=False)
