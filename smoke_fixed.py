from __future__ import annotations

import base64
import http.cookiejar
import re
import sqlite3
import sys
import time
import urllib.parse
import urllib.request
from urllib.error import HTTPError

BASE = "http://127.0.0.1:5000"
DB = r"C:/Anul 3/Semestru 2/Dezvoltarea Apl Softw/fixed/deskly_fixed.db"

def session_opener():
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cj),
        urllib.request.HTTPRedirectHandler(),
    )
    return op, cj

def post(opener, path, data, allow_redirect=True):
    body = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(BASE + path, data=body, method="POST")
    if allow_redirect:
        return opener.open(req)
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **kw): return None
    op = urllib.request.build_opener(NoRedirect)
    try:
        return op.open(req)
    except HTTPError as e:
        return e

def get(opener, path):
    return opener.open(BASE + path)

def assert_(cond, msg):
    print(f"  {'PASS' if cond else 'FAIL'} -- {msg}")
    if not cond:
        sys.exit(1)

CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')

def login_get_csrf(email, password):
    opener, cj = session_opener()
    post(opener, "/login", {"email": email, "password": password})
    body = get(opener, "/ticket/create").read().decode()
    m = CSRF_RE.search(body)
    return opener, cj, (m.group(1) if m else None)

def cookies_dict(cj):
    return {c.name: c.value for c in cj}

print("\n[4.1] weak password rejected on register")
opener, _ = session_opener()
email = f"weak_{int(time.time())}@x.local"
resp = post(opener, "/register", {"email": email, "password": "a", "confirm": "a"})
body = resp.read().decode()
assert_("at least 8 characters" in body, "weak password rejected with policy message")
db = sqlite3.connect(DB)
row = db.execute("SELECT email FROM users WHERE email = ?", (email,)).fetchone()
db.close()
assert_(row is None, "user with weak password not stored in DB")

print("\n[4.2] passwords stored as bcrypt hashes (no MD5)")
import hashlib
md5_manager = hashlib.md5(b"Manager123!").hexdigest()
db = sqlite3.connect(DB)
hashes = [r[0] for r in db.execute("SELECT password_hash FROM users").fetchall()]
db.close()
assert_(all(h.startswith("$2b$") or h.startswith("$2a$") for h in hashes),
        "all password_hash values are bcrypt ($2b$...)")
assert_(md5_manager not in hashes, "no MD5 of 'Manager123!' present in DB")

print("\n[4.4] generic auth error (no enumeration)")
opener, _ = session_opener()
r1 = post(opener, "/login", {"email": "ghost@nope.local", "password": "x"}).read().decode()
r2 = post(opener, "/login", {"email": "manager@deskly.local", "password": "wrong"}).read().decode()
assert_("Invalid credentials" in r1 and "Invalid credentials" in r2,
        "both unknown user and wrong password return 'Invalid credentials'")
assert_("does not exist" not in (r1 + r2) and "Incorrect password" not in (r1 + r2),
        "no distinct messages leak user existence")

print("\n[4.3] account lockout after 5 failed attempts")

opener, _ = session_opener()
test_email = f"locktest_{int(time.time())}@x.local"
test_pw = "Strong#1Password"
post(opener, "/register", {"email": test_email, "password": test_pw, "confirm": test_pw})
opener2, _ = session_opener()
for _ in range(5):
    post(opener2, "/login", {"email": test_email, "password": "WRONG"})

opener3, cj3 = session_opener()
post(opener3, "/login", {"email": test_email, "password": test_pw}, allow_redirect=False)
assert_(not any(c.name == "session_id" for c in cj3),
        "after 5 wrong attempts, even the correct password is rejected (locked)")
db = sqlite3.connect(DB)
row = db.execute("SELECT lock_until FROM users WHERE email = ?", (test_email,)).fetchone()
db.close()
assert_(row[0] is not None, f"lock_until set in DB ({row[0]})")

print("\n[4.5] cookie hardening + session invalidated on logout + rotation")
opener, cj = session_opener()
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw): return None
op = urllib.request.build_opener(NoRedirect)
body = urllib.parse.urlencode({"email": "manager@deskly.local", "password": "Manager123!"}).encode()
req = urllib.request.Request(BASE + "/login", data=body, method="POST")
try:
    resp = op.open(req)
except HTTPError as e:
    resp = e
sc = resp.headers.get("Set-Cookie", "")
assert_("HttpOnly" in sc, f"Set-Cookie has HttpOnly ({sc[:80]}...)")
assert_("SameSite=Lax" in sc, f"Set-Cookie has SameSite=Lax ({sc[:80]}...)")
captured = sc.split("session_id=", 1)[1].split(";", 1)[0]

req = urllib.request.Request(BASE + "/dashboard")
req.add_header("Cookie", f"session_id={captured}")
body = urllib.request.urlopen(req).read().decode()
assert_("Dashboard" in body, "captured cookie works while session is alive")

req = urllib.request.Request(BASE + "/logout")
req.add_header("Cookie", f"session_id={captured}")
urllib.request.urlopen(req)

class NoRedirect2(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw): return None
op2 = urllib.request.build_opener(NoRedirect2)
req = urllib.request.Request(BASE + "/dashboard")
req.add_header("Cookie", f"session_id={captured}")
try:
    resp = op2.open(req)
except HTTPError as e:
    resp = e
assert_(resp.status in (301, 302) and "/login" in resp.headers.get("Location", ""),
        f"after logout, captured cookie redirects to /login (got {resp.status})")

op_a, cj_a = session_opener()
post(op_a, "/login", {"email": "manager@deskly.local", "password": "Manager123!"})
sid_a = next(c.value for c in cj_a if c.name == "session_id")
op_b, cj_b = session_opener()
post(op_b, "/login", {"email": "manager@deskly.local", "password": "Manager123!"})
sid_b = next(c.value for c in cj_b if c.name == "session_id")
assert_(sid_a != sid_b, "second login produced a new session id")

req = urllib.request.Request(BASE + "/dashboard")
req.add_header("Cookie", f"session_id={sid_a}")
try:
    resp = op2.open(req)
except HTTPError as e:
    resp = e
assert_(resp.status in (301, 302) and "/login" in resp.headers.get("Location", ""),
        "first session was rotated out by the second login")

print("\n[4.6] forged predictable token rejected; real token is one-shot")
forged = base64.urlsafe_b64encode(b"1:0").decode().rstrip("=")
opener, _ = session_opener()
resp = post(opener, f"/reset/{forged}",
            {"password": "AAAaaa1!fail", "confirm": "AAAaaa1!fail"})
body = resp.read().decode()
assert_("Invalid or expired token" in body,
        "forged base64 token rejected with 'Invalid or expired token'")

opener, _ = session_opener()
resp = post(opener, "/forgot", {"email": "manager@deskly.local"})
body = resp.read().decode()
m = re.search(r"/reset/([A-Za-z0-9_\-]+)", body)
assert_(m is not None, "real reset token issued by /forgot")
real_token = m.group(1)
assert_(len(real_token) >= 40, f"real token is {len(real_token)} chars (random)")

new_pw = "ResetPwd#1A"
opener, _ = session_opener()
post(opener, f"/reset/{real_token}", {"password": new_pw, "confirm": new_pw})
opener2, cj2 = session_opener()
post(opener2, "/login", {"email": "manager@deskly.local", "password": new_pw})
assert_(any(c.name == "session_id" for c in cj2), "real token used once -> login works")

opener, _ = session_opener()
resp = post(opener, f"/reset/{real_token}",
            {"password": "Other#1Pwd", "confirm": "Other#1Pwd"})
body = resp.read().decode()
assert_("Invalid or expired token" in body, "token cannot be replayed (single-use)")

opener, _ = session_opener()
post(opener, "/forgot", {"email": "manager@deskly.local"})
body = get(opener, "/forgot").read().decode()

opener, _ = session_opener()
resp = post(opener, "/forgot", {"email": "manager@deskly.local"})
body = resp.read().decode()
m = re.search(r"/reset/([A-Za-z0-9_\-]+)", body)
opener, _ = session_opener()
post(opener, f"/reset/{m.group(1)}",
     {"password": "Manager123!", "confirm": "Manager123!"})

print("\n[4.7] SQL injection neutralised on /ticket/search")
opener, _ = session_opener()
post(opener, "/login", {"email": "analyst@deskly.local", "password": "Analyst123!"})
resp = get(opener, "/ticket/search?q=" + urllib.parse.quote("' OR 1=1--"))
body = resp.read().decode()
assert_("Internal report" not in body,
        "OR 1=1 payload does NOT return the manager's ticket")
union = ("' UNION SELECT id, email, password_hash, role, "
         "created_at, locked, NULL, NULL FROM users--")
resp = get(opener, "/ticket/search?q=" + urllib.parse.quote(union))
body = resp.read().decode()
assert_("$2b$" not in body and "$2a$" not in body,
        "UNION attack does NOT leak any bcrypt hash")

print("\n[4.8] IDOR blocked -- analyst gets 403 on manager's ticket")
class NoRedirect3(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw): return None
op = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(),
    NoRedirect3(),
)
body = urllib.parse.urlencode({"email": "analyst@deskly.local",
                               "password": "Analyst123!"}).encode()
req = urllib.request.Request(BASE + "/login", data=body, method="POST")
try: op.open(req)
except HTTPError: pass
try:
    resp = op.open(BASE + "/ticket/1")
except HTTPError as e:
    resp = e
assert_(resp.status == 403, f"analyst hitting /ticket/1 returns 403 (got {resp.status})")

print("\n[4.9] audit_logs records sensitive events")
db = sqlite3.connect(DB)
n = db.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
actions = [r[0] for r in db.execute(
    "SELECT DISTINCT action FROM audit_logs"
).fetchall()]
db.close()
assert_(n > 0, f"audit_logs has {n} rows")
for needed in ("LOGIN", "LOGIN_FAIL", "LOGOUT", "AUTHZ_DENY",
               "PASSWORD_RESET", "RESET_REQUEST", "REGISTER"):
    assert_(needed in actions, f"audit log contains {needed}")

print("\n[+] CSRF protection on authenticated POSTs")
opener, cj, csrf = login_get_csrf("manager@deskly.local", "Manager123!")
sid = cookies_dict(cj)["session_id"]

class NoRedirect4(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw): return None
op = urllib.request.build_opener(NoRedirect4())
data = urllib.parse.urlencode({"title": "no-csrf",
                               "description": "x",
                               "severity": "LOW"}).encode()
req = urllib.request.Request(BASE + "/ticket/create", data=data, method="POST")
req.add_header("Cookie", f"session_id={sid}")
try:
    resp = op.open(req)
except HTTPError as e:
    resp = e
assert_(resp.status == 403, f"POST without CSRF token returns 403 (got {resp.status})")

data = urllib.parse.urlencode({
    "title": "with-csrf",
    "description": "x",
    "severity": "LOW",
    "csrf_token": csrf,
}).encode()
req = urllib.request.Request(BASE + "/ticket/create", data=data, method="POST")
req.add_header("Cookie", f"session_id={sid}")
try:
    resp = op.open(req)
except HTTPError as e:
    resp = e
assert_(resp.status in (301, 302),
        f"POST with valid CSRF token succeeds (got {resp.status})")

print("\n[+] security headers present")
resp = urllib.request.urlopen(BASE + "/login")
for h in ("Content-Security-Policy", "X-Frame-Options",
          "X-Content-Type-Options", "Referrer-Policy"):
    assert_(resp.headers.get(h) is not None, f"{h} header set")

print("\nAll fixes hold up under attack.")
