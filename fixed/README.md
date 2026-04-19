# Deskly / AuthX -- secure build (v2)

Hardened version of the Deskly app, addressing every vulnerability listed
in section 4 of the project PDF.

## Run

```bash
python -m venv .venv
.venv\Scripts\activate           # Windows
# source .venv/bin/activate      # Linux / macOS
pip install -r requirements.txt
python app.py
```

Then open <http://127.0.0.1:5000>.

The first run creates `deskly_fixed.db` and seeds two demo accounts:

| Role     | Email                     | Password      |
|----------|---------------------------|---------------|
| MANAGER  | `manager@deskly.local`    | `Manager123!` |
| ANALYST  | `analyst@deskly.local`    | `Analyst123!` |

To reset the database, stop the server and delete `deskly_fixed.db`.

## Optional environment variables

| Variable                   | Effect                                                 |
|----------------------------|--------------------------------------------------------|
| `DESKLY_SECRET_KEY`        | Pin Flask `secret_key` so existing sessions survive a restart |
| `DESKLY_SECURE_COOKIE=1`   | Add the `Secure` cookie flag (only useful behind HTTPS) |

## Hardening summary

| PDF | Control |
|-----|---------|
| 4.1 | Password policy enforced on register and reset (`PASSWORD_POLICY_RE`) |
| 4.2 | bcrypt (cost 12) with per-password salt (`hash_password`) |
| 4.3 | Per-account failed-attempt counter, 15-minute lockout after 5 failures (`login`) |
| 4.4 | Single generic auth message, plus a dummy bcrypt run on unknown users to equalise timing |
| 4.5 | Session table on the server, rotation on login, full revocation on logout, 30-min inactivity expiry, `HttpOnly` + `SameSite=Lax` (+ `Secure` via env) cookies |
| 4.6 | `secrets.token_urlsafe(32)`, SHA-256 stored at rest, single-use, 1-hour TTL |
| 4.7 | All queries use `?` parameter binding |
| 4.8 | `ticket_detail` returns 403 unless the user owns the ticket or is a MANAGER |
| 4.9 | Every state-changing event is recorded in `audit_logs` (LOGIN, LOGIN_FAIL, LOGOUT, REGISTER, RESET_REQUEST, PASSWORD_RESET, CREATE_TICKET, VIEW_TICKET, AUTHZ_DENY, SEARCH); MANAGER can view via `/audit` |
| +   | CSRF token on authenticated POST forms |
| +   | Security headers (`CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`) |
| +   | Custom 403 / 404 / 500 pages without stack traces |

See `../RAPORT_SECURITATE.md` for proof-of-concept payloads, impact and the
re-test that proves each fix.
