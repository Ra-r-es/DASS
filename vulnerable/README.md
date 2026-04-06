# Deskly / AuthX -- vulnerable build (v1)

> ⚠ This build is **intentionally insecure** and is meant for the lab only.
> Do **not** expose it to the network.

## Run

```bash
python -m venv .venv
.venv\Scripts\activate           # Windows
# source .venv/bin/activate      # Linux / macOS
pip install -r requirements.txt
python app.py
```

Then open <http://127.0.0.1:5000> in a browser.

The first run creates `deskly_vuln.db` and seeds two demo accounts:

| Role     | Email                     | Password      |
|----------|---------------------------|---------------|
| MANAGER  | `manager@deskly.local`    | `Manager123!` |
| ANALYST  | `analyst@deskly.local`    | `Analyst123!` |

To reset the database, stop the server and delete `deskly_vuln.db`.

## Vulnerabilities present (cross-referenced in code with `# VULN <id>`)

| ID  | Category (PDF mapping) | Where to look |
|-----|------------------------|---------------|
| 4.1 | weak password policy   | `register()` and `reset()` |
| 4.2 | MD5 password hashing   | `hash_password()`  |
| 4.3 | no brute-force defence | `login()` |
| 4.4 | user enumeration       | `login()`, `register()`, `forgot()` |
| 4.5 | insecure session cookie / no rotation / no server-side invalidation on logout | `login()`, `logout()` |
| 4.6 | predictable, reusable, non-expiring reset token | `forgot()`, `reset()` |
| 4.7 | SQL injection          | `ticket_search()` |
| 4.8 | IDOR                   | `ticket_detail()` |
| 4.9 | no audit logging       | (absent everywhere) |

See `../RAPORT_SECURITATE.md` for proof-of-concept payloads, impact and fix.
