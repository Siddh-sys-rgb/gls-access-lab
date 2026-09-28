# GLS Access Lab

An unofficial GLS University Institute of Technology portfolio demo that makes Broken Object Level Authorization (BOLA) visible. Sign in as either of two fictional users, request the same note ID through two endpoints, and compare an intentionally vulnerable lookup with an owner-scoped fix.

This is a portfolio demonstration for application-security interviews. It uses only Python 3's standard library, SQLite, and vanilla HTML/CSS/JavaScript. There are no packages, API keys, containers, or build steps.

> **Safety boundary:** `server.py` always binds to `127.0.0.1`. The vulnerable route is intentional and must never be deployed or exposed publicly. The included audit refuses every non-loopback target and is not a scanner.

## Clone and run locally

Requirements: Python 3.9 or newer.

```bash
git clone https://github.com/Siddh-sys-rgb/gls-access-lab.git
cd gls-access-lab
python3 app.py
```

The project uses only the Python standard library, so there is no `pip install` step. An isolated environment is optional. On macOS or Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 app.py
```

On Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
py -3 app.py
```

Open <http://127.0.0.1:8103>. Confirm the server is healthy at <http://127.0.0.1:8103/api/health>; it should return `{"status":"ok","bind":"localhost-only"}`. Stop the server with Ctrl+C.

To choose another local port:

```bash
python3 app.py --port 9000
```

The database is created at `data/notes.db` on first run. Seed accounts and all note content are fictional:

| User | Password | Owned note IDs |
| --- | --- | --- |
| Aarav Shah (`aarav`) | `aarav-demo` | 1, 2 |
| Meera Patel (`meera`) | `meera-demo` | 3, 4 |

Passwords are stored as salted PBKDF2-HMAC-SHA256 hashes. Login creates a random server-side session and sends only an opaque `HttpOnly; SameSite=Strict` cookie to the browser.

Existing copies of the original demo database migrate the two legacy fixture accounts and unchanged seeded notes in place. User IDs, note IDs, and ownership relationships remain stable; custom note content is not rewritten.

## Demo walkthrough

1. Sign in as Aarav Shah. The UI lists only Aarav's notes.
2. Click **MY_NOTE**. Both endpoints return `200 OK`, because Aarav owns the object.
3. Click **OTHER_USER_NOTE**. The vulnerable endpoint returns Meera Patel's note with `200 OK`; the secure endpoint returns `404 Not Found`.
4. Click **NO_SESSION**. Both endpoints return `401 Unauthorized`.
5. Switch to Meera and repeat. The outcome is symmetric.

The UI redacts note bodies in its evidence cards while still showing the object ID, owner, title, and status needed to prove the issue. The API response contains the fictional body because unauthorized object disclosure is the behavior being demonstrated.

## Architecture

```text
Browser (vanilla JS)
  │ opaque HttpOnly session cookie
  ▼
ThreadingHTTPServer on 127.0.0.1
  ├── authentication + in-memory session store
  ├── vulnerable object lookup: WHERE notes.id = ?
  ├── secure object lookup:     WHERE notes.id = ? AND notes.owner_id = ?
  └── SQLite: users + private notes
```

Identity always comes from the server-side session. Query strings and JSON bodies cannot select a user. The secure route combines object lookup and ownership authorization in one parameterized SQL query, avoiding a check-then-fetch gap. Both an unauthorized object and a nonexistent object return the same 404 response, which avoids confirming whether another user's object exists.

The session store is in memory, so sessions disappear when the process stops. SQLite connections are short-lived per request, which works cleanly with `ThreadingHTTPServer` for this small lab.

## API

| Method | Route | Authentication | Purpose |
| --- | --- | --- | --- |
| `GET` | `/api/health` | No | Health check; returns `{"status":"ok","bind":"localhost-only"}` |
| `POST` | `/api/login` | No | Validate username/password and create a session |
| `POST` | `/api/logout` | Session optional | Destroy the current session |
| `GET` | `/api/me` | Yes | Return the session-derived user |
| `GET` | `/api/notes` | Yes | List only the current user's notes |
| `GET` | `/api/vulnerable/notes/:id` | Yes | Deliberately omits ownership filtering |
| `GET` | `/api/secure/notes/:id` | Yes | Requires the note to belong to the session user |

No edit or delete routes are provided. In a production API, every read, update, and delete query must carry the same ownership or policy constraint.

## Run the audit

Keep `python3 app.py` running in one terminal. From a second terminal in the cloned `gls-access-lab` directory, run:

```bash
python3 audit.py
python3 audit.py --report artifacts/security-report.md
```

The audit exercises six checks: own note through both endpoints, another user's note through both endpoints, and unauthenticated access through both endpoints. Expected results are `200/200`, `200/404`, and `401/401`. Generated evidence redacts note bodies.

The target defaults to `http://127.0.0.1:8103`. `--base-url` can select a different loopback port, but the script rejects non-HTTP schemes and hosts outside `localhost`, `127.0.0.1`, and `::1`. Redirect following is disabled so a local endpoint cannot bounce the audit to a remote host. The optional `artifacts/security-report.md` path is ignored by Git, so local audit output will not be committed accidentally. The repository's checked-in `SECURITY_REPORT.md` is a redacted example report.

## Tests

```bash
python3 -m unittest discover -v
```

The end-to-end suite starts an isolated local server with a temporary database and verifies:

- health and browser security headers;
- password rejection and secure cookie attributes;
- client-supplied `user_id` values have no effect;
- the complete `200/200`, `200/404`, `401/401` authorization matrix;
- unauthorized and nonexistent objects have indistinguishable secure responses.

GitHub Actions runs this same standalone suite on Python 3.9 and 3.13 for every push and pull request.

## Troubleshooting

- **Port 8103 is already in use:** stop the other process or start this lab with `python3 app.py --port 9000`. When auditing that instance, use `python3 audit.py --base-url http://127.0.0.1:9000`.
- **The database cannot be opened:** confirm the repository directory is writable and that `data/` is not a file. Stop the server before moving a damaged `data/notes.db` aside; the next start creates a fresh fictional fixture database.
- **Login stops working after a restart:** sessions live only in server memory. Restarting intentionally signs everyone out; sign in again with a demo account.
- **The audit cannot connect:** leave the application server running in a separate terminal and make sure its port matches `--base-url`.
- **A generated report is missing from Git status:** files under `artifacts/` are intentionally ignored. Choose another path only if you deliberately want to retain a report.

The source is safe to review publicly, but the running application is deliberately unsafe. It contains an endpoint that discloses another fictional user's note by design. Keep it bound to localhost and never deploy it to a public or shared network.

## Security finding

The vulnerable route demonstrates [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html), commonly called BOLA or IDOR. It is [OWASP API Security API1:2023](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/).

Authentication answers “who is making this request?” Object-level authorization answers “may this user act on this specific object?” The vulnerable route answers the first question and skips the second:

```sql
SELECT ... FROM notes WHERE notes.id = ?;
```

The remediation binds the authenticated owner to the object lookup:

```sql
SELECT ... FROM notes
WHERE notes.id = ? AND notes.owner_id = ?;
```

The second parameter is the user ID recovered from the server-side session—not a value supplied by the browser. Regression tests preserve this rule as the application changes.

## Production differences

This lab is intentionally small and honest about what it does not model. A production service should remove the vulnerable route; use a mature framework and centralized policy layer; store sessions in a durable, expiring backend; set `Secure` on cookies behind HTTPS; add CSRF protection for state-changing requests; rate-limit authentication; support password reset and stronger password policy; log authorization decisions without sensitive content; rotate secrets; encrypt backups; and run tests in CI. Multi-tenant or role-based systems may require policy checks beyond a simple `owner_id` predicate.

The local lab's fixed query is still the essential control: enforce access at the data boundary using trusted identity and test cross-user denial explicitly.

## Interview talking points

- **Why return 404 instead of 403?** It gives unauthorized callers the same result as a nonexistent object and reduces object-existence leakage.
- **Why keep both endpoints?** Side-by-side behavior isolates one missing authorization predicate, making the root cause and remediation concrete.
- **Why not accept a user ID from the client?** Client input is attacker-controlled. The server must derive identity from a validated session or token.
- **Why test allowed access too?** A security fix that blocks legitimate owners is broken. The regression matrix checks positive and negative behavior.
- **What would change for teams or shared notes?** Replace the owner predicate with a server-side membership or policy check, still tied to trusted identity and performed for every object operation.
- **What makes the demo safe?** Fixed loopback binding, fictional data, no outbound requests, a loopback-only audit, and clear warnings against deployment.
