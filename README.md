# SecureNotes API - OWASP Top 10 (2025) Fixed Lab

This is the fixed version of the Week 13 SecureNotes FastAPI + SQLite activity. The six intended findings and fixes are documented in `FINDINGS.md`.

## Requirements

- Python 3.10 or newer
- Git (for the GitHub PR portion)
- The packages in `requirements.txt`

## Run on Windows (PowerShell)

From this `SecureNotes-STUDENT` folder:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
$env:SECURENOTES_SECRET_KEY = python -c "import secrets; print(secrets.token_urlsafe(48))"
uvicorn app.main:app --reload
```

If PowerShell blocks activation, use this for the current terminal session only, then activate the environment:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1
```

## Run on macOS/Linux

```bash
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
export SECURENOTES_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
uvicorn app.main:app --reload
```

Open the interactive API docs at <http://127.0.0.1:8000/docs>.

## Seeded accounts

| Username | Password | Role |
|---|---|---|
| `admin` | `admin123` | Administrator |
| `alice` | `alicepass` | Normal user |
| `bob` | `bobpass` | Normal user |

The in-memory database is recreated on each server start. Seeded passwords are hashed before being stored. Alice owns note `1`; Bob owns note `2`.

## Security behavior

- Passwords are salted PBKDF2-HMAC-SHA256 hashes, never stored or returned as plaintext.
- Login uses a parameterized SQL query and one generic error for invalid credentials.
- Bearer tokens are HMAC-signed and expire after one hour.
- Notes can be read only by their owner; missing and unauthorized note IDs both return 404.
- `/admin/users` requires an authenticated administrator and returns no password hashes.
- CORS origins are explicitly configured by `SECURENOTES_ALLOWED_ORIGINS` (comma-separated). The default permits local Vite development origins only.
- `SECURENOTES_SECRET_KEY` should be a long random environment variable. If not set in development, a temporary random key is generated and existing tokens become invalid after restart. In production mode (`SECURENOTES_ENV=production`), the app refuses to start without the configured key.
- Unexpected errors return a generic message to clients; details remain in server logs.

## Run the smoke tests

With the requirements installed, stop any existing copy of the app and run:

```bash
python tests/smoke_test.py
```

The script starts its own local server on a free port, runs positive and negative API tests, and shuts the server down. A successful run ends with `ALL SMOKE TESTS PASSED`.

## GitHub pull request workflow

The lab requires the original starter to be the `main` branch and the fixes to be on `security-fixes`. If you are starting from a fresh copy of this fixed folder, the supplied ZIP does not include the starter's Git history. Follow the separate `GITHUB_SUBMISSION_GUIDE.md` for a reliable setup using both the original ZIP and the fixed folder.
