# Vulnerability Findings - Student Pair

Names: ______________________________ and ______________________________

The six findings below map to the six OWASP Top 10 (2025) risk codes listed in the laboratory handout. File line numbers refer to the **original starter** `app/main.py` so a reviewer can locate each planted issue in the starter diff.

| # | OWASP 2025 code & name | Where in original starter | How an attacker abuses it | Fix applied |
|---|---|---|---|---|
| 1 | **A01 - Broken Access Control** | `GET /notes/{note_id}`, original lines 132-138 | Alice can request Bob's note by guessing its ID because the route checks that the note exists but never checks its owner. | Query by both `note_id` and authenticated `owner_id`; return 404 when the note is absent or belongs to someone else. |
| 2 | **A02 - Security Misconfiguration** | Original lines 28-37 and 93-99 | A hardcoded signing secret, wildcard CORS with credentials, and stack traces in API responses expose configuration details and can make cross-origin access unsafe. | Read signing secret and allowed origins from environment variables; use explicit development origins; return a generic 500 response and keep diagnostics in server logs. |
| 3 | **A04 - Cryptographic Failures** | Original lines 63-67 and 105-108; login check at 120 | Passwords are stored directly in the database, so a database leak immediately exposes credentials. | Hash each password with a random salt and PBKDF2-HMAC-SHA256; compare derived hashes with `hmac.compare_digest`; seed accounts use the same hash format. |
| 4 | **A05 - Injection** | `POST /login`, original lines 115-117 | A username containing SQL syntax is interpolated into the SQL string, allowing an attacker to alter the login query. | Use a parameterized query with `WHERE username = ?`. |
| 5 | **A07 - Authentication Failures** | `POST /login`, original lines 119-122; `current_user`, original lines 86-90 | Sequential user IDs are accepted as bearer tokens and do not expire; different login errors also reveal whether a username exists. | Issue HMAC-signed tokens with a one-hour expiry, reject invalid/tampered/expired tokens, require the Bearer scheme, and return one generic login failure. |
| 6 | **A10 - Mishandling of Exceptional Conditions** *(2025 handout wording: Exceptional Conditions)* | `GET /admin/users`, original lines 154-161 | If authentication or the admin permission check raises an exception, the broad `except` swallows it and continues to expose the user list. | Authenticate before entering the route and deny non-admin users with 403; do not swallow permission-check errors. |

## Reflection (3-4 sentences)

Broken Access Control (A01) would likely cause the most immediate damage in a notes application because a logged-in user could read another person's private information simply by changing a note ID. The impact could include disclosure of personal or confidential information, and the same mistake can also affect update or delete actions if those routes are added later. Authentication and injection flaws are also serious, but the ownership check directly protects the central promise of this app: each user's notes stay private. The route now checks both the note ID and the authenticated user's ID before returning a record.

## Verification notes

The fixed project includes `tests/smoke_test.py`, which exercises normal registration/login/note flows and the relevant negative security cases using only the Python standard library plus the app's listed dependencies. Run it from this folder after installing requirements:

```bash
python tests/smoke_test.py
```

Record the actual test date/results after running it on your machine. Peer review of another team's pull request still needs to be completed by your assigned reviewer; do not mark that external review complete until it has actually happened.
