"""End-to-end smoke tests using only the standard library and project dependencies."""

import base64
import hashlib
import hmac
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEST_SECRET = "smoke-test-only-secret-key-with-more-than-32-bytes"


def request(base_url, method, path, body=None, token=None, extra_headers=None):
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if extra_headers:
        headers.update(extra_headers)
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        base_url + path, data=data, headers=headers, method=method
    )
    try:
        with urllib.request.urlopen(req, timeout=3) as response:
            raw = response.read()
            try:
                parsed = json.loads(raw.decode("utf-8")) if raw else None
            except json.JSONDecodeError:
                parsed = raw.decode("utf-8", errors="replace")
            return response.status, parsed, response.headers
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            parsed = json.loads(raw.decode("utf-8")) if raw else None
        except json.JSONDecodeError:
            parsed = raw.decode("utf-8", errors="replace")
        return exc.code, parsed, exc.headers


def token_for_expired_user(user_id=1):
    payload = base64.urlsafe_b64encode(
        json.dumps({"sub": user_id, "exp": int(time.time()) - 60}, separators=(",", ":"), sort_keys=True).encode()
    ).rstrip(b"=").decode("ascii")
    signature = base64.urlsafe_b64encode(
        hmac.new(TEST_SECRET.encode(), payload.encode("ascii"), hashlib.sha256).digest()
    ).rstrip(b"=").decode("ascii")
    return payload + "." + signature


def main():
    failures = []
    checks = 0

    def check(description, condition, detail=""):
        nonlocal checks
        checks += 1
        if condition:
            print(f"[PASS] {description}")
        else:
            message = f"[FAIL] {description}"
            if detail:
                message += f" — {detail}"
            print(message)
            failures.append(message)

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    base_url = f"http://127.0.0.1:{port}"
    env = os.environ.copy()
    env["SECURENOTES_SECRET_KEY"] = TEST_SECRET
    env["SECURENOTES_ENV"] = "testing"
    env["SECURENOTES_ALLOWED_ORIGINS"] = "http://localhost:5173,http://127.0.0.1:5173"

    # Inspect the local app instance directly to verify storage format as well as API behavior.
    sys.path.insert(0, str(ROOT))
    os.environ["SECURENOTES_SECRET_KEY"] = TEST_SECRET
    os.environ["SECURENOTES_ENV"] = "testing"
    import app.main as local_app

    stored_rows = local_app.db.execute("SELECT username, password FROM users").fetchall()
    stored_hashes = {row["username"]: row["password"] for row in stored_rows}
    check(
        "Seeded accounts store salted hashes, not plaintext passwords",
        all(
            stored_hashes.get(username, "").startswith("pbkdf2_sha256$")
            and stored_hashes[username] != password
            for username, password in (("admin", "admin123"), ("alice", "alicepass"), ("bob", "bobpass"))
        ),
    )
    check(
        "Seeded password hashes verify against the documented credentials",
        all(
            local_app.verify_password(password, stored_hashes[username])
            for username, password in (("admin", "admin123"), ("alice", "alicepass"), ("bob", "bobpass"))
        ),
    )

    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
        cwd=ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        ready = False
        for _ in range(100):
            if server.poll() is not None:
                raise RuntimeError("Uvicorn exited before startup; install requirements first.")
            try:
                status, _, _ = request(base_url, "GET", "/")
                if status == 200:
                    ready = True
                    break
            except (urllib.error.URLError, TimeoutError, OSError):
                pass
            time.sleep(0.1)
        if not ready:
            raise RuntimeError("Uvicorn did not become ready on the selected local port.")

        status, data, _ = request(base_url, "GET", "/")
        check("API starts and root responds", status == 200 and data.get("service") == "SecureNotes API")
        status, openapi, _ = request(base_url, "GET", "/openapi.json")
        check(
            "OpenAPI schema loads with required endpoints",
            status == 200 and all(path in openapi.get("paths", {}) for path in ("/register", "/login", "/notes", "/notes/{note_id}", "/admin/users")),
        )

        status, alice_login, _ = request(base_url, "POST", "/login", {"username": "alice", "password": "alicepass"})
        check("Alice can log in", status == 200 and isinstance(alice_login.get("token"), str))
        alice_token = alice_login.get("token", "")
        check("Login token is signed format, not a sequential user ID", alice_token.count(".") == 1 and alice_token != "2")

        status, bob_login, _ = request(base_url, "POST", "/login", {"username": "bob", "password": "bobpass"})
        check("Bob can log in", status == 200 and isinstance(bob_login.get("token"), str))
        bob_token = bob_login.get("token", "")

        status, alice_notes, _ = request(base_url, "GET", "/notes", token=alice_token)
        check("Alice can list her own notes", status == 200 and [n["id"] for n in alice_notes] == [1])
        status, bob_notes, _ = request(base_url, "GET", "/notes", token=bob_token)
        check("Bob can list his own notes", status == 200 and [n["id"] for n in bob_notes] == [2])
        status, _, _ = request(base_url, "GET", "/notes/2", token=alice_token)
        check("Alice cannot read Bob's note by guessing its ID", status == 404, f"status={status}")
        status, _, _ = request(base_url, "GET", "/notes/1", token=alice_token)
        check("Alice can read her own note", status == 200)

        status, _, _ = request(base_url, "GET", "/notes")
        check("Unauthenticated notes request is denied", status == 401, f"status={status}")
        status, _, _ = request(base_url, "GET", "/admin/users", token="1")
        check("A made-up/sequential token is rejected", status == 401, f"status={status}")
        tampered = alice_token.rsplit(".", 1)
        bad_signature = ("a" if tampered[1][-1:] != "a" else "b")
        status, _, _ = request(base_url, "GET", "/notes", token=tampered[0] + "." + tampered[1][:-1] + bad_signature)
        check("Tampered token is rejected", status == 401, f"status={status}")
        status, _, _ = request(base_url, "GET", "/admin/users", token=token_for_expired_user())
        check("Expired signed token is rejected", status == 401, f"status={status}")

        status, _, _ = request(base_url, "GET", "/admin/users", token=alice_token)
        check("Normal user cannot access admin route", status == 403, f"status={status}")
        status, users, _ = request(base_url, "GET", "/admin/users", token=(request(base_url, "POST", "/login", {"username": "admin", "password": "admin123"})[1] or {}).get("token"))
        check("Admin can access the admin route", status == 200 and len(users) == 3)
        check("Admin response does not expose password hashes", status == 200 and all("password" not in u for u in users))

        status, _, _ = request(base_url, "POST", "/login", {"username": "' OR 1=1 --", "password": "admin123"})
        check("SQL injection in username is blocked", status == 401, f"status={status}")
        status_missing, missing, _ = request(base_url, "POST", "/login", {"username": "made-up-user", "password": "somepassword"})
        status_wrong, wrong, _ = request(base_url, "POST", "/login", {"username": "alice", "password": "not-the-password"})
        check("Unknown username and wrong password have the same generic error", status_missing == status_wrong == 401 and missing == wrong and missing.get("detail") == "Invalid username or password")

        status, _, _ = request(base_url, "POST", "/register", {"username": "charlie", "password": "charlie-secret"})
        check("Registration works", status == 201, f"status={status}")
        status, charlie_login, _ = request(base_url, "POST", "/login", {"username": "charlie", "password": "charlie-secret"})
        check("Newly registered user can log in", status == 200, f"status={status}")
        charlie_token = (charlie_login or {}).get("token", "")
        status, created, _ = request(base_url, "POST", "/notes", {"title": "Test note", "body": "Private test content"}, token=charlie_token)
        check("Authenticated user can create a note", status == 201 and created.get("id") is not None, f"status={status}")
        status, charlie_notes, _ = request(base_url, "GET", "/notes", token=charlie_token)
        check("New user can list their created note", status == 200 and len(charlie_notes) == 1 and charlie_notes[0]["title"] == "Test note")
        status, _, _ = request(base_url, "POST", "/register", {"username": "charlie", "password": "another-secret"})
        check("Duplicate username is handled without server error", status == 409, f"status={status}")

        status, _, allowed_headers = request(
            base_url, "OPTIONS", "/login",
            extra_headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type"},
        )
        check("Configured local frontend origin is permitted by CORS", allowed_headers.get("Access-Control-Allow-Origin") == "http://localhost:5173")
        status, _, blocked_headers = request(
            base_url, "OPTIONS", "/login",
            extra_headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type"},
        )
        check("Unconfigured external origin is not permitted by CORS", blocked_headers.get("Access-Control-Allow-Origin") != "https://evil.example")

    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)

    print(f"\nResult: {checks - len(failures)}/{checks} checks passed.")
    if failures:
        print("\nSMOKE TESTS FAILED")
        return 1
    print("ALL SMOKE TESTS PASSED")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"TEST HARNESS ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
