"""SecureNotes API - Week 13 security lab (fixed version).

Run from this directory with:
    uvicorn app.main:app --reload

Set SECURENOTES_SECRET_KEY to a long random value for stable, production-like
signing. In development, a random per-process key is generated automatically.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import time
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger("securenotes")

# --- app + configuration ---------------------------------------------------
app = FastAPI(title="SecureNotes API", version="1.1")

_SECRET_KEY = os.getenv("SECURENOTES_SECRET_KEY")
if not _SECRET_KEY:
    if os.getenv("SECURENOTES_ENV", "development").strip().lower() == "production":
        raise RuntimeError("SECURENOTES_SECRET_KEY must be set in production")
    # Safe for local lab use; tokens are invalidated when the process restarts.
    _SECRET_KEY = secrets.token_urlsafe(48)
    logger.warning(
        "SECURENOTES_SECRET_KEY is not set; using a temporary development key."
    )
SECRET_KEY = _SECRET_KEY.encode("utf-8")
TOKEN_TTL_SECONDS = 60 * 60
PASSWORD_HASH_ITERATIONS = 600_000

_default_origins = "http://localhost:5173,http://127.0.0.1:5173"
_allowed_origins = os.getenv("SECURENOTES_ALLOWED_ORIGINS", _default_origins)
ALLOWED_ORIGINS = [
    origin.strip().rstrip("/")
    for origin in _allowed_origins.split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


# --- password helpers ------------------------------------------------------
def hash_password(password: str) -> str:
    """Return a salted PBKDF2-HMAC-SHA256 password hash."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_HASH_ITERATIONS
    )
    return "pbkdf2_sha256${}${}${}".format(
        PASSWORD_HASH_ITERATIONS, salt.hex(), digest.hex()
    )


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password using constant-time digest comparison."""
    try:
        algorithm, iterations_text, salt_hex, expected_hex = stored_hash.split("$")
        iterations = int(iterations_text)
        if algorithm != "pbkdf2_sha256" or not 100_000 <= iterations <= 2_000_000:
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(expected_hex)
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, iterations
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError, AttributeError):
        return False


# Used for a dummy hash so a missing username does not skip the expensive
# password-hash verification entirely (reduces username-enumeration timing).
_DUMMY_PASSWORD_HASH = hash_password("not-a-real-user-password")


# --- signed, expiring bearer tokens ---------------------------------------
def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def create_token(user_id: int) -> str:
    payload = _b64url_encode(
        json.dumps(
            {"sub": user_id, "exp": int(time.time()) + TOKEN_TTL_SECONDS},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )
    signature = _b64url_encode(
        hmac.new(SECRET_KEY, payload.encode("ascii"), hashlib.sha256).digest()
    )
    return f"{payload}.{signature}"


def get_token_user_id(token: str) -> Optional[int]:
    """Return the subject only when a bearer token is valid and unexpired."""
    try:
        if not isinstance(token, str) or token.count(".") != 1:
            return None
        payload_part, supplied_signature = token.split(".", 1)
        if not payload_part or not supplied_signature or not supplied_signature.isascii():
            return None
        expected_signature = _b64url_encode(
            hmac.new(
                SECRET_KEY, payload_part.encode("ascii"), hashlib.sha256
            ).digest()
        )
        if not hmac.compare_digest(supplied_signature, expected_signature):
            return None
        payload = json.loads(_b64url_decode(payload_part).decode("utf-8"))
        user_id = payload.get("sub")
        expires_at = payload.get("exp")
        if type(user_id) is not int or type(expires_at) is not int:
            return None
        if expires_at <= int(time.time()):
            return None
        return user_id
    except (ValueError, TypeError, UnicodeError, json.JSONDecodeError):
        return None


# --- database (SQLite, created fresh on startup) --------------------------
db = sqlite3.connect(":memory:", check_same_thread=False)
db.row_factory = sqlite3.Row


def init_db() -> None:
    db.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            FOREIGN KEY (owner_id) REFERENCES users(id)
        );
        """
    )
    # Keep the seeded credentials used by the lab, but store only password hashes.
    db.execute(
        "INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
        ("admin", hash_password("admin123"), 1),
    )
    db.execute(
        "INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
        ("alice", hash_password("alicepass"), 0),
    )
    db.execute(
        "INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
        ("bob", hash_password("bobpass"), 0),
    )
    db.execute(
        "INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
        (2, "Alice diary", "Alice secret note"),
    )
    db.execute(
        "INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
        (3, "Bob plans", "Bob secret note"),
    )
    db.commit()


init_db()


# --- request models --------------------------------------------------------
class Credentials(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=1024)


class NewNote(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1, max_length=10_000)


# --- authentication dependency --------------------------------------------
def current_user(authorization: Optional[str] = Header(default=None)) -> sqlite3.Row:
    """Authenticate a signed bearer token and return its user row."""
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    scheme, separator, token = authorization.partition(" ")
    if not separator or scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user_id = get_token_user_id(token.strip())
    if user_id is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


# --- safe error handling ---------------------------------------------------
@app.exception_handler(Exception)
async def handle_unexpected_error(request, exc):
    # Details stay in server logs; never send stack traces or internal errors to clients.
    logger.exception(
        "Unhandled exception while processing %s %s",
        request.method,
        request.url.path,
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )


# --- routes ----------------------------------------------------------------
@app.post("/register", status_code=201)
def register(creds: Credentials):
    username = creds.username.strip()
    if not username:
        raise HTTPException(status_code=422, detail="Username must not be blank")
    try:
        password_hash = hash_password(creds.password)
        db.execute(
            "INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)",
            (username, password_hash),
        )
        db.commit()
    except sqlite3.IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Username is already registered")
    return {"message": "User created"}


@app.post("/login")
def login(creds: Credentials):
    username = creds.username.strip()
    # Parameterized query: user input is always data, never SQL syntax.
    row = db.execute(
        "SELECT id, password FROM users WHERE username = ?", (username,)
    ).fetchone()
    if row is None:
        verify_password(creds.password, _DUMMY_PASSWORD_HASH)
        raise HTTPException(status_code=401, detail="Invalid username or password")
    if not verify_password(creds.password, row["password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return {"token": create_token(row["id"]), "token_type": "bearer", "expires_in": TOKEN_TTL_SECONDS}


@app.get("/notes")
def list_my_notes(user: sqlite3.Row = Depends(current_user)):
    rows = db.execute(
        "SELECT id, owner_id, title, body FROM notes WHERE owner_id = ? ORDER BY id",
        (user["id"],),
    ).fetchall()
    return [dict(row) for row in rows]


@app.get("/notes/{note_id}")
def get_note(note_id: int, user: sqlite3.Row = Depends(current_user)):
    # Include ownership in the query so an ID alone can never grant access.
    row = db.execute(
        "SELECT id, owner_id, title, body FROM notes WHERE id = ? AND owner_id = ?",
        (note_id, user["id"]),
    ).fetchone()
    if row is None:
        # Same response for missing and someone else's notes to avoid ID probing.
        raise HTTPException(status_code=404, detail="Note not found")
    return dict(row)


@app.post("/notes", status_code=201)
def create_note(note: NewNote, user: sqlite3.Row = Depends(current_user)):
    cur = db.execute(
        "INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
        (user["id"], note.title, note.body),
    )
    db.commit()
    return {"id": cur.lastrowid, "title": note.title}


@app.get("/admin/users")
def list_all_users(user: sqlite3.Row = Depends(current_user)):
    # A failed/missing authentication check never proceeds to the protected action.
    if not user["is_admin"]:
        raise HTTPException(status_code=403, detail="Admins only")
    # Never return password hashes, even to an administrator.
    rows = db.execute("SELECT id, username, is_admin FROM users ORDER BY id").fetchall()
    return [dict(row) for row in rows]


@app.get("/")
def home():
    return {"service": "SecureNotes API", "docs": "/docs"}
