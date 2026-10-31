"""Auth for the web app: local users, roles, sessions.

- Passwords: PBKDF2-HMAC-SHA256, 200k iterations, per-user salt (stdlib only).
- Sessions: random tokens in a `sessions` table, HttpOnly cookie, 7-day expiry.
- Roles: `admin` sees everything and manages users; `user` is scoped to
  their own business.

Honest limits: this is a small-team v1 — no 2FA, no password reset flow
(an admin can set a new password), no brute-force lockout yet.
"""
from __future__ import annotations

import hashlib
import secrets
import sqlite3
import time

USERS_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT UNIQUE NOT NULL,
  pwd_hash      TEXT NOT NULL,
  salt          TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'user',
  business_id   TEXT NOT NULL DEFAULT '',
  business_name TEXT NOT NULL DEFAULT '',
  active        INTEGER NOT NULL DEFAULT 1,
  created_at    REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token      TEXT PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
"""

ITERATIONS = 200_000
SESSION_TTL = 7 * 24 * 3600


def hash_password(password: str, salt_hex: str | None = None) -> tuple[str, str]:
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)
    return dk.hex(), salt.hex()


def verify_password(password: str, salt_hex: str, pwd_hash: str) -> bool:
    calc, _ = hash_password(password, salt_hex)
    return secrets.compare_digest(calc, pwd_hash)


def valid_username(name: str) -> bool:
    import re
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]{3,30}", name or ""))


class AuthStore:
    def __init__(self, path: str):
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(USERS_SCHEMA)
        self.db.execute("PRAGMA foreign_keys = ON")

    def user_count(self) -> int:
        return self.db.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]

    def admin_count(self) -> int:
        row = self.db.execute(
            "SELECT COUNT(*) c FROM users WHERE role='admin' AND active=1"
        ).fetchone()
        return row["c"]

    def create_user(self, username: str, password: str, role: str = "user",
                    business_id: str = "", business_name: str = "") -> int:
        if not valid_username(username):
            raise ValueError("username must be 3-30 chars: letters, digits, _ . -")
        if len(password) < 8:
            raise ValueError("password must be at least 8 characters")
        if role not in ("admin", "user"):
            raise ValueError("role must be admin or user")
        pwd_hash, salt = hash_password(password)
        try:
            cur = self.db.execute(
                """INSERT INTO users
                   (username, pwd_hash, salt, role, business_id, business_name, created_at)
                   VALUES (?,?,?,?,?,?,?)""",
                (username, pwd_hash, salt, role, business_id, business_name,
                 time.time()))
        except sqlite3.IntegrityError:
            raise ValueError(f"username '{username}' is already taken")
        self.db.commit()
        return cur.lastrowid

    def get_by_username(self, username: str) -> dict | None:
        row = self.db.execute(
            "SELECT * FROM users WHERE username=?", (username,)).fetchone()
        return dict(row) if row else None

    def get_by_id(self, user_id: int) -> dict | None:
        row = self.db.execute(
            "SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        return dict(row) if row else None

    def authenticate(self, username: str, password: str) -> dict | None:
        u = self.get_by_username(username)
        if not u or not u["active"]:
            return None
        if not verify_password(password, u["salt"], u["pwd_hash"]):
            return None
        return u

    def list_users(self) -> list[dict]:
        rows = self.db.execute(
            "SELECT id, username, role, business_id, business_name, active,"
            " created_at FROM users ORDER BY id").fetchall()
        return [dict(r) for r in rows]

    def set_active(self, user_id: int, active: bool) -> None:
        self.db.execute("UPDATE users SET active=? WHERE id=?",
                        (1 if active else 0, user_id))
        self.db.commit()

    def set_password(self, user_id: int, password: str) -> None:
        if len(password) < 8:
            raise ValueError("password must be at least 8 characters")
        pwd_hash, salt = hash_password(password)
        self.db.execute("UPDATE users SET pwd_hash=?, salt=? WHERE id=?",
                        (pwd_hash, salt, user_id))
        self.db.commit()

    def delete_user(self, user_id: int) -> None:
        self.db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        self.db.execute("DELETE FROM users WHERE id=?", (user_id,))
        self.db.commit()

    def create_session(self, user_id: int) -> str:
        token = secrets.token_hex(32)
        self.db.execute(
            "INSERT INTO sessions (token, user_id, expires_at) VALUES (?,?,?)",
            (token, user_id, time.time() + SESSION_TTL))
        self.db.commit()
        return token

    def get_session_user(self, token: str) -> dict | None:
        if not token:
            return None
        row = self.db.execute(
            """SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
               WHERE s.token=? AND s.expires_at > ? AND u.active=1""",
            (token, time.time())).fetchone()
        return dict(row) if row else None

    def delete_session(self, token: str) -> None:
        self.db.execute("DELETE FROM sessions WHERE token=?", (token,))
        self.db.commit()

    def prune_sessions(self) -> None:
        self.db.execute("DELETE FROM sessions WHERE expires_at <= ?",
                        (time.time(),))
        self.db.commit()
