#!/usr/bin/env python3
"""Local-only Broken Object Level Authorization teaching lab."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import hmac
import json
import mimetypes
import secrets
import sqlite3
import threading
import time
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Iterator, Optional, Tuple, Union
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
SESSION_COOKIE = "gls_access_lab_session"
PASSWORD_ROUNDS = 210_000
SEED_USERS = (("aarav", "Aarav Shah", "aarav-demo"), ("meera", "Meera Patel", "meera-demo"))
SEED_NOTES = (
    ("aarav", "Aarav's placement prep", "Review the fictional portfolio, rehearse the walkthrough, and pack the project notes."),
    ("aarav", "Aarav's security study plan", "Practice SQL authorization patterns and write three regression tests."),
    ("meera", "Meera's campus event ideas", "Draft a fictional event schedule and confirm the student volunteer list."),
    ("meera", "Meera's project retrospective", "Keep the useful alerts, simplify handoffs, and celebrate the team."),
)
LEGACY_FIXTURES = (
    (
        "alice", "aarav", "Aarav Shah", "aarav-demo",
        (
            ("Alice's launch checklist", "Confirm the demo data, rehearse the walkthrough, and bring coffee.", "Aarav's placement prep", "Review the fictional portfolio, rehearse the walkthrough, and pack the project notes."),
            ("Alice's learning plan", "Practice SQL authorization patterns and write three regression tests.", "Aarav's security study plan", "Practice SQL authorization patterns and write three regression tests."),
        ),
    ),
    (
        "bob", "meera", "Meera Patel", "meera-demo",
        (
            ("Bob's weekend idea", "Pack a fictional picnic and visit the imaginary lighthouse.", "Meera's campus event ideas", "Draft a fictional event schedule and confirm the student volunteer list."),
            ("Bob's draft retrospective", "Keep the good alerts, simplify handoffs, and celebrate the team.", "Meera's project retrospective", "Keep the useful alerts, simplify handoffs, and celebrate the team."),
        ),
    ),
)


def password_hash(password: str, salt: Optional[bytes] = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PASSWORD_ROUNDS)
    return f"pbkdf2_sha256${PASSWORD_ROUNDS}${salt.hex()}${digest.hex()}"


def password_matches(password: str, encoded: str) -> bool:
    try:
        algorithm, rounds, salt, expected = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(rounds))
        return hmac.compare_digest(actual.hex(), expected)
    except (ValueError, TypeError):
        return False


class LabState:
    def __init__(self, database: Path):
        self.database = database
        self.sessions: Dict[str, Tuple[int, float]] = {}
        self.session_lock = threading.Lock()
        self.initialize()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.database, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def initialize(self) -> None:
        self.database.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    display_name TEXT,
                    password_hash TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS notes (
                    id INTEGER PRIMARY KEY,
                    owner_id INTEGER NOT NULL REFERENCES users(id),
                    title TEXT NOT NULL,
                    body TEXT NOT NULL
                );
                """
            )
            columns = {row["name"] for row in db.execute("PRAGMA table_info(users)")}
            if "display_name" not in columns:
                db.execute("ALTER TABLE users ADD COLUMN display_name TEXT")
            self.migrate_legacy_fixtures(db)
            if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
                for username, display_name, password in SEED_USERS:
                    db.execute(
                        "INSERT INTO users (username, display_name, password_hash) VALUES (?, ?, ?)",
                        (username, display_name, password_hash(password)),
                    )
                for username, title, body in SEED_NOTES:
                    db.execute(
                        "INSERT INTO notes (owner_id, title, body) "
                        "SELECT id, ?, ? FROM users WHERE username = ?",
                        (title, body, username),
                    )

    def migrate_legacy_fixtures(self, db: sqlite3.Connection) -> None:
        """Rename only the original demo fixtures, retaining user/note IDs in place."""
        for old_username, username, display_name, password, notes in LEGACY_FIXTURES:
            legacy = db.execute("SELECT id FROM users WHERE username = ?", (old_username,)).fetchone()
            if legacy is None:
                db.execute(
                    "UPDATE users SET display_name = COALESCE(display_name, ?) WHERE username = ?",
                    (display_name, username),
                )
                continue
            if db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
                continue
            for old_title, old_body, new_title, new_body in notes:
                db.execute(
                    "UPDATE notes SET title = ?, body = ? WHERE owner_id = ? AND title = ? AND body = ?",
                    (new_title, new_body, legacy["id"], old_title, old_body),
                )
            db.execute(
                "UPDATE users SET username = ?, display_name = ?, password_hash = ? WHERE id = ?",
                (username, display_name, password_hash(password), legacy["id"]),
            )

    def create_session(self, user_id: int) -> str:
        token = secrets.token_urlsafe(32)
        with self.session_lock:
            self.sessions[token] = (user_id, time.time() + 8 * 60 * 60)
        return token

    def session_user_id(self, token: Optional[str]) -> Optional[int]:
        if not token:
            return None
        with self.session_lock:
            session = self.sessions.get(token)
            if not session:
                return None
            user_id, expires = session
            if expires < time.time():
                self.sessions.pop(token, None)
                return None
            return user_id

    def destroy_session(self, token: Optional[str]) -> None:
        if token:
            with self.session_lock:
                self.sessions.pop(token, None)


class LabServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: Tuple[str, int], state: LabState):
        super().__init__(address, LabHandler)
        self.state = state


class LabHandler(BaseHTTPRequestHandler):
    server: LabServer
    server_version = "NotesSecurityLab/1.0"

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"[{self.log_date_time_string()}] {self.client_address[0]} {fmt % args}")

    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'",
        )
        super().end_headers()

    def json_response(self, status: int, payload: Union[dict, list], extra_headers: Optional[Dict[str, str]] = None) -> None:
        encoded = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(encoded)

    def error_json(self, status: int, message: str) -> None:
        self.json_response(status, {"error": message, "status": status})

    def request_json(self) -> Optional[dict]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0 or length > 16_384:
                return None
            value = json.loads(self.rfile.read(length) or b"{}")
            return value if isinstance(value, dict) else None
        except (ValueError, json.JSONDecodeError):
            return None

    def session_token(self) -> Optional[str]:
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        morsel = cookie.get(SESSION_COOKIE)
        return morsel.value if morsel else None

    def authenticated_user(self) -> Optional[sqlite3.Row]:
        user_id = self.server.state.session_user_id(self.session_token())
        if user_id is None:
            return None
        with self.server.state.connect() as db:
            return db.execute("SELECT id, username, display_name FROM users WHERE id = ?", (user_id,)).fetchone()

    def require_user(self) -> Optional[sqlite3.Row]:
        user = self.authenticated_user()
        if user is None:
            self.error_json(HTTPStatus.UNAUTHORIZED, "Authentication required")
        return user

    @staticmethod
    def note_payload(row: sqlite3.Row) -> dict:
        return {
            "id": row["id"], "owner": row["owner"], "owner_name": row["owner_name"],
            "title": row["title"], "body": row["body"],
        }

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/health":
            self.json_response(HTTPStatus.OK, {"status": "ok", "bind": "localhost-only"})
            return
        if path == "/api/me":
            user = self.require_user()
            if user:
                self.json_response(HTTPStatus.OK, {"id": user["id"], "username": user["username"], "display_name": user["display_name"]})
            return
        if path == "/api/notes":
            self.list_own_notes()
            return
        for prefix, secure in (("/api/vulnerable/notes/", False), ("/api/secure/notes/", True)):
            if path.startswith(prefix):
                raw_id = path[len(prefix):]
                if not raw_id.isdigit() or not 0 < int(raw_id) <= 9_223_372_036_854_775_807:
                    self.error_json(HTTPStatus.BAD_REQUEST, "Note ID must be a positive integer")
                    return
                self.get_note(int(raw_id), secure)
                return
        if path == "/":
            self.serve_static("index.html")
            return
        if path in ("/styles.css", "/app.js"):
            self.serve_static(path[1:])
            return
        self.error_json(HTTPStatus.NOT_FOUND, "Not found")

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/login":
            self.login()
            return
        if path == "/api/logout":
            self.server.state.destroy_session(self.session_token())
            cookie = f"{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
            self.json_response(HTTPStatus.OK, {"status": "signed out"}, {"Set-Cookie": cookie})
            return
        self.error_json(HTTPStatus.NOT_FOUND, "Not found")

    def login(self) -> None:
        data = self.request_json()
        if data is None:
            self.error_json(HTTPStatus.BAD_REQUEST, "Expected a small JSON object")
            return
        username = str(data.get("username", "")).strip().lower()
        password = str(data.get("password", ""))
        with self.server.state.connect() as db:
            user = db.execute("SELECT id, username, display_name, password_hash FROM users WHERE username = ?", (username,)).fetchone()
        if user is None or not password_matches(password, user["password_hash"]):
            self.error_json(HTTPStatus.UNAUTHORIZED, "Invalid username or password")
            return
        token = self.server.state.create_session(user["id"])
        cookie = f"{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800"
        self.json_response(HTTPStatus.OK, {"id": user["id"], "username": user["username"], "display_name": user["display_name"]}, {"Set-Cookie": cookie})

    def list_own_notes(self) -> None:
        user = self.require_user()
        if user is None:
            return
        with self.server.state.connect() as db:
            rows = db.execute(
                "SELECT notes.id, users.username AS owner, users.display_name AS owner_name, title, body FROM notes "
                "JOIN users ON users.id = notes.owner_id WHERE notes.owner_id = ? ORDER BY notes.id",
                (user["id"],),
            ).fetchall()
        self.json_response(HTTPStatus.OK, [self.note_payload(row) for row in rows])

    def get_note(self, note_id: int, secure: bool) -> None:
        user = self.require_user()
        if user is None:
            return
        with self.server.state.connect() as db:
            if secure:
                # Correct: object lookup and authorization happen in the same query.
                row = db.execute(
                    "SELECT notes.id, users.username AS owner, users.display_name AS owner_name, title, body FROM notes "
                    "JOIN users ON users.id = notes.owner_id WHERE notes.id = ? AND notes.owner_id = ?",
                    (note_id, user["id"]),
                ).fetchone()
            else:
                # INTENTIONALLY VULNERABLE FOR THIS LOCAL LAB: ownership is never checked.
                row = db.execute(
                    "SELECT notes.id, users.username AS owner, users.display_name AS owner_name, title, body FROM notes "
                    "JOIN users ON users.id = notes.owner_id WHERE notes.id = ?",
                    (note_id,),
                ).fetchone()
        if row is None:
            self.error_json(HTTPStatus.NOT_FOUND, "Note not found")
            return
        self.json_response(HTTPStatus.OK, self.note_payload(row))

    def serve_static(self, filename: str) -> None:
        path = STATIC / filename
        try:
            data = path.read_bytes()
        except FileNotFoundError:
            self.error_json(HTTPStatus.NOT_FOUND, "Not found")
            return
        media_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", f"{media_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the local Notes authorization lab")
    parser.add_argument("--port", type=int, default=8103, help="localhost port (default: 8103)")
    parser.add_argument("--database", type=Path, default=ROOT / "data" / "notes.db")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if not 0 <= args.port <= 65535:
        raise SystemExit("--port must be between 0 and 65535")
    state = LabState(args.database.resolve())
    server = LabServer(("127.0.0.1", args.port), state)
    host, port = server.server_address
    print(f"GLS Access Lab: http://{host}:{port}", flush=True)
    print("Local educational use only. Never expose this intentionally vulnerable app publicly.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping lab.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
