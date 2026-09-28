#!/usr/bin/env python3
"""End-to-end tests using only the Python standard library."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from http.cookiejar import CookieJar
from pathlib import Path
from typing import Optional
from urllib.error import HTTPError
from urllib.request import HTTPCookieProcessor, Request, build_opener, urlopen

ROOT = Path(__file__).resolve().parent


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class ApiClient:
    def __init__(self, base: str):
        self.base = base
        self.opener = build_opener(HTTPCookieProcessor(CookieJar()))

    def call(self, path: str, method: str = "GET", payload: Optional[dict] = None):
        data = json.dumps(payload).encode() if payload is not None else None
        request = Request(self.base + path, data=data, method=method, headers={"Content-Type": "application/json"})
        try:
            response = self.opener.open(request, timeout=3)
            return response.status, json.loads(response.read()), response.headers
        except HTTPError as error:
            return error.code, json.loads(error.read()), error.headers


class NotesLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.TemporaryDirectory()
        cls.port = free_port()
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.process = subprocess.Popen(
            [sys.executable, str(ROOT / "server.py"), "--port", str(cls.port), "--database", str(Path(cls.tempdir.name) / "test.db")],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        for _ in range(50):
            try:
                if urlopen(cls.base + "/api/health", timeout=.2).status == 200:
                    break
            except OSError:
                time.sleep(.05)
        else:
            raise RuntimeError("test server did not start")

    @classmethod
    def tearDownClass(cls):
        cls.process.terminate()
        cls.process.wait(timeout=5)
        cls.tempdir.cleanup()

    def login(self, username: str) -> ApiClient:
        client = ApiClient(self.base)
        status, body, headers = client.call("/api/login", "POST", {"username": username, "password": f"{username}-demo"})
        self.assertEqual(status, 200)
        self.assertEqual(body["username"], username)
        self.assertIn("HttpOnly", headers["Set-Cookie"])
        self.assertIn("SameSite=Strict", headers["Set-Cookie"])
        return client

    def test_health_and_security_headers(self):
        response = urlopen(self.base + "/api/health")
        self.assertEqual(json.loads(response.read())["bind"], "localhost-only")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])

    def test_authentication_rejects_bad_password_and_client_user_id(self):
        client = ApiClient(self.base)
        status, _, _ = client.call("/api/login", "POST", {"username": "aarav", "password": "wrong"})
        self.assertEqual(status, 401)
        aarav = self.login("aarav")
        status, notes, _ = aarav.call("/api/notes?user_id=2")
        self.assertEqual(status, 200)
        self.assertTrue(notes)
        self.assertTrue(all(note["owner"] == "aarav" for note in notes))

    def test_authorization_matrix(self):
        aarav, meera, anonymous = self.login("aarav"), self.login("meera"), ApiClient(self.base)
        _, aarav_notes, _ = aarav.call("/api/notes")
        _, meera_notes, _ = meera.call("/api/notes")
        own_id, other_id = aarav_notes[0]["id"], meera_notes[0]["id"]
        for endpoint in ("vulnerable", "secure"):
            self.assertEqual(aarav.call(f"/api/{endpoint}/notes/{own_id}")[0], 200)
            self.assertEqual(anonymous.call(f"/api/{endpoint}/notes/{own_id}")[0], 401)
        status, exposed, _ = aarav.call(f"/api/vulnerable/notes/{other_id}")
        self.assertEqual(status, 200)
        self.assertEqual(exposed["owner"], "meera")
        self.assertEqual(exposed["owner_name"], "Meera Patel")
        status, denied, _ = aarav.call(f"/api/secure/notes/{other_id}")
        self.assertEqual(status, 404)
        self.assertNotIn("owner", denied)

    def test_not_found_is_same_for_unknown_and_other_owner(self):
        aarav, meera = self.login("aarav"), self.login("meera")
        _, meera_notes, _ = meera.call("/api/notes")
        other_status, other_body, _ = aarav.call(f"/api/secure/notes/{meera_notes[0]['id']}")
        missing_status, missing_body, _ = aarav.call("/api/secure/notes/999999")
        self.assertEqual((other_status, other_body), (missing_status, missing_body))

    def test_malformed_input_and_oversized_object_id_are_rejected(self):
        request = Request(
            self.base + "/api/login",
            data=b"{not-json",
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with self.assertRaises(HTTPError) as context:
            urlopen(request, timeout=3)
        self.assertEqual(context.exception.code, 400)
        aarav = self.login("aarav")
        status, body, _ = aarav.call("/api/secure/notes/999999999999999999999999")
        self.assertEqual(status, 400)
        self.assertIn("positive integer", body["error"])

    def test_logout_invalidates_session(self):
        aarav = self.login("aarav")
        self.assertEqual(aarav.call("/api/me")[0], 200)
        status, _, headers = aarav.call("/api/logout", "POST")
        self.assertEqual(status, 200)
        self.assertIn("Max-Age=0", headers["Set-Cookie"])
        self.assertEqual(aarav.call("/api/me")[0], 401)


if __name__ == "__main__":
    unittest.main(verbosity=2)
