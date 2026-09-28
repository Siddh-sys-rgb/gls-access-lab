#!/usr/bin/env python3
"""Local allowlisted authorization regression audit for GLS Access Lab."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from http.cookiejar import CookieJar
from pathlib import Path
from typing import List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, HTTPCookieProcessor, Request, build_opener

ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}


@dataclass
class Result:
    scenario: str
    endpoint: str
    expected: int
    actual: int

    @property
    def passed(self) -> bool:
        return self.expected == self.actual


class NoRedirect(HTTPRedirectHandler):
    """Keep an allowlisted loopback request from being redirected off-host."""

    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


class Client:
    def __init__(self, base_url: str, cookies: bool = True):
        self.base_url = base_url.rstrip("/")
        handlers = [NoRedirect()]
        if cookies:
            handlers.append(HTTPCookieProcessor(CookieJar()))
        self.opener = build_opener(*handlers)

    def call(self, path: str, method: str = "GET", body: Optional[dict] = None) -> Tuple[int, object]:
        encoded = json.dumps(body).encode() if body is not None else None
        request = Request(self.base_url + path, data=encoded, method=method, headers={"Content-Type": "application/json"})
        try:
            response = self.opener.open(request, timeout=4)
            return response.status, json.loads(response.read())
        except HTTPError as error:
            raw = error.read()
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                payload = {"error": "non-JSON HTTP response"}
            return error.code, payload


def assert_local(base_url: str) -> None:
    parsed = urlparse(base_url)
    if parsed.scheme != "http" or parsed.hostname not in ALLOWED_HOSTS:
        raise SystemExit("Refusing target: audit permits HTTP loopback hosts only (localhost, 127.0.0.1, ::1).")


def audit(base_url: str) -> Tuple[List[Result], dict]:
    assert_local(base_url)
    aarav, meera, anonymous = Client(base_url), Client(base_url), Client(base_url, cookies=False)
    for client, username, password in ((aarav, "aarav", "aarav-demo"), (meera, "meera", "meera-demo")):
        status, _ = client.call("/api/login", "POST", {"username": username, "password": password})
        if status != 200:
            raise RuntimeError(f"Could not authenticate seeded user {username}: HTTP {status}")
    _, aarav_notes = aarav.call("/api/notes")
    _, meera_notes = meera.call("/api/notes")
    aarav_id, meera_id = aarav_notes[0]["id"], meera_notes[0]["id"]
    matrix = [
        ("Own note", "vulnerable", aarav, aarav_id, 200),
        ("Own note", "secure", aarav, aarav_id, 200),
        ("Other user's note", "vulnerable", aarav, meera_id, 200),
        ("Other user's note", "secure", aarav, meera_id, 404),
        ("Unauthenticated", "vulnerable", anonymous, aarav_id, 401),
        ("Unauthenticated", "secure", anonymous, aarav_id, 401),
    ]
    results, evidence = [], {}
    for scenario, endpoint, client, note_id, expected in matrix:
        status, payload = client.call(f"/api/{endpoint}/notes/{note_id}")
        results.append(Result(scenario, endpoint, expected, status))
        evidence[f"{scenario}:{endpoint}"] = {
            "status": status,
            "object_id": payload.get("id") if isinstance(payload, dict) else None,
            "owner": payload.get("owner") if isinstance(payload, dict) else None,
            "owner_name": payload.get("owner_name") if isinstance(payload, dict) else None,
            "body": "[redacted]" if isinstance(payload, dict) and "body" in payload else None,
        }
    return results, evidence


def report_markdown(base_url: str, results: List[Result], evidence: dict) -> str:
    outcome = "PASS" if all(item.passed for item in results) else "FAIL"
    rows = "\n".join(
        f"| {item.scenario} | `{item.endpoint}` | {item.expected} | {item.actual} | {'PASS' if item.passed else 'FAIL'} |"
        for item in results
    )
    vulnerable = evidence["Other user's note:vulnerable"]
    secure = evidence["Other user's note:secure"]
    return f"""# GLS Access Lab Security Report

**Institution:** GLS University Institute of Technology  
**Project:** GLS Access Lab — unofficial portfolio demo  

**Overall result:** {outcome}  
**Run time (UTC):** {datetime.now(timezone.utc).isoformat(timespec='seconds')}  
**Target:** `{base_url}` (loopback allowlist enforced)

## Finding

The intentionally vulnerable endpoint reproduces Broken Object Level Authorization (BOLA), mapped to [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html) and [OWASP API1:2023](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/). An authenticated Aarav Shah session can request Meera Patel's numeric object ID and receive HTTP {vulnerable['status']}. Evidence records owner `{vulnerable['owner_name']}` (`{vulnerable['owner']}`) and object ID `{vulnerable['object_id']}`; note content is `[redacted]`.

The fixed endpoint performs the lookup with both the note ID and the session-derived owner ID. The equivalent cross-owner request returns HTTP {secure['status']} with no object data.

## Regression matrix

| Scenario | Endpoint | Expected | Actual | Result |
| --- | --- | ---: | ---: | --- |
{rows}

## Remediation

Enforce authorization on every object operation. Derive identity from the validated server-side session, then constrain the data query with `WHERE notes.id = ? AND notes.owner_id = ?`. Return the same 404 response for nonexistent and unauthorized IDs to avoid disclosing which objects exist. Apply the same ownership predicate to future update and delete routes, and retain this regression matrix in CI.

## Scope and safety

This report covers a deliberately vulnerable localhost teaching application with fictional data. The audit refuses non-loopback hosts and is not an external target scanner. The vulnerable endpoint must not be copied into production or exposed on a network.
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit the local GLS Access Lab")
    parser.add_argument("--base-url", default="http://127.0.0.1:8103")
    parser.add_argument("--report", type=Path, help="optional Markdown report output path")
    args = parser.parse_args()
    try:
        results, evidence = audit(args.base_url)
    except (URLError, ConnectionError, RuntimeError) as error:
        raise SystemExit(f"Audit could not run: {error}") from error
    print("Scenario                 Endpoint     Expected  Actual  Result")
    print("-----------------------  -----------  --------  ------  ------")
    for item in results:
        print(f"{item.scenario:<23}  {item.endpoint:<11}  {item.expected:>8}  {item.actual:>6}  {'PASS' if item.passed else 'FAIL'}")
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(report_markdown(args.base_url, results, evidence), encoding="utf-8")
        print(f"\nWrote redacted report: {args.report}")
    if not all(item.passed for item in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
