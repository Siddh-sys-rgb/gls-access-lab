# GLS Access Lab Security Report

**Institution:** GLS University Institute of Technology  
**Project:** GLS Access Lab — unofficial portfolio demo  

**Overall result:** PASS  
**Run time (UTC):** 2026-09-27T22:56:34+00:00  
**Target:** `http://127.0.0.1:18103` (loopback allowlist enforced)

## Finding

The intentionally vulnerable endpoint reproduces Broken Object Level Authorization (BOLA), mapped to [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html) and [OWASP API1:2023](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/). An authenticated Aarav Shah session can request Meera Patel's numeric object ID and receive HTTP 200. Evidence records owner `Meera Patel` (`meera`) and object ID `3`; note content is `[redacted]`.

The fixed endpoint performs the lookup with both the note ID and the session-derived owner ID. The equivalent cross-owner request returns HTTP 404 with no object data.

## Regression matrix

| Scenario | Endpoint | Expected | Actual | Result |
| --- | --- | ---: | ---: | --- |
| Own note | `vulnerable` | 200 | 200 | PASS |
| Own note | `secure` | 200 | 200 | PASS |
| Other user's note | `vulnerable` | 200 | 200 | PASS |
| Other user's note | `secure` | 404 | 404 | PASS |
| Unauthenticated | `vulnerable` | 401 | 401 | PASS |
| Unauthenticated | `secure` | 401 | 401 | PASS |

## Remediation

Enforce authorization on every object operation. Derive identity from the validated server-side session, then constrain the data query with `WHERE notes.id = ? AND notes.owner_id = ?`. Return the same 404 response for nonexistent and unauthorized IDs to avoid disclosing which objects exist. Apply the same ownership predicate to future update and delete routes, and retain this regression matrix in CI.

## Scope and safety

This report covers a deliberately vulnerable localhost teaching application with fictional data. The audit refuses non-loopback hosts and is not an external target scanner. The vulnerable endpoint must not be copied into production or exposed on a network.
