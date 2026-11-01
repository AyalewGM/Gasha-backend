# Issue #45 — protected analyst case-history read contract (internal v0.1)

**Status:** draft, opt-in, read-only API extension. This is not a bank-approved
identity, case-management, analyst UAT, stage-readiness, or payment-action API.

## Request

```http
GET /v1/tenants/{tenant_id}/cases/{case_id}/history
Authorization: Bearer <bank-verified credential>
```

- `tenant_id` is a **selector**, not a trusted role or tenant claim. It must
  exactly match an authorized tenant in the server-verified principal.
- `case_id` must be a UUID and is not authorization. The installed case reader
  must look it up under the selected tenant and check tenant ownership.
- Required capability: **`case.read`**, independently scoped from case create,
  triage, assign, disposition, correction, feedback and administrator actions.
- The shared protected FastAPI ingress authenticates **before path or body
  validation**, including under the supported ASGI `root_path`. Client-supplied
  tenant/role/forwarding headers never establish identity or route authority.
- There are **no bank credentials or reader in the default app**. The
  `case_history_reader` port must be explicitly installed by a trusted server
  composition, not a browser, request body, worker claim or environment flag
  accepted as authorization.

## Response on an authorized, existing case (200)

```json
{
  "case_id": "00000000-0000-4000-8000-000000000001",
  "enforcement_activated": false,
  "events": [
    {
      "revision": 1,
      "previous_revision": null,
      "operation": "create",
      "recorded_at": "2026-11-01T12:00:00+00:00",
      "reason_code": "source_evaluation",
      "disposition": null,
      "actor_ref": "<64 lowercase hex characters>",
      "assignee_ref": null,
      "source_event_id": "00000000-0000-4000-8000-000000000002",
      "source_context_ref": "<64 lowercase hex characters>",
      "bank_execution": "unknown"
    }
  ]
}
```

All timestamps are normalized UTC instants; revisions and source references
must remain consistent across the history. Actor and context references are
pseudonymous; no customer names, raw beneficiary/account identifiers, case
free-text, credential, or internal idempotency/command hashes are returned.

`bank_execution="unknown"` is not proof of a Bank action. A Gasha alert or
recommendation never establishes executed HOLD/BLOCK, settled outcome or saved
funds. **No endpoint on this contract mutates a case, rule, model, outcome,
payment, or readiness stage.**

## Fail-closed HTTP behavior

| Condition | HTTP |
| --- | --- |
| Missing, malformed, revoked or expired bearer credential | 401 |
| Identity verifier outage or unavailable mandatory security audit | 503 |
| Authenticated principal missing `case.read` capability | 403 |
| Wrong tenant (even with spoofed headers) | 404 |
| Authorized but absent case | 404 |
| Reader not installed; storage/reader outage or unsafe/cross-scope history | 503 |
| Authenticated but invalid case UUID | 422 |

The authenticated route records redacted authorization and terminal
success/failure/not-found events. Failed authorization or failed audit prevents
data access. Final-success audit failure prevents returning case data.

## Implementation and evidence boundaries

The reader protocol is `TrustedCaseHistoryReader.history(principal, tenant_id,
case_id, at)` and should be backed by the existing reviewed
`PostgresCaseTimelineService.history` (or an independently accepted equivalent)
with tenant-scoped database permissions, validated historical source/evaluation
links, fresh credential/capability checks and operational failure handling.
The protected endpoint additionally validates the returned immutable history,
opaque identifiers, UTC-monotonic timestamps, and the canonical case lifecycle
before serialization. The same pure validator is reused by the PostgreSQL
adapter and the case proposal kernel: CREATE must be first; transitions,
reason/disposition, assignee placement and corrections must be semantically
valid. An invalid typed reader history returns redacted 503 with a failed
audit event, never analyst evidence.

Existing `tests/test_api_case_history.py` cases execute missing/revoked/expired
and provider-down credentials, cross-tenant/capability denial, proxy/header
spoofing, audit failure before DB access, failure/unsafe-history 503, and
read-only success. The installed protected-API CI matrix includes those tests.
This is **synthetic test evidence**, not a bank IdP, proxy, live PostgreSQL
composition, or CBE UAT.

The Frontend must not treat a 200 result as case assignment authority or expose
case mutation actions without separate protected capabilities and mutation
contracts. No browser claim, case response, risk-list digest or offline #54
readiness report may authorize stage promotion or payment enforcement.

**Outstanding:** independent exact-commit Security/Architecture and QA review;
Bank-selected IdP/revocation and secure ingress; production deployment of
the trusted case reader; authenticated analyst queue and case mutations;
atomic outcome/audit contracts; Bank UAT and release authorization.
