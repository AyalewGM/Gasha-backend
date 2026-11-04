# Issue #49: bounded evidence lifecycle transition proposal kernel

This internal module is **not** a trusted evidence store, authorized stage gate, bank audit ledger or completed PoC requirement. It builds on the three-file **merged, inactive PR #67** evidence identity kernel and leaves merged PR #54 untouched and non-authoritative.

The new lifecycle object reconstructs a frozen, packet-digest-bound sequence of *proposed* transitions: submit each evidence record, verify against an injected **server-side trusted artifact reader**, independently approve a complete verified packet, revoke evidence and revoke approval. Typed tenant-scoped capabilities use TrustedPrincipal and distinct bank authority-plane labels (evidence.submit, evidence.verify, stage.approve, evidence.revoke, approval.revoke), without allowing legacy evidence.create/evidence.approve permissions to substitute, credential expiry, and pseudonymous audit actors. Proposals reject duplicate or out-of-order events, missing verification, **packet-wide collector/verifier role overlap** (a collector of any record cannot verify any record), collector/verifier self-approval, changed packet versions, missing/mismatching artifacts, expired/future evidence and unauthorized tenants. Verification checks submission, revocation, duplicate state, capabilities and whole-packet duties **before invoking the privileged artifact reader**. UTC timestamps normalize before ordering. Revocation is irreversible for the same immutable packet; new evidence needs a new packet identity. These checks can be tested without bank data or transactions.

## Critical authority boundary

- A TrustedPrincipal **must** come from a Bank-provisioned authenticated verifier, not headers/JSON. A caller can construct one in Python; this module cannot attest it.
- TrustedArtifactReader **must** read the actual immutable referenced artifact from an approved source using trusted installation-specific permissions. A caller-provided digest or injected mock is not independent verification. Only the *adapter* can establish artifact authenticity and source lineage; the kernel compares its result to the expected digest.
- EvidenceLifecycle and its events are constructible locally. **Their shape, successful transition proposal, and packet digest prove no authenticity whatsoever.** Never accept caller-supplied histories as an authority source. Do not feed these values into #54 readiness or CBE approval, or expose them on protected APIs.
- The next write path must use a Bank-owned PostgreSQL append-only schema, separate migrator/runtime roles, signed/authorized principals, row-level scope checks, transaction-level revision/fencing, mandatory redacted audit committed in the **same transaction**, immutable artifact lineage, independent reviewer controls and serializable revoke/evaluate operations. If audit cannot commit, no evidence/approval transition may persist. Readiness must fail closed if registry unavailable or status changes during evaluation.
- Bank-specific installation permission, reviewer accreditation, independent-human approval, security/privacy/compliance vetoes, bank inline authorization, concurrent DB races, credential revocation, installed proxy/IdP verification and CBE acceptance are **out of scope**. The module never produces ready, enforcement_activated or bank release authority.

This draft is an implementation of bounded domain transition guards against merged, inert #67; it grants no Bank authority. Full Issue #49 remains blocked; PO → Security/Architecture → Independent QA → Unified Lead must review the exact SHA before inactive internal integration. Previously merged PRs #52/#53 are untouched.


## Transition replay type-integrity hardening (bounded #49 follow-up)

The history replay path reconstructs every retained `EvidenceTransition`
before evaluating any action. A frozen Python dataclass is not a trust boundary:
`object.__setattr__` can replace a typed action with its equal raw `StrEnum`
string (for example `"verify"`), or replace the clock/actor/digest/UUID,
and `object.__delattr__` can remove a required attribute. Without revalidation,
the raw string compared equal in a membership test but failed the enum identity
branches, allowing an invalid transition to be interpreted as a revocation.
The corrected replay rejects those histories before proposal or artifact access.
Regression tests cover malformed/deleted fields and an unchanged valid lifecycle.

This is **only** a defensive check of caller-supplied, in-process synthetic
transition history. It authenticates neither principals nor artifacts and does
not provide a trusted append-only ledger, independent verification, Bank
approval, or readiness decision. No changes to merged #54, #52, #53, API,
database, Kafka, frontend, shadow operation, payments or enforcement.
