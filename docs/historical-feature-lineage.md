# Issue #48 — historical point-in-time signal lineage (inactive kernel)

This is a **synthetic, untrusted input-validation foundation**, not evidence that the Bank supplied a dataset, source attestations or a historical decision clock. It is **not wired** to the current historical replay path, protected API, reporting, stage approval or merged #54 readiness evaluator. A successful check must not be used as a readiness signal.

## Contract

Each historical risk snapshot needs the original transaction event UUID, tenant reference, dataset SHA-256 digest, cohort/mapping/configuration/policy/signal-policy versions and a **separately documented historical decision cutoff**. The cutoff is not replay wall-clock time and must be agreed per Bank dataset/use case (including any permitted ingestion delay). Source observations bind one of the eight existing IntelligenceSnapshot risk fields to a source/version, as-of and available-at instant, and numeric value. Both times must be on or before the explicitly supplied decision cutoff, with as-of <= available-at. The Bank has to attest the original source and clock; this code only checks caller-provided statements.

All times are normalized to UTC *before comparison and hashing*, including daylight-saving repeated local times. Every risk field must be explicitly represented; missing/optional telemetry has value=None and a canonical reason, **not an invented 0.0 risk**. An incomplete envelope can be counted for quality/coverage, but assert_historical_snapshot_bound refuses to use it with the existing numeric-only decision input. The same guard refuses wrong tenant/event/dataset/event time, modified score or ambiguous duplicate signal names. It is a validation barrier only and does not guarantee historical source provenance.

The deterministic SHA-256 content fingerprint binds source version, exact historical timing, and all policy/mapping/cohort/dataset references. It is **not** a cryptographic attestation or bank approval. Neither labels nor post-event outcomes may be inserted as feature sources. No real customer/account/device values belong in provenance IDs or tests.

## Post-construction mutation boundary

Although lineage dataclasses are frozen, caller code can bypass that protection with
object.__setattr__. Before fingerprinting, reporting unavailable telemetry or
binding a synthetic IntelligenceSnapshot, the kernel now reconstructs and
revalidates a detached copy of the full envelope and its signal records. Invalid
post-cutoff observations, invalid clocks/sources, changed signal shapes and missing
fields fail closed even after initially valid construction. Deleted required slotted\nfields (including the whole signals tuple or nested signal members) raise the fixed,\nredacted HistoricalLineageRejected at each public consumption point, rather than\nan AttributeError that a future adapter could mishandle. Valid value changes yield
a different content fingerprint and must still match the decision input. This is
defense-in-depth against malformed caller-held objects; it is **not** source
authentication, Bank attestation, or replay integration.

## Still required for Issues #48 and #49

Bank-approved field mappings and source/decision cutoff semantics; secure collection of source timestamps; independently attested immutable dataset and model lineage; verified label maturity and time-separated cohort selection; missing-data quality report and clear signal coverage; integration into a fail-closed historical adapter; independent Fraud/Security/QA exact-SHA review and CBE acceptance. The current numeric-only replay must **not** be described as point-in-time-safe merely because this module exists. There are no bank data, deployment or payment interventions in this patch.
