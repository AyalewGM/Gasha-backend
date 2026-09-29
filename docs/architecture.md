# Gasha production architecture

Gasha is a bank-agnostic fraud intelligence and real-time decision platform. Bank-specific
payloads and integrations belong behind adapters; the core domain never depends on a bank.

## M1 synchronous decision path

Channel/API -> ingestion adapter -> canonical transaction -> intelligence assembly ->
rules/detectors -> risk fusion -> policy decision -> action + reason codes + audit event.

The intelligence contract has four first-class inputs from M1:

1. customer/account intelligence,
2. transaction/velocity intelligence,
3. beneficiary intelligence,
4. sender-beneficiary relationship intelligence.

Network/graph risk is represented in the contract now so graph analytics can evolve without
breaking the transaction or decision APIs.

## Runtime boundaries

- FastAPI: synchronous ingress and decision API.
- PostgreSQL: durable configuration, decisions, rules, watchlists, cases and audit metadata.
- Redis: online velocity and relationship features.
- Kafka: asynchronous event distribution, monitoring, enrichment and feedback.
- Object storage: model and data artifacts.

M1 is a modular monolith with event-driven workers. Domain interfaces are extraction
boundaries; microservices are introduced only when scaling, isolation or ownership requires it.

## Beneficiary intelligence

Internal and external beneficiaries are distinct. Internal beneficiaries may use rich account,
customer, device and transaction history. External beneficiaries are evaluated only from
signals legitimately available to the institution: identifiers, sender relationship/history,
outgoing transfers, returns/reversals, confirmed fraud/watchlist evidence, and future
consortium/payment-network signals.

A graph provider is an interface, not an M1 infrastructure dependency. Neo4j or another graph
store can therefore be added later without coupling the core decision engine to it.

## Non-negotiable decision properties

Every decision is correlated, explainable, versioned and auditable. Model/rule versions and
reason codes travel with the decision. Idempotency, immutable decision persistence, latency
metrics, authentication/authorization, encryption, secrets management and data minimization
are production requirements, not demo extensions.


## Multi-bank configuration boundary

Every canonical transaction carries a tenant identifier. Every fraud decision records the
configuration, policy, rule and model versions that produced it so an investigator can
reproduce the decision later. Decision thresholds are supplied by a validated `DecisionPolicy`
rather than selected by bank-name conditionals. Bank-specific payload mappings and action
integrations remain adapter concerns.

Tenant configuration must be isolated in durable storage and loaded by authenticated tenant
context in production. The current POC request may carry an explicit policy only as a temporary
contract seam; clients must not be allowed to choose their own enforcement policy once the
tenant configuration repository is introduced.

## Internal and external beneficiary data boundary

An internal beneficiary may be enriched with data the tenant is authorized to use from its own
systems. An external beneficiary requires a destination institution identifier and is scored
only from signals observable by the originating institution plus legitimately supplied
payment-rail, consortium, central-bank or other authorized shared intelligence. Gasha does not
infer access to the receiving bank's private ledger, balance, device history or onward movement.

External-beneficiary profiles should use protected/tokenized identifiers where practical and
retain only data required for fraud detection, investigation, audit and applicable retention
policy.
