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
