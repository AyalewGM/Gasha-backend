# Gasha Backend

Production backend for **Gasha**, a bank-agnostic real-time fraud intelligence and decision platform.

## M1

M1 establishes the canonical transaction contract and beneficiary-aware real-time decision pipeline. Bank adapters stay outside fraud-domain logic, and the synchronous decision path remains independent from background monitoring.

### Local development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
uvicorn gasha.api.main:app --reload
pytest
```

See `docs/architecture.md` for the production direction.
