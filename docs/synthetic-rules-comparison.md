# Synthetic Gasha rules comparison

Run from the backend checkout after installing the package.

```bash
python -m gasha.poc.synthetic_rules_comparison --alert-budget 4
pytest -q tests/test_synthetic_rules_comparison.py
```

The command replays eight fixed synthetic transactions through the existing
deterministic Gasha scorer. The baseline supplies transaction risk only. The
candidate adds synthetic device-session risk to Gasha's full signal fusion.
Both configurations select the same number of highest-scoring events, breaking
ties by event time and identifier. This quota measures ranking performance
independent of configured decision-action thresholds.

Selection includes all eight events. The comparison consumes only labels
confirmed by the fixed cutoff when computing confusion counts and rates.
An alert with an unavailable label still uses one slot. The JSON contains
each denominator, any undefined reason, and hashes that identify the data,
replay evaluations, and complete comparison. It omits execution timings
so repeated runs produce matching report bytes.

The expected budget-four result is illustrative. The constructed inputs
exercise both missed fraud and false positives. Measured performance on
Dashen data and a same-cohort comparison against NetGuardians require
authorized outcomes, feature lineage, and a jointly agreed alert budget.
