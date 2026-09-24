# Full A1–A5 reference harness

Asimov v0.2 implements executable semantic probes for all **42 normative families**.

## Coverage

| Profile | Cumulative families | Executable reference probes |
|---|---:|---:|
| A1 — Observable | 8 | 8 |
| A2 — Controlled | 21 | 21 |
| A3 — Supervised | 28 | 28 |
| A4 — Hardened | 35 | 35 |
| A5 — Critical | 42 | 42 |

Every family has a paired deliberate control-removal mutation. The reference target must pass the complete probe and the corresponding mutated target must fail it.

## Run

```bash
python -m asimov_conformance reference-probes
python -m asimov_conformance reference-mutations
python -m asimov_conformance doctor --level A5
```

Lower-profile subsets remain directly executable through the probe API.

## A4 — Hardened

The Hardened tranche adds:

- independent corroboration for high-consequence observations;
- enforcement against hostile actor/orchestrator routes;
- revocation under partition and degraded connectivity;
- common-mode supervision failure analysis;
- delegation under churn, restart, partition, and orphaning;
- out-of-band operator intervention;
- cryptographically bound and externally checkpointed assessment evidence.

## A5 — Critical

The Critical tranche adds:

- domain-critical transition observation;
- independent defense in depth for critical effects;
- secondary emergency containment;
- independent adversarial assurance of supervision;
- constrained critical delegation across trust boundaries;
- redundant human emergency authority and governed recovery;
- independent assessment with durable evidence escrow.

## Portability

The reference harness establishes executable semantics. The next milestone is running these same requirements against independently designed external deployments through thin adapters while keeping acceptance criteria unchanged.
