# Validation status — full reference harness

Current reference-harness validation:

- All **42 A1–A5 normative families** have executable semantic probes.
- The complete reference target passes **42/42**.
- Each family has a paired deliberate control-removal mutation; **42/42 mutations are detected** by the matching probe.
- `doctor --level A5` reports the reference target ready with zero capability blockers.
- A1–A4 remain executable cumulative subsets at 8, 21, 28, and 35 families.

The next validation milestone is portability: run the same semantics through independently designed real deployments without weakening acceptance criteria.
