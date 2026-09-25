# Validation status — full reference harness

Current reference-harness validation:

- All **42 A1–A5 normative families** have executable semantic probes.
- The complete reference target passes **42/42**.
- Each family has a paired deliberate control-removal mutation; **42/42 mutations are detected** by the matching probe.
- `doctor --level A5` reports the reference target ready with zero capability blockers.
- A1–A4 remain executable cumulative subsets at 8, 21, 28, and 35 families.

## Adversarial probe hardening

The reference harness also includes regression tests aimed specifically at false-PASS shortcuts:

- always-deny implementations cannot satisfy controls that require a functional positive path;
- `admitted` / `denied` claims are reconciled with authoritative resource-side state;
- empty or non-useful evidence cannot satisfy accountability/integrity families;
- one-time approvals and aggregate delegation budgets are exercised under concurrent races;
- newly discovered consequential routes automatically enter mediation, revocation, stop, restart-latch, partition, out-of-band intervention, and secondary-containment attack sets;
- queued, cached-session, retry, in-flight, background, raw-credential, host-admin, direct, subprocess, and delegated routes are represented in the reference action inventory;
- stop persistence now includes an explicit negative actor-reset test and a separately approved, attributable human-reset path;
- observation testing covers collector outage, sequence gaps, forbidden audit sampling, disagreement, and observer failure;
- A4/A5 assurance probes require non-vacuous evidence, independent evidence references, bounded timing/residual semantics, fresh-environment reconstruction, and targeted mutation rejection;
- probe capability declarations are checked against the adapter methods they actually exercise so readiness cannot silently omit a required surface.

These tests strengthen the semantics of the reference harness; they do not turn a reference-target PASS into a conformance claim for an external deployment.

The next validation milestone is portability: run the same semantics through independently designed real deployments without weakening acceptance criteria.
