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
- newly discovered consequential routes automatically enter mediation, hardened-enforcement, revocation, stop, restart-latch, partition, out-of-band intervention, and secondary-containment attack sets;
- queued, cached-session, retry, in-flight, background, raw-credential, host-admin, direct, subprocess, and delegated routes are represented in the reference action inventory;
- stop persistence now includes an explicit negative actor-reset test and a separately approved, attributable human-reset path;
- observation testing covers collector outage, sequence gaps, forbidden audit sampling, disagreement, and observer failure;
- A4/A5 assurance probes require non-vacuous evidence, independent evidence references, bounded timing/residual semantics, fresh-environment reconstruction, transcript substitution rejection, and targeted mutation rejection;
- timing/count fields reject Python boolean-as-integer smuggling, backwards detection clocks, malformed sampling rates, and non-collection evidence references;
- A5 critical observation requires enough distinct evidence references to support the declared independent-observer count;
- A5 emergency recovery requires distinct authenticated recovery operators, separation of duties, reviewed evidence, attributable authorization, and a retained recovery evidence reference;
- common-mode resilience checks the declared dependency graph for an intervention dependency outside the actor dependency set instead of trusting a self-declared independence flag alone;
- probe selection rejects duplicate and unknown requirement IDs, and probe capability declarations are checked against the adapter methods they actually exercise so readiness cannot silently omit a required surface;
- full CI now runs automatically on `main` pushes across Ubuntu, macOS, and Windows on Python 3.10 and 3.13.

These tests strengthen the semantics of the reference harness; they do not turn a reference-target PASS into a conformance claim for an external deployment.

The next validation milestone is portability: run the same semantics through independently designed real deployments without weakening acceptance criteria.
