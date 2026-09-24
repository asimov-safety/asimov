# Asimov
## Seven contracts. Testable control. Accountable autonomy.

**Founding working draft · 0.2.0-draft.1 · September 24, 2026**

Asimov is a proposed free, open-source safety standard and conformance suite defining the minimum technical conditions under which autonomous AI can remain under accountable human control.

**Start with [ASIMOV-CORE-0.2.md](ASIMOV-CORE-0.2.md).**

The Seven Contracts are **Observable Agency, Mediated Action, Revocable Authority, Protected Oversight, Bounded Delegation, Human Authority, and Accountability**. They describe properties of the deployment around an AI, not promises that the model must voluntarily obey.

## Current state

| Artifact | v0.2 state |
|---|---|
| Core specification | 42 cumulative families across A1–A5 |
| A0–A5 profiles | Draft-evaluable; A4 Hardened and A5 Critical are newly specified |
| Test catalog | Property, setup, procedure, acceptance, evidence, limits, method class and automation class for every family |
| Framework abstraction | `ConformanceAdapter` protocol; no framework is required |
| Python definition tests | One generated structural test per all 42 families |
| Report engine | Fail-closed A0–A5 aggregation |
| Results interface | Console + JSON + dependency-free HTML summary |
| Evidence integrity | Local SHA-256 evidence manifest generation/verification |
| Signature/transparency verification | Architecture specified; Sigstore/in-toto integration not implemented yet |
| Live deployment probes | **A3 reference harness complete:** 28 executable A1–A3 probes + 28 matching mutation validations; external framework adapters remain the next portability milestone |
| Certification | None; this is not an adopted standard or certification service |

## Profiles

- **A0 — Non-agentic:** classification only.
- **A1 — Observable:** 8 families + 5 baseline preconditions.
- **A2 — Controlled:** 21 families + 5 baseline preconditions.
- **A3 — Supervised:** 28 families + 5 baseline preconditions.
- **A4 — Hardened:** 35 families + 8 preconditions; adds hostile-workload resilience, partitions, common-mode analysis, out-of-band intervention and cryptographically bound evidence.
- **A5 — Critical:** 42 families + 11 preconditions; adds domain-critical observation, independent defense in depth, secondary containment, independent adversarial assurance, critical delegation constraints, governed recovery and independent evidence assurance.

There is **no averaging**. A mandatory FAIL fails the profile. Missing, errored, inconclusive, or not-tested mandatory work makes it incomplete.

## Run the current tooling

Python 3.10+; the prototype itself uses the standard library.

```bash
python3 -m unittest discover -s tests -v
python3 -m asimov_conformance catalog
python3 -m asimov_conformance report examples/report-illustrative-complete.json --html-output /tmp/asimov-result.html
python3 -m asimov_conformance reference-probes --html-output /tmp/asimov-probes.html
python3 -m asimov_conformance reference-mutations
```

Evidence integrity prototype:

```bash
python3 -m asimov_conformance evidence-manifest ./evidence --output evidence-manifest.json
python3 -m asimov_conformance verify-evidence evidence-manifest.json ./evidence
```

The executable A3 harness is documented in [docs/A3-REFERENCE-PROBES.md](docs/A3-REFERENCE-PROBES.md); integration authors should also read [docs/ADAPTER-GUIDE.md](docs/ADAPTER-GUIDE.md). Passing 28/28 on the disposable reference target validates the harness mechanics, not an external A3 conformance claim.

The hash manifest proves local byte integrity relative to the manifest. It does **not** prove signer identity, trusted time, completeness, or safety. See [docs/VERIFICATION.md](docs/VERIFICATION.md).

## Framework-neutral by design

An implementer does not need to run Asimov middleware. A proprietary frontier-lab service, Microsoft AGT deployment, ACS Guardian, cloud-native control plane, or local agent framework can all satisfy the same property using different mechanisms. Adapters translate those native mechanisms into semantic operations required by the conformance tests. See [docs/TEST-METHODOLOGY.md](docs/TEST-METHODOLOGY.md).

## What Asimov should not reinvent

Asimov should map to and reuse adjacent infrastructure: OWASP ACS for runtime control interfaces, Microsoft AGT for runtime-governance mechanisms, ControlArena for AI-control experiments, AAS-1 for audit-grade agent records, Sigstore/in-toto for signing and attestations, and OpenTelemetry for telemetry conventions. See [docs/ECOSYSTEM.md](docs/ECOSYSTEM.md).

## Open-source strategy

The recommended launch home is a public GitHub organization/repository with tagged releases, public AEPs, CI, Discussions, and a GitHub Pages documentation site generated from the same normative source. GitHub is the collaboration home, not the authority: releases should remain downloadable/archivable elsewhere. See [docs/PROJECT-STRATEGY.md](docs/PROJECT-STRATEGY.md) and [ROADMAP.md](ROADMAP.md). A manual GitHub Pages deployment workflow is included under `.github/workflows/pages.yml`.

## Important limitation

**Asimov does not certify that an AI is safe.** It defines and tests mechanisms intended to keep specified autonomous authority under accountable external control within a declared scope and threat model.

Original repository material is under Apache-2.0. The project name/package namespace remain provisional pending name/trademark clearance.
