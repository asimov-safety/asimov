# Asimov
## Seven contracts. Testable control. Accountable autonomy.

**Version 0.2 · September 24, 2026**

Asimov is a free, open-source safety standard and conformance suite defining the technical conditions under which autonomous AI remains under accountable human control.

The Seven Contracts are **Observable Agency, Mediated Action, Revocable Authority, Protected Oversight, Bounded Delegation, Human Authority, and Accountability**.

## Current implementation

| Artifact | Status |
|---|---|
| Core specification | 42 cumulative families across A1–A5 |
| A1 — Observable | 8/8 executable reference probes |
| A2 — Controlled | 21/21 cumulative executable reference probes |
| A3 — Supervised | 28/28 cumulative executable reference probes |
| A4 — Hardened | 35/35 cumulative executable reference probes |
| A5 — Critical | 42/42 cumulative executable reference probes |
| Mutation validation | 42/42 paired control removals detected |
| Cross-platform CI | Ubuntu, macOS, Windows · Python 3.10 and 3.13 |
| Evidence integrity | Deterministic SHA-256 manifests and verification |
| Results | Console, JSON, and dependency-free HTML |

Profiles are cumulative. Every mandatory family for a claimed level must pass with the required evidence.

## Install and run

```bash
git clone https://github.com/asimov-safety/asimov.git
cd asimov
python -m pip install -e .

python -m asimov_conformance reference-probes
python -m asimov_conformance reference-mutations
python -m asimov_conformance doctor --level A5
```

## Build an adapter

Asimov is framework-neutral. Adapters translate native infrastructure—agent frameworks, IAM, databases, lifecycle controls, supervisors, and audit systems—into the semantic operations used by the conformance probes.

**Start here:** [Adapter Quick Start](docs/ADAPTER-QUICKSTART.md)  
**Deep reference:** [Adapter Guide](docs/ADAPTER-GUIDE.md)

Missing mandatory control surfaces block the corresponding A-level.

## Specification and methodology

- [ASIMOV CORE 0.2](ASIMOV-CORE-0.2.md)
- [Test Catalog 0.2](docs/TEST-CATALOG-0.2.md)
- [Test Methodology](docs/TEST-METHODOLOGY.md)
- [Full A1–A5 Reference Harness](docs/FULL-REFERENCE-HARNESS.md)
- [Verification Architecture](docs/VERIFICATION.md)
- [Ecosystem Mapping](docs/ECOSYSTEM.md)
- [Roadmap](ROADMAP.md)

## Evidence integrity

```bash
python -m asimov_conformance evidence-manifest ./evidence --output evidence-manifest.json
python -m asimov_conformance verify-evidence evidence-manifest.json ./evidence
```

Assessment results are bound to a specific deployment configuration, scope, threat model, and evidence set.

## Project

Apache-2.0. Public development happens in this repository through issues, pull requests, and Asimov Enhancement Proposals.
