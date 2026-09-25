# Asimov
## The Seven Constants of Accountable Autonomy

**Version 0.2 · September 24, 2026**

Asimov is a free, open-source safety standard and conformance suite defining the technical conditions under which autonomous AI remains under accountable human control.

The Seven Constants are **Observable Agency, Mediated Action, Revocable Authority, Protected Oversight, Bounded Delegation, Human Authority, and Accountability**. Each Constant defines a control invariant that must remain true throughout autonomous operation.

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
| Human review | HUMAN / ROLE_SEPARATED / THIRD_PARTY + signed Sigstore review attestations |
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
**Architecture walkthroughs:** [Implementation Handbook](docs/IMPLEMENTATION-HANDBOOK.md)  
**Deep semantic reference:** [Adapter Guide](docs/ADAPTER-GUIDE.md)

Missing mandatory control surfaces block the corresponding A-level.

## Assess a real deployment

Use the staged generic workflow rather than hand-building a report from raw probe output:

```bash
asimov prepare-assessment \
  --adapter ./my_adapter.py:MyAdapter \
  --level A5 \
  --assessor "Assessment Team" \
  --subject-organization "Deployment Operator" \
  --assessor-organization "Assessment Organization" \
  --output ./assessment

# Review and acknowledge the generated scope, preconditions,
# HYBRID / REVIEW_REQUIRED records, and verification plan.

asimov run-assessment ./assessment \
  --adapter ./my_adapter.py:MyAdapter

# Complete required human/review records against the actual evidence.
asimov assessment-status ./assessment

# Sign each completed human-review/precondition record with its reviewer's identity.
asimov sign-review ./assessment/reviews/requirements/ACC-006.json \
  --provider google --identity reviewer@example.org

# After all required review attestations exist:
asimov finalize-assessment ./assessment
```

An A5 run is cumulative and covers A1–A5. HYBRID and REVIEW_REQUIRED findings remain INCONCLUSIVE until their required review records and Sigstore attestations are valid; human review cannot override a technical failure. Review requirements distinguish ordinary HUMAN review, internal ROLE_SEPARATED review, and external THIRD_PARTY review. See [End-to-end Assessment Workflow](docs/ASSESSMENT-WORKFLOW.md).

## Specification and methodology

- [ASIMOV CORE 0.2](ASIMOV-CORE-0.2.md)
- [Test Catalog 0.2](docs/TEST-CATALOG-0.2.md)
- [Test Methodology](docs/TEST-METHODOLOGY.md)
- [Full A1–A5 Reference Harness](docs/FULL-REFERENCE-HARNESS.md)
- [Verification](docs/VERIFICATION.md)
- [Professional Reports](docs/REPORTS.md)
- [Implementation Handbook](docs/IMPLEMENTATION-HANDBOOK.md)
- [Ecosystem Mapping](docs/ECOSYSTEM.md)
- [Roadmap](ROADMAP.md)

## Public report verification

The primary public verification workflow uses a single self-contained file:

```text
report.html
```

A reader can upload that report to the public Verify page to answer **“Has this report changed?”** The report can also be digitally signed so a verifier can answer **“Who signed this?”**

To sign a finalized report, install Cosign once and run:

```bash
asimov sign-report report.html --statement asimov-statement.json --provider google --identity you@example.com
```

The full private evidence-package verifier remains available for auditors.

## Report, sign, verify

```bash
asimov report assessment.json \
  --html-output asimov-report.html \
  --summary-output asimov-summary.html

asimov evidence-manifest ./evidence --output evidence-manifest.json

asimov verification-statement assessment.json \
  --evidence-manifest evidence-manifest.json \
  --report asimov-report.html \
  --report asimov-summary.html \
  --output asimov-statement.json

asimov sigstore-sign asimov-statement.json --bundle asimov.sigstore.json

asimov public-record \
  --statement asimov-statement.json \
  --report asimov-report.html \
  --bundle asimov.sigstore.json \
  --certificate-identity '<EXPECTED_IDENTITY>' \
  --certificate-oidc-issuer '<EXPECTED_OIDC_ISSUER>' \
  --output public-verification.json
```

The styled report, assessment, and evidence manifest become cryptographically bound subjects of the signed verification statement. For public/media distribution, the self-contained HTML report is the intended verification artifact; the full evidence package is primarily for auditors and technical reviewers.

## Project

Apache-2.0. Public development happens in this repository through issues, pull requests, and Asimov Enhancement Proposals.
