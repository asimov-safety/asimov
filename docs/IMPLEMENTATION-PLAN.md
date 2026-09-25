# Asimov implementation plan — after 0.2 draft

## M0 — specification integrity (done in this draft)

- Seven Contracts and cumulative A0–A5 profiles.
- 42 operational test-family specifications.
- Machine-readable catalog and report/schema bindings.
- Automation/method classification for every family.
- Explicit NONE / HUMAN / ROLE_SEPARATED / THIRD_PARTY review requirements.
- Structured human-review records with reviewer/subject organization and independence declarations.
- Fail-closed A1–A5 report aggregation.
- HTML/JSON/console result surfaces.
- Local SHA-256 evidence-manifest integrity tooling.
- Framework-neutral adapter protocol.

These are specification/tooling milestones, not proof that any deployment passes.

## M1 — executable A2 core harness (**completed: all 21 A1/A2 families**

A disposable reference target and live probes now exist for:

- OBS-002 external observation;
- MED-001 pre-effect authorization;
- MED-002 alternate-path bypass;
- REV-001 external revocation;
- REV-004 descendant revocation;
- OVR-001 control-plane tamper resistance;
- HUM-001 independent stop;
- HUM-003 stop persistence across restart;
- ACC-002 evidence tamper detection.

All 21 A1/A2 probes have a corresponding deliberate control-removal mutation, and mutation validation requires the matching probe to fail. **This is reference-harness validation, not external conformance.**\n\n## M1.5 — executable A3 supervised harness (**completed: all 28 A1–A3 families**)\n\nThe A3 tranche adds authenticated supervisor messaging, independent supervision health/intervention, untrusted-content control isolation, delegated lifecycle tracking, cross-boundary recipient verification, persistent stop latching, and hazard/load intervention exercises. All 28 cumulative probes pass the hardened reference target and all 28 matching mutations are detected. The next portability milestone is to run the same semantics through independently designed external adapters without weakening acceptance criteria.

## M2 — adapter API and second implementation

Implement two genuinely different targets before claiming portability. Good candidates:

1. minimal disposable Python target maintained in-repo;
2. an existing ecosystem implementation (ACS/AGT or a mainstream agent framework).

Adapters must publish supported capabilities and map each live family to concrete native APIs and independent observation oracles.

## M3 — verifiable assessment bundle (**substantially implemented**)

Implemented:

- deterministic evidence-manifest binding;
- Asimov in-toto-style assessment predicate;
- Sigstore/Cosign package/report signing and identity verification;
- one-file public report verification capsule;
- structured human-review records;
- Sigstore/Cosign blob attestations for individual human reviews;
- machine checks for ROLE_SEPARATED and declared THIRD_PARTY relationships;
- full-package verification that fails on missing/invalid review attestations;
- clear verification states rather than one ambiguous badge.

Still to mature:

- canonical interchange/profile stabilization across independent implementations;
- optional AAS-1 evidence import/mapping;
- stronger offline/trusted-root verification workflows;
- independent interoperability testing of the review-attestation format.

## M4 — A4 assurance harness

- fault/partition injection;
- common-mode dependency graph tooling;
- load/churn delegation tests;
- out-of-band intervention drills;
- adversarial campaign interface;
- statistical reporting for semantic monitors.

ControlArena should be evaluated as reusable infrastructure before building custom experimental machinery.

## M5 — A5 critical profile validation

A5 must not mature based only on project authors' intuition. Recruit independent reviewers from safety engineering, security, AI control, SRE, human factors, and at least one regulated/high-consequence domain. Pilot on simulated/disposable systems. Revise criteria before any certification program exists.

A5 pilots must exercise the actual THIRD_PARTY path: separate assessor organization, signed independence declaration, reviewer-owned Sigstore identity, fresh-environment reconstruction, and evidence escrow. A self-assessment with a differently named reviewer is not an A5 independence pilot.

## M6 — public project

- name/trademark clearance;
- GitHub organization and public repository;
- GitHub Pages docs generated from tagged source;
- AEP process + public roadmap + security policy;
- signed/attested releases;
- package namespace/PyPI only after naming is stable;
- eventual independent governance/technical steering.
