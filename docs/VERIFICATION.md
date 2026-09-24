# Verifiable Asimov evidence

The conformance result needs to be **independently checkable without pretending cryptography proves safety**.

## What hashes can and cannot do

A SHA-256 digest can bind a report to exact bytes. If any bound artifact changes, its digest changes. But a hash alone does not establish who created the evidence, when it existed, whether relevant evidence was omitted, or whether the logged event actually happened. An operator can modify a report and calculate a new hash.

Asimov therefore separates four assurance layers.

### V1 — Content integrity

Create a deterministic evidence manifest containing the relative path, size, and SHA-256 digest of each relied-upon artifact. Bind the report to the scope manifest and tested configuration digest.

The prototype implements:

```bash
python -m asimov_conformance evidence-manifest ./evidence --output evidence-manifest.json
python -m asimov_conformance verify-evidence evidence-manifest.json ./evidence
```

This detects local artifact modification/substitution against the manifest. It is not an identity proof.

### V2 — Signer identity

Sign the report/evidence commitment with an authenticated assessor or assessment-system identity. Asimov should prefer standard attestation envelopes rather than invent a signature format.

A strong candidate is an **in-toto Statement** whose subject is the assessment report and whose Asimov predicate binds the specification, scope/configuration, evidence-manifest digest, profile request, and result. The statement can then be signed with an established signing system.

### V3 — Independent timestamp/transparency checkpoint

An issuer who controls both the evidence store and long-lived private key can otherwise rewrite history and issue a new signature. For A4, the signed commitment should therefore be externally checkpointed in a transparency log, trusted timestamp service, independently controlled append-only log, or equivalent mechanism.

**Sigstore** is a strong public option because it supports identity-bound short-lived signing certificates and transparency-log inclusion. Enterprise deployments may instead use an HSM-backed PKI plus independently administered immutable/timestamped storage. Blockchain can satisfy the external-checkpoint property, but is neither required nor preferred by Core.

### V4 — Semantic assurance

An assessor verifies that the evidence actually supports each requirement and that the scope matches the deployment. Cryptographic validity cannot establish completeness, correctness of a monitor, or truth of an unobserved event.

## A4 vs A5

**A4 / ACC-005** requires cryptographic binding plus authenticated signing and an external checkpoint (or equivalent independent mechanism).

**A5 / ACC-006** additionally requires independent assessment and durable evidence that can be verified from a fresh environment. The A5 assessor must verify the scope/configuration binding and material limitations, not merely a signature.

## Reuse, not reinvention

- **Sigstore/Cosign** — signature identity, certificate, timestamp, transparency proof.
- **in-toto** — extensible attestation statement model.
- **AAS-1** — agent audit records, signatures, timestamps, Merkle aggregation, auditor determinations. Asimov should be able to cite AAS-1 records as evidence rather than define a rival action-record format.
- **GitHub Artifact Attestations / SLSA** — useful for proving how the Asimov package and released conformance runner were built; this is distinct from proving a deployment's controls.

## Verification states for a future CLI

A future `asimov verify` should report layers separately, for example:

```text
REPORT STRUCTURE            VERIFIED
EVIDENCE CONTENT INTEGRITY  VERIFIED
SIGNER IDENTITY             VERIFIED
EXTERNAL CHECKPOINT         VERIFIED
SCOPE/CONFIGURATION MATCH   VERIFIED
SEMANTIC EVIDENCE REVIEW    INDEPENDENTLY REVIEWED

A4 reported result: SATISFIED_IN_SCOPE
This is not a claim of absolute AI safety.
```

The tool must never collapse all of these into a single ambiguous green "verified safe" badge.
