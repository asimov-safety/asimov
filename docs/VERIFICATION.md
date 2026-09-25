# Asimov Verification

Asimov verification is a chain, not a badge.

For a real external assessment, begin with [ASSESSMENT-WORKFLOW.md](ASSESSMENT-WORKFLOW.md). `finalize-assessment` generates the assessment, full report, evidence manifest, verification statement and an exact `VERIFICATION-INSTRUCTIONS.md` file for the requested profile.

**Profile expectations are not implicit:** ACC-002 applies from A1 and requires trusted integrity state outside the actor's unauthorized mutation authority; A4/ACC-005 additionally requires authenticated signing plus an external transparency/timestamp/append-only (or equivalent independent) checkpoint; A5/ACC-006 additionally requires independent assessment, durable external retention/escrow, and successful reverification from a fresh environment.

```text
evidence files
     |
     v
evidence-manifest.json
     |
     +---- assessment.json
     +---- styled report / summary
     |
     v
asimov-statement.json
     |
     v
Sigstore bundle
     |
     v
verification receipt
```

## What is implemented

### 1. Evidence integrity

```bash
asimov evidence-manifest ./evidence --output evidence-manifest.json
asimov verify-evidence evidence-manifest.json ./evidence
```

The manifest deterministically binds file paths, sizes, and SHA-256 digests.

### 2. Assessment/report binding

```bash
asimov verification-statement assessment.json \
  --evidence-manifest evidence-manifest.json \
  --report asimov-report.html \
  --output asimov-statement.json
```

The statement uses the in-toto Statement v1 shape and an Asimov predicate. It binds:

- the assessment JSON digest;
- the evidence-manifest digest;
- each supplied styled report digest;
- system ID;
- deployment configuration SHA-256;
- scope-manifest SHA-256;
- requested assurance profile;
- assessment mode and report ID;
- reported outcome.

### 3. Identity-bound Sigstore signing

Install Cosign, then:

```bash
asimov sigstore-sign asimov-statement.json --bundle asimov.sigstore.json
```

This invokes the standard `cosign sign-blob` workflow. Keyless signing associates the signature with an OIDC identity through Sigstore Fulcio and stores verification material in the Sigstore bundle.

For CI/non-interactive confirmation:

```bash
asimov sigstore-sign asimov-statement.json \
  --bundle asimov.sigstore.json --yes
```

### 4. Full package verification

```bash
asimov verify-package assessment.json \
  --evidence-manifest evidence-manifest.json \
  --evidence-root ./evidence \
  --statement asimov-statement.json \
  --report asimov-report.html \
  --bundle asimov.sigstore.json \
  --certificate-identity assessor@example.com \
  --certificate-oidc-issuer https://accounts.google.com \
  --json-output verification-receipt.json \
  --html-output verification-receipt.html
```

The verifier reports these layers separately:

- evidence integrity;
- artifact/report binding;
- scope and configuration binding;
- Sigstore signer identity and transparency proof;
- semantic assurance review.

A successful Cosign bundle verification establishes the signature against the expected identity and issuer and verifies the Sigstore bundle's signed-time/transparency material. Semantic evidence review remains a separate assessment judgment.

## Browser verification

The public **Verify** page performs the non-network parts locally in the browser:

- SHA-256 recomputation;
- evidence-manifest self-digest;
- optional evidence-directory comparison;
- assessment/report subject digests;
- in-toto-style statement binding;
- scope/configuration binding.

Files selected in this mode stay in the browser.

Full Sigstore cryptographic verification uses the official Sigstore verifier. The site UI supports a verifier-service endpoint, and also generates the exact `cosign verify-blob` command when no service is configured.

## Verification service

A small optional verifier service lives in `services/verifier/`. It accepts only the verification statement, Sigstore bundle, expected identity, and OIDC issuer; it does not need the private assessment evidence. It executes Cosign with strict file-size limits and no shell interpolation.

## A4 and A5

**ACC-005 / A4** requires cryptographic binding, authenticated signing, and an external checkpoint.

**ACC-006 / A5** additionally requires independent assessment and durable evidence retention/escrow that can be reverified from a fresh environment.

## Sigstore interoperability

Asimov uses standard Sigstore/Cosign blob signing rather than inventing a signature system:

```bash
cosign sign-blob asimov-statement.json --bundle asimov.sigstore.json

cosign verify-blob asimov-statement.json \
  --bundle asimov.sigstore.json \
  --certificate-identity=assessor@example.com \
  --certificate-oidc-issuer=https://accounts.google.com
```

Official documentation:

- https://docs.sigstore.dev/quickstart/quickstart-cosign/
- https://docs.sigstore.dev/cosign/signing/signing_with_blobs/
- https://docs.sigstore.dev/cosign/verifying/verify/
- https://docs.sigstore.dev/about/bundle/
