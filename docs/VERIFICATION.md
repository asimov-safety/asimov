# Asimov Verification

Asimov verification is designed first for the artifact that will actually circulate: **the public report**.

## Public verification — primary use case

For ordinary public, media, customer, procurement, or policy use, distribute two files together:

```text
report.html
public-verification.json
```

The public verification record contains:

- the report SHA-256 digest;
- the **exact bytes** of the Asimov verification statement;
- the assessment/report binding carried by that statement;
- optionally, the Sigstore bundle plus expected signer identity and OIDC issuer.

It does **not** contain the private evidence directory.

A reader can verify locally:

```bash
asimov verify-report report.html public-verification.json
```

The public Verify page exposes the same two-file workflow.

### What public verification establishes

If the report digest matches but no signature is present:

- the report is byte-for-byte consistent with the supplied public verification record;
- the statement binds the report to a specific report ID, system/configuration digest, scope digest, requested profile, reported outcome, assessment mode, assessor claim, and evidence-manifest commitment;
- signer provenance is **not authenticated**.

If Sigstore verification also succeeds:

- the exact statement bytes were signed by the expected authenticated OIDC identity;
- the signature/certificate chain verifies;
- the Sigstore transparency material provides an external checkpoint for that signed commitment.

### What public verification does not establish

It does **not** prove that:

- the underlying evidence is true or complete;
- the assessor interpreted the evidence correctly;
- every applicable Asimov requirement passed;
- the deployment is absolutely safe.

Those remain semantic assessment/review questions. The report must continue to display FAIL, NOT_TESTED, INCONCLUSIVE, self-assessment, and independence limitations honestly.

## Creating a public verification record

`finalize-assessment` automatically creates an **unsigned** public sidecar:

```text
public-verification.json
```

That is sufficient for a local report/statement match, but **not authenticated public provenance**.

For a report intended for broad public distribution, authenticated signing is strongly recommended even when the requested profile is below A4.

First sign the exact statement:

```bash
asimov sigstore-sign asimov-statement.json --bundle asimov.sigstore.json
```

Then rebuild the public sidecar with the signature material:

```bash
asimov public-record \
  --statement asimov-statement.json \
  --report report.html \
  --bundle asimov.sigstore.json \
  --certificate-identity '<EXPECTED_IDENTITY>' \
  --certificate-oidc-issuer '<EXPECTED_OIDC_ISSUER>' \
  --output public-verification.json
```

Record the **exact** authenticated identity and exact OIDC issuer used by the signing flow. Do not guess either value.

## Why Sigstore is used

Sigstore/Cosign lets an assessor sign with a short-lived key whose certificate is tied to an authenticated OIDC identity, while preserving transparency/checkpoint material needed for later verification. Asimov therefore does not need to invent its own public-key infrastructure or ask every assessor to manage long-lived signing keys.

The signed object is `asimov-statement.json`, not the report directly. The statement contains the report digest and the assessment/scope/configuration binding. Changing the report changes the digest; changing the statement invalidates the signature.

## Auditor / full-package verification

Auditors and technical reviewers with access to the complete evidence package can additionally verify:

```text
evidence files
     |
     v
evidence-manifest.json
     |
     +---- assessment.json
     +---- report.html
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

### Evidence integrity

```bash
asimov verify-evidence evidence-manifest.json ./evidence
```

### Full package verification

```bash
asimov verify-package assessment.json \
  --evidence-manifest evidence-manifest.json \
  --evidence-root ./evidence \
  --statement asimov-statement.json \
  --report report.html \
  --bundle asimov.sigstore.json \
  --certificate-identity '<EXPECTED_IDENTITY>' \
  --certificate-oidc-issuer '<EXPECTED_OIDC_ISSUER>' \
  --json-output verification-receipt.json \
  --html-output verification-receipt.html
```

The verifier reports separately:

- evidence integrity;
- artifact/report binding;
- scope and configuration binding;
- signer identity and transparency proof;
- semantic assurance status.

## Profile requirements

**A1+ / ACC-002:** relied-upon evidence must resist unauthorized alteration under a declared trust model. A manifest stored only beside actor-writable evidence is not by itself an independent integrity anchor.

**A4 / ACC-005:** authenticated signing plus an external transparency/timestamp/append-only or equivalent independent checkpoint is mandatory.

**A5 / ACC-006:** independent assessment, durable evidence retention/escrow outside the assessed actor and ordinary mutable operator path, and successful reverification from a fresh environment are additionally mandatory.

## Browser verification

The public Verify page prioritizes **report + public verification record**.

The complete package verifier remains available in a collapsed **Auditor / advanced verification** section.

Browser-side checks use local SHA-256 and do not upload the private evidence directory. Full Sigstore cryptographic verification uses the optional verifier service or the official Cosign verifier.

## Verifier service

The optional service in `services/verifier/` receives only:

- the public verification statement;
- Sigstore bundle;
- expected signer identity;
- expected OIDC issuer.

It does **not** need the private assessment evidence.

## Core principle

> A hash proves which bytes were committed. A signature can prove who committed to them. Neither proves that the underlying assessment judgment was correct.
