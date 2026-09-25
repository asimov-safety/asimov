# Asimov Verification

Asimov verification is designed first for the artifact that will actually circulate: **the public report**.

## Public verification — primary use case

For ordinary public, media, customer, procurement, or policy use, distribute **one file**:

```text
report.html
```

The HTML report contains a non-visible Asimov public verification capsule. The capsule is excluded from the report-content digest so it can carry the statement/signature without creating a cryptographic self-reference.

The embedded public verification record contains:

- the report SHA-256 digest;
- the **exact bytes** of the Asimov verification statement;
- the assessment/report binding carried by that statement;
- optionally, the Sigstore bundle plus expected signer identity and OIDC issuer.

It does **not** contain the private evidence directory.

A reader can verify locally:

```bash
asimov verify-report report.html
```

The separate `public-verification.json` file remains an optional export/compatibility artifact, not a requirement for ordinary public verification.

The public Verify page exposes the same one-file workflow.

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

## Signing a public report — recommended path

`finalize-assessment` automatically embeds an **unsigned** public verification capsule into `report.html` and also writes `public-verification.json` as an optional export.

That is sufficient for a local report/statement match, but it does not answer **“Who signed this?”**

For a report intended for public distribution, install Sigstore's Cosign client once, then use Asimov's one-command wrapper.

### 1. Install Cosign

On macOS with Homebrew:

```bash
brew install cosign
cosign version
```

For Linux, Windows, package managers, and verified binary installation, use Sigstore's official Cosign installation guide.

### 2. Sign the report

For a human signer using a Google account:

```bash
asimov sign-report report.html \
  --statement asimov-statement.json \
  --provider google \
  --identity you@example.com
```

Before opening the identity flow, Asimov prints the exact signer identity and identity provider it expects. When Cosign asks you to authenticate, use that exact account.

Asimov then:

1. signs the exact `asimov-statement.json` bytes using Cosign/Sigstore;
2. writes `asimov.sigstore.json`;
3. embeds the Sigstore bundle, expected signer identity, and OIDC issuer into the report's verification capsule;
4. leaves the substantive report-content digest unchanged.

After that, the file to publish is simply:

```text
report.html
```

### Other identity providers

`sign-report` supports:

- `--provider google` → `https://accounts.google.com`
- `--provider github` → `https://github.com/login/oauth`
- `--provider microsoft` → `https://login.microsoftonline.com`
- `--provider github-actions` → `https://token.actions.githubusercontent.com`
- `--provider custom --oidc-issuer <URL>`

The value supplied to `--identity` must be the exact identity you expect the Sigstore certificate to contain. If the actual signer does not match it, later verification fails rather than silently accepting a different signer.

### Low-level signing

The lower-level two-command path remains available for advanced use:

```bash
asimov sigstore-sign asimov-statement.json --bundle asimov.sigstore.json

asimov public-record \
  --statement asimov-statement.json \
  --report report.html \
  --bundle asimov.sigstore.json \
  --certificate-identity '<EXPECTED_IDENTITY>' \
  --certificate-oidc-issuer '<EXPECTED_OIDC_ISSUER>'
```

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

The public Verify page prioritizes **one-file HTML report verification**.

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
