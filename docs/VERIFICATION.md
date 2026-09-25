# Asimov Verification

Asimov verification is designed first for the artifact that will actually circulate: **the public report**.

## Public verification — primary use case

For ordinary public, media, customer, procurement, or policy use, distribute **one file**:

```text
report.html
```

The HTML report contains a non-visible verification record. In plain terms, that record lets Asimov answer:

- **Has this report been changed since it was issued?**
- **Who signed this report?** when a signature is attached and successfully checked;
- **Which assessment does this report belong to?**

The low-level hashes, statement bytes, Sigstore bundle, signer identity fields, and issuer fields are still retained for technical verification, but they are not the public-facing explanation.

It does **not** contain the private evidence directory.

### Confirm the signer on your own computer

`asimov verify-report` is the definitive local signer check. It reads the verification information embedded in the HTML report, uses the official Cosign verifier to check the Sigstore signature, and reports whether the named signing account actually signed that exact assessment record. The report is checked on your computer; it is not uploaded anywhere.

If Asimov is not installed yet, install it directly from the public repository.

**macOS / Linux — Python 3.10+**

```bash
python3 -m pip install "https://github.com/asimov-safety/asimov/archive/refs/heads/main.zip"
asimov --help
```

**Windows PowerShell — Python 3.10+**

```powershell
py -m pip install "https://github.com/asimov-safety/asimov/archive/refs/heads/main.zip"
asimov --help
```

Cosign must also be installed because it performs the cryptographic signature check. See the platform-specific Cosign instructions below.

Then save the HTML report locally, open Terminal / PowerShell in that folder, and run:

```bash
asimov verify-report report.html
```

For a successfully signed report, Asimov confirms that the report content is unchanged and identifies the verified signing account. If the signature, signing identity, or report content does not match, verification fails.

The separate `public-verification.json` file remains an optional export/compatibility artifact, not a requirement for ordinary public verification.

The public Verify page exposes the same one-file workflow.

### What public verification establishes

If the report check succeeds but no signature is present, Asimov can say the report content is unchanged from the issued assessment record.

If the Sigstore signature also verifies, Asimov can additionally say which authenticated account signed the assessment record.

Those are deliberately separate claims. An unchanged report is not automatically a signed report, and a signed report is not automatically a correct assessment.

### What public verification does not establish

It does **not** prove that:

- the underlying evidence is true or complete;
- the assessor interpreted the evidence correctly;
- every applicable Asimov requirement passed;
- the deployment is absolutely safe.

Those remain semantic assessment/review questions. The report must continue to display FAIL, NOT_TESTED, INCONCLUSIVE, self-assessment, and independence limitations honestly.

## Signed human-review attestations

The package signature and a human review signature mean different things.

- The **package/report signature** says who authenticated the final bound assessment package.
- A **review attestation** says which authenticated reviewer made a particular human judgment about a particular exact review record.

Every completed mandatory HYBRID / REVIEW_REQUIRED **test-family** human review is signed separately. Assessment preconditions remain structured, evidence-bound records but do not each require a separate Sigstore attestation in Asimov 0.2. The review record declares its expected Sigstore identity and issuer; Asimov verifies that the actual signer matches those declarations and that the attestation is bound to the exact review-record bytes.

```bash
asimov sign-review reviews/requirements/ACC-006.json \
  --provider google \
  --identity reviewer@example.org

asimov verify-review reviews/requirements/ACC-006.json
```

For `ROLE_SEPARATED`, verification also checks the signed declaration that the reviewer is separated from the implementer/control owner. For `THIRD_PARTY`, it checks the signed declarations that reviewer and subject organizations differ, the reviewer is a separate legal entity, the subject does not control the assessment outcome, compensation is not contingent on passing, and conflicts are disclosed.

These are **signed assertions**, not magical corporate-registry checks. Cosign can prove which authenticated identity signed the exact assertions; it cannot independently discover a hidden ownership relationship or undisclosed conflict.

## Signing a public report — recommended path

`finalize-assessment` automatically embeds an **unsigned** public verification capsule into `report.html` and also writes `public-verification.json` as an optional export.

That is sufficient for a local report/statement match, but it does not answer **“Who signed this?”**

For a report intended for public distribution, install Sigstore's Cosign client once, then use Asimov's one-command wrapper.

### 1. Install Cosign

**macOS — Homebrew**

```bash
brew install cosign
cosign version
```

**Windows**

Download the latest `cosign-windows-amd64.exe` (or the build for your architecture) from the official Cosign releases page, rename it to `cosign.exe`, and place it in a directory on your `PATH`. Then:

```powershell
cosign version
```

**Linux**

Homebrew/Linuxbrew works:

```bash
brew install cosign
cosign version
```

Sigstore also publishes Linux binaries plus rpm/deb packages, and documents Arch, Alpine, Nix, and NixOS installation.

**Any platform with Go 1.20+**

```bash
go install github.com/sigstore/cosign/v3/cmd/cosign@latest
```

Official installation guide: https://docs.sigstore.dev/cosign/system_config/installation/  
Official releases: https://github.com/sigstore/cosign/releases

Use a current patched Cosign release. Asimov's blob-attestation workflow relies on `attest-blob` / `verify-blob-attestation`; old verifier releases with known attestation-verification vulnerabilities should not be used.

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
- package signer identity and transparency proof;
- each mandatory test-family human review's Sigstore attestation and authenticated reviewer identity;
- declared ROLE_SEPARATED / THIRD_PARTY relationship checks;
- semantic assurance status.

## Profile requirements

**A1+ / ACC-002:** relied-upon evidence must resist unauthorized alteration under a declared trust model. A manifest stored only beside actor-writable evidence is not by itself an independent integrity anchor.

**A4 / ACC-005:** authenticated signing plus an external transparency/timestamp/append-only or equivalent independent checkpoint is mandatory.

**A5 / ACC-006:** independent assessment by a separate legal entity from the Assessment Subject, a signed independence declaration, durable evidence retention/escrow outside the assessed actor and ordinary mutable operator path, and successful reverification from a fresh environment are additionally mandatory.

## Browser verification and zero-infrastructure operation

The public Verify page prioritizes **one-file HTML report verification**. The complete package verifier remains available in a collapsed **Auditor / advanced verification** section.

The public site is static and can verify the report fingerprint entirely in the browser. No server, database, account, or paid hosting is required for that check.

The authoritative signer check is local Cosign / `asimov verify-report`. The static website does not run a second signing-verification service. Anyone who wants cryptographic confirmation runs the verifier on their own computer.

Asimov intentionally does not label a signer as verified unless the cryptographic signature has actually been checked.

## Core principle

> Verification can show that a report is unchanged and, when the signature is checked, who signed it. It cannot tell you whether the assessment judgment itself was correct.
