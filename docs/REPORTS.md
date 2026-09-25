# Asimov Reports

The assessment report is a first-class Asimov artifact and the primary public-facing assessment output.

For public/media distribution, share the full HTML report by itself. The report contains an embedded verification capsule that allows a reader to verify the substantive report content and, when Sigstore material is included, authenticate the signer/checkpoint without receiving the private evidence directory. A separate `public-verification.json` remains available only as an optional export.

For external deployments, **do not hand-build the final assessment JSON from raw probe output**. Use the generic staged workflow in [ASSESSMENT-WORKFLOW.md](ASSESSMENT-WORKFLOW.md): `prepare-assessment` → `run-assessment` → complete required review records → `finalize-assessment`. This is what merges HYBRID / REVIEW_REQUIRED human judgments fail-closed and generates the report, manifest and verification statement consistently.

## Outputs

`asimov report` can produce three forms from the same assessment JSON:

- **result JSON** — machine-readable aggregation;
- **full report HTML** — professional multi-page assessment artifact, print/PDF-ready;
- **summary HTML** — concise shareable executive/media summary.

```bash
asimov report assessment.json \
  --json-output assessment.result.json \
  --html-output asimov-report.html \
  --summary-output asimov-summary.html
```

The full report includes:

- assessment cover and system identity;
- highest satisfied cumulative assurance profile;
- Seven Constants overview;
- profile progression;
- assessment preconditions;
- detailed findings grouped by Constant;
- evidence references;
- deployment configuration and scope digests;
- limitations;
- verification instructions.

The summary emphasizes the assessment result and Seven Constants in a compact shareable format.

Both HTML files are self-contained and use print styles so browsers can export them directly to PDF.

## Signing reports

Pass every report artifact you intend to distribute to `verification-statement`:

```bash
asimov verification-statement assessment.json \
  --evidence-manifest evidence-manifest.json \
  --report asimov-report.html \
  --report asimov-summary.html \
  --output asimov-statement.json
```

Each report digest becomes a subject of the signed verification statement. A recipient can therefore verify that the shared report is byte-for-byte the report bound to the assessment package.
