# Asimov Reports

The assessment report is a first-class Asimov artifact.

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
