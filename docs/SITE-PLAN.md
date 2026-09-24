# GitHub Pages site plan

The website is a human-friendly rendering of the repository, **not a second normative source**.

## v1 navigation

1. **Home** — one-sentence thesis, Seven Contracts, A-level ladder, current maturity.
2. **Seven Contracts** — plain-language contract cards linked to normative requirements.
3. **A1–A5** — cumulative profile table, mandatory-family counts, no-averaging rule.
4. **Test Your System** — install, `init`, `doctor`, adapter quick-start, run probes, read results.
5. **Probe Explorer** — all 42 families with implementation status and required evidence.
6. **Verification** — hashes, signatures, transparency checkpoints, evidence review, what each proves.
7. **Integrations** — framework/provider adapters and their supported semantic capabilities.
8. **Status & Roadmap** — executable coverage, portability status, known limitations.
9. **Contribute** — AEP process, adapter contributions, test/failure-mode contributions.

## Design rules

- The normative source remains tagged repository content.
- Every website requirement links to the exact versioned source.
- Never display a single numeric safety score.
- Missing mandatory surfaces are shown as blockers, not partial credit.
- Results distinguish reference-harness validation, self-assessment, independent assessment, and verified evidence.
- Keep the visual identity sober and infrastructure-like; avoid "AI safety theater" imagery.
- The site must work as static files so GitHub Pages remains sufficient initially.

## v1 homepage

The homepage should answer, in order:

1. What is Asimov?
2. What are the Seven Contracts?
3. What do A1–A5 mean?
4. What is actually implemented today?
5. How do I test my system?
6. What does a result prove—and not prove?

## Later

After external-adapter validation, add:
- interactive test/result explorer;
- verified attestation viewer;
- public compatibility matrix;
- machine-readable release/spec downloads;
- searchable AEP/test-failure corpus.
