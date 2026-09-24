# Project strategy: open standard first, software second

## Development home

**GitHub is the primary development home.** It gives the project public source history, issues, pull requests, discussions, release tags, CI, security scanning, artifact attestations, and a natural contribution workflow. The normative standard must nevertheless remain portable: tagged specification releases should be downloadable and archivable independently of GitHub.

Repository layout:

```text
github.com/<asimov-org>/asimov
  ASIMOV-CORE.md
  conformance/
  schemas/
  adapters/
  docs/
  aeps/
  .github/workflows/
```

The project lives under the `asimov-safety` organization.

## Website

The **GitHub Pages** site is the public documentation front end. It renders tagged repository content; the repository remains the normative source. A custom domain can point at Pages when desired.

Public navigation:

- Seven Contracts
- A0–A5 Profiles
- Conformance Test Catalog
- Test Methodology
- Verification Model
- Ecosystem / mappings
- AEP proposals
- Implementer guide
- Current limitations

## Distribution

- Specification: tagged GitHub releases + website + archival mirror.
- Python reference tooling: PyPI once package/name clearance is complete.
- Schemas: versioned stable URLs on the documentation site.
- Containers/reference targets: GHCR if useful.
- Test corpus: Git LFS or external object storage only when size requires it.

## Governance

Normative changes go through Asimov Enhancement Proposals (AEPs), public review, versioned releases, and recorded rationales. Governance expands through documented maintainer and technical-steering roles. Commercial sponsorship does not buy exemptions or control of conformance criteria.

## Name risk

`Asimov` is memorable and conceptually excellent, but public launch should include a real trademark/name clearance rather than assuming the namespace is free. Keep the package/repository namespace provisional until checked.
