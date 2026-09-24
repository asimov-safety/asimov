# Project strategy: open standard first, software second

## Recommended home

**GitHub should be the primary development home at launch.** It gives the project public source history, issues, pull requests, discussions, release tags, CI, security scanning, artifact attestations, and a natural contribution workflow. The normative standard must nevertheless remain portable: tagged specification releases should be downloadable and archivable independently of GitHub.

Recommended eventual layout:

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

The project should use an organization rather than a personal repository once governance begins to broaden.

## Website

A **GitHub Pages** site makes sense for the public documentation because it can be generated directly from the tagged repository and hosted free for a public project. The website should be a presentation layer, never a second source of normative text. A custom domain can point at Pages later.

Suggested public navigation:

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

For credibility, control of the project should gradually move from founder-only decisions to a documented maintainer/technical-steering process. Normative changes should go through Asimov Enhancement Proposals (AEPs), public review, versioned releases, and recorded rationales. Commercial sponsorship should not buy exemptions or control of conformance criteria.

## Name risk

`Asimov` is memorable and conceptually excellent, but public launch should include a real trademark/name clearance rather than assuming the namespace is free. Keep the package/repository namespace provisional until checked.
