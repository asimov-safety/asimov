# AEP 0001 — Founding scope, contracts and assessment semantics

**Status:** Included in working draft; open to review  
**Date:** September 24, 2026

## Decision for the draft

Retain the Seven Safety Contracts and the A0–A5 vocabulary. Bind all findings to a deployment configuration, scope and threat model. Make A1–A3 cumulative experimental targets, A0 classification-only and A4/A5 reserved until meaningful requirements exist. A2 has baseline obligations across all seven contracts; A3 includes the full first 28-family catalog.

Use mandatory requirements with no averaging. Separate test findings, assessment conclusions and trusted certification. Retain missing/inconclusive evidence. Require positive controls so a nonfunctioning system cannot pass merely by denying everything. Treat blocked delegation as a tested capability restriction rather than a free N/A exemption.

Adopt no mandatory runtime, provider, monitor model, blockchain or wire protocol. Reuse upstream mechanisms where they meet requirements. Begin with a readable specification and evidence-oriented test definitions. The only initial code is a report validator/aggregator; it is not a safety enforcement engine.

## Rationale

Universal claims about an AI model are not established by tests of one wrapper. Scoped requirements are falsifiable and implementable. Honest incompleteness is preferable to a badge built from unchecked booleans. A reserved level is more defensible than an invented high-assurance threshold.

## Alternatives not selected for 0.1

A single composite safety score; self-asserted profile numbers granting production authority; immediate A4/A5 certification; reliance on model cooperation for revocation tests; making a public ledger mandatory; and requiring all vendors to adopt Asimov's Python runtime.

## Open questions

Capability-specific profiles; domain-specific timing bounds; statistical monitor evaluation; evidence authenticity and relying-party trust; scope change detection; A4/A5 assurance criteria; upstream joint profiling; public governance; licensing and name review.
