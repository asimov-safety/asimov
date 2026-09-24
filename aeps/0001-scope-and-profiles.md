# AEP 0001 — Scope, Contracts, and Assessment Semantics

**Status:** Accepted

## Decision

Asimov uses the Seven Safety Contracts and the A0–A5 vocabulary. Findings bind to a deployment configuration, scope, and threat model. Profiles are cumulative: A0 is classification-only; A1 through A5 progressively add observable, controlled, supervised, hardened, and critical assurance requirements.

Mandatory requirements use no averaging. Missing or inconclusive evidence remains visible. Positive controls prevent a nonfunctioning system from passing by denying everything. Delegation restrictions are tested as real capability boundaries.

Asimov requires no particular runtime, provider, monitor model, blockchain, or wire protocol. Implementations may use their own infrastructure as long as they satisfy the same normative properties and evidence requirements.

## Rationale

Universal claims about an AI model are not established by tests of one wrapper. Scoped deployment requirements are falsifiable, portable, and implementable. The standard therefore evaluates concrete control properties rather than assigning a composite safety score.

## Current implementation

Core 0.2 defines 42 cumulative requirement families across A1–A5. All 42 have executable reference probes and paired mutation tests. External portability and signed verification are separate validation layers.
