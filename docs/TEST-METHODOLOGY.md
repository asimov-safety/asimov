# Asimov test methodology 0.2

Asimov conformance is a **deployment assessment**, not a unit-test score and not a model benchmark. A valid assessment combines executable probes, independent observations, architecture/privilege evidence, and—at higher profiles—fault injection, adversarial campaigns, human exercises, and independent review.

## 1. Operational definition of a test family

Every family must specify nine things:

1. **Required property** — the falsifiable control property.
2. **Setup** — the environment, identities, resources, and fixtures needed.
3. **Procedure** — what the assessor actually does.
4. **Acceptance condition** — the evidence that permits PASS.
5. **Required evidence** — artifacts that must survive the run.
6. **Limitations** — what the result does not establish.
7. **Method class(es)** — review/probe/fault/adversarial/etc.
8. **Automation class** — adapter-automatable, hybrid, or review-required.
9. **Scope binding** — the exact deployment/configuration to which the result applies.

A family may contain several trials. One successful example cannot satisfy a family whose procedure calls for multiple enabled paths, failure modes, or identities.

## 2. Method classes

- `ARCHITECTURE_REVIEW` / `PRIVILEGE_REVIEW` — establish topology, trust boundaries, credentials, identities, and bypass routes.
- `DETERMINISTIC_PROBE` / `BYPASS_PROBE` — directly attempt allowed and forbidden effects using the actor's effective authority.
- `RESOURCE_OBSERVATION` — independently inspect the actual protected resource or executor rather than trusting the agent transcript.
- `FAULT_INJECTION` / `RESTART_PROBE` — deliberately break required dependencies and verify the bounded failure posture.
- `REVOCATION_PROBE` — withdraw authority while work is active, queued, cached, delegated, or disconnected.
- `DELEGATION_PROBE` / `LIFECYCLE_PROBE` — exercise child, grandchild, scheduled, background, and cross-boundary work.
- `LOAD_TEST` / `CONCURRENCY_PROBE` / `BUDGET_PROBE` — test aggregate limits and race conditions under the declared load envelope.
- `HUMAN_EXERCISE` / `APPROVAL_BINDING_PROBE` — exercise real operator controls, trusted presentation, stop, and recovery paths.
- `ADVERSARIAL_CAMPAIGN` / `INDEPENDENT_RED_TEAM` — run predeclared attempts to evade supervision or exploit the control plane.
- `STATISTICAL_EVALUATION` — evaluate stochastic monitors with a defined task distribution, denominator, sampling settings, scorer, and uncertainty.
- `CRYPTOGRAPHIC_VERIFICATION` / `EVIDENCE_REPLAY` — verify artifact integrity, identity binding, checkpoints, and reproducible reconstruction.
- `DOMAIN_HAZARD_REVIEW` / `SAFETY_CASE_REVIEW` — map domain-specific critical effects and residual risk; these are not honestly reducible to a universal Python assertion.
- `INDEPENDENT_ASSESSMENT` — a genuinely separate assessor validates the evidence and claim boundary.

## 3. Automation classes

### ADAPTER_AUTOMATABLE

The normative mechanics can usually be run automatically after an adapter provides the required semantic operation and an independent observation oracle. Automation does not mean the test is universally portable without integration work.

### HYBRID

Executable probes are mandatory, but the PASS also depends on architecture, privilege, trust-boundary, common-mode, human-factors, or evidence review.

### REVIEW_REQUIRED

A harness can collect and validate artifacts, but the normative conclusion includes a judgment that would be misleading if produced solely by code—for example a domain safety case, independent red-team adequacy, or emergency staffing/recovery exercise.

## 4. Framework-neutral adapter model

Asimov should not require LangGraph, OpenAI Agents SDK, Microsoft Agent Framework, CrewAI, AutoGen, Runic, MCP, ACS, or any other orchestrator. An adapter translates a deployment's native mechanics into semantic operations such as:

- obtain a deployment/configuration snapshot;
- attempt an action as the real actor principal;
- observe a protected resource independently;
- revoke a grant;
- stop/restrict a scope;
- restart a component;
- inject a declared fault;
- create delegated work under a scoped grant.

The draft `ConformanceAdapter` protocol lives in `asimov_conformance/adapter.py`. Future probe plugins should declare the capabilities they require. Missing capability means `NOT_TESTED` or `INCONCLUSIVE`, never PASS.

## 5. Direct-driver rule

A safety test must not depend on a model agreeing to behave adversarially. Where a boundary is deterministic, the assessor should exercise it with a direct driver using the same effective credentials/privileges. Model-driven red-team trials are additional evidence, not substitutes for direct boundary testing.

## 6. Independent-oracle rule

An agent saying "the command was blocked" is not proof. For protected effects, the test must observe the executor, resource, credential issuer, network boundary, or equivalent external source. A4 requires explicit corroboration for high-consequence action classes; A5 requires a domain-justified observation strategy for critical transitions.

## 7. Stochastic evaluation

For semantic monitors or adversarial campaigns, predeclare:

- task/attack distribution and generation method;
- model/provider/version and mutable aliases;
- prompts/system settings and tool configuration;
- sampling temperature/seed where available;
- number of attempts and exclusion rules;
- scorer and adjudication procedure;
- acceptance threshold and uncertainty calculation;
- stop conditions and resource budget.

Zero observed failures is a fact about those trials, not a probability-zero safety claim.

## 8. Fail-closed result semantics

- `PASS` — every mandatory branch/probe/review for the family is satisfied with reviewed evidence.
- `FAIL` — credible evidence contradicts a mandatory property.
- `ERROR` — the procedure could not execute reliably.
- `NOT_TESTED` — the required test did not run.
- `INCONCLUSIVE` — evidence cannot support either PASS or FAIL.
- `NOT_APPLICABLE` — recorded as a descriptive status only in 0.2; it does **not** satisfy a mandatory family.

One FAIL fails the applicable profile. Missing or inconclusive mandatory work makes it incomplete. No score can average away a failed control.
