# Asimov Implementation Handbook

## Build around the deployment you already have

Asimov does not require an Asimov runtime. An implementation connects six native surfaces to the conformance adapter:

| Surface | What Asimov needs | Typical source |
|---|---|---|
| Action driver | Exercise the real agent/action path | Agent SDK, API, orchestrator |
| Authority controller | Issue and revoke bounded authority | IAM, token broker, policy engine, leases |
| Resource oracle | Observe the real external effect independently | Database, filesystem, cloud API, queue, downstream service |
| Lifecycle controller | Restart, partition, stop, and fault the deployment | Kubernetes, systemd, launchd, Windows SCM, cloud control plane |
| Supervisor | Authenticated intervention outside the actor | Separate service, policy gateway, ACS/AGT host, operator control plane |
| Evidence | Reconstruct control decisions and outcomes | OpenTelemetry, audit DB, cloud audit, AAS-1, resource-side logs |

A seventh surface—**verification**—binds the assessment, evidence, and report after testing.

Reviewer assignment is deliberately **not** an adapter surface. The adapter exposes technical controls and evidence; the assessment layer assigns HUMAN, ROLE_SEPARATED, or THIRD_PARTY reviewers and records their signed judgments. Do not hide reviewer independence logic inside framework glue.

---

## The universal implementation sequence

### 1. Draw the real action surface

List every route that can cause a consequential effect:

- normal function/tool calls;
- hosted/provider tools;
- shell or subprocess execution;
- direct SDK or HTTP access;
- browser/computer control;
- MCP servers;
- scheduled/background work;
- delegated agents/jobs;
- credentials available to generated code;
- provider-side operations the local framework does not mediate.

Asimov tests the deployment that exists, not only the framework API that is easiest to instrument.

### 2. Choose an independent resource oracle

The oracle answers **what actually happened**.

Examples:

- PostgreSQL: read the target row/event/audit table with an assessor identity unavailable to the actor;
- S3/object storage: inspect object version, metadata, CloudTrail/resource audit, or bucket state;
- filesystem: inspect from a separate process/account or disposable test workspace;
- HTTP API: use the target service's authoritative GET/audit endpoint;
- queue/job system: inspect queue state and worker admission records;
- Kubernetes: inspect API-server state rather than agent text.

### 3. Connect authority

The adapter needs to create, bound, expire, and revoke test authority through the same mechanism production uses. Do not create a test-only permission system.

### 4. Connect lifecycle and supervision

A2 needs effective human restriction and revocation. A3 needs supervision outside the acting principal's authority. A4/A5 progressively require failure, partition, secondary containment, and independent assurance paths.

### 5. Run `doctor`

```bash
asimov doctor --level A3
```

Every missing mandatory surface is a blocker with remediation. Wire the missing real control, then rerun.

### 6. Plan the human-review boundary

Human review is part of the implementation, not an after-the-fact comment box. Before a real assessment, identify:

| Catalog review requirement | Implementation consequence |
|---|---|
| `NONE` | No family-specific human adjudication |
| `HUMAN` | Assign a named competent reviewer |
| `ROLE_SEPARATED` | Assign someone outside the implementation/control-owner role |
| `THIRD_PARTY` | Engage a separate legal entity from the Assessment Subject |

For every human-reviewed item, preserve the reviewer name, role, organization, Assessment Subject organization, evidence references, rationale, decision, and expected Sigstore signing identity. `THIRD_PARTY` additionally requires signed declarations covering legal-entity separation, subject control of the assessment, outcome-contingent compensation, and disclosed conflicts.

Do not use a different employee and call it third-party. Do not use an outside contractor as third-party if the Assessment Subject controls the finding. Payment by the Assessment Subject is allowed; payment contingent on a passing result is not.

### 7. Sign each completed review

The reviewer signs the **review record**, not merely the final report:

```bash
asimov sign-review reviews/requirements/ACC-006.json \
  --provider google \
  --identity reviewer@example.org
```

This creates a companion `.sigstore.json` bundle. Generated assessment preconditions are structured and bound by the final package, but do not require separate Sigstore review attestations in Asimov 0.2.

Verify a review directly:

```bash
asimov verify-review reviews/requirements/ACC-006.json
```

A valid signature establishes the authenticated signer and binds the exact record. It does not independently prove undisclosed corporate relationships or conflicts.

---


# Provider & stack assistance

Provider APIs move faster than Asimov Core. The canonical provider/runtime
taxonomy now lives in:

- `asimov_conformance/adapter_catalog.json` — machine-readable mappings used
  by Studio and the scaffold generator;
- [Provider & Stack Guide](ADAPTER-PROVIDERS.md) — current human-readable
  guidance and important non-equivalences.

Use the same guidance from either interface:

```bash
asimov studio
```

Open **Adapter Assistant** and choose the runtime, hosting, authority system,
protected resources, and evidence sources.

Or from the CLI:

```bash
asimov adapter-catalog

asimov adapter-scaffold \
  --runtime openai-agents-api \
  --hosting kubernetes \
  --authority aws-iam \
  --resource postgresql \
  --evidence opentelemetry \
  --evidence resource-audit \
  --output ./asimov-adapter
```

The generator is intentionally fail-closed. A starter adapter reports an empty
capability set. Selecting a provider does **not** prove that any Asimov control
exists; it only supplies a current wiring map and TODO scaffold.

## Current runtime families

The catalog distinguishes architectures that used to be collapsed under one
vendor name:

- **OpenAI:** Agents API, Agents SDK, or a custom loop around Responses;
- **Anthropic:** Claude Managed Agents, Claude Agent SDK, or a custom Messages
  API loop;
- **Google:** Agent Development Kit (ADK), local or hosted;
- **Microsoft:** Agent Framework agents/workflows/harness/hosting;
- **LangGraph / LangChain agents;**
- **CrewAI;**
- **custom/local open-weight stacks** such as Python, Ollama, vLLM, and
  llama.cpp.

MCP is modeled separately as a tool/integration boundary. Every consequential
MCP server/tool family remains part of the action surface.

The architecture rule does not change across providers:

> **Framework hooks tell you what the agent attempted. Independent authority,
> resource, lifecycle, supervision, and evidence surfaces establish whether
> control actually held.**

For provider-specific mappings and current official documentation links, use
[ADAPTER-PROVIDERS.md](ADAPTER-PROVIDERS.md).

---

# Infrastructure patterns

## Kubernetes

Typical mapping:

- service account / workload identity -> actor identity;
- NetworkPolicy / service mesh / gateway -> network mediation;
- admission/policy layer -> authority boundary;
- Kubernetes API -> lifecycle controller;
- pod/process restart -> persistence tests;
- namespace/test environment -> disposable fault fixtures;
- cloud/resource API -> independent effect oracle.

For A4, exercise node/network/control-plane degradation and ensure the intervention path does not share every failure dependency with the agent workload.

## Docker / single host

Use a separate control process/container and keep actor credentials narrower than operator/supervisor credentials. Mount test resources explicitly. Do not give the agent access to the Docker socket if container isolation is part of the claimed boundary.

---

# Cloud authority patterns

## AWS

Common building blocks:

- IAM roles / STS credentials;
- session/resource policies;
- explicit deny at the protected resource;
- CloudTrail and service-native audit records;
- short-lived credentials for bounded residual authority.

For revocation tests, measure **resource-side effectiveness**. A control-plane API response is not the end of the test; cached/session credentials and propagation delay belong in the declared residual interval.

## Microsoft Azure

Common building blocks:

- Microsoft Entra identities / managed identities;
- Azure RBAC and resource policies;
- Key Vault or equivalent credential authority;
- Azure Monitor / resource logs.

Token lifetime and authorization propagation are part of revocation semantics. The adapter should measure when the resource actually stops accepting the authority.

## Google Cloud

Common building blocks:

- service accounts / workload identity;
- IAM policies and short-lived credentials;
- resource-specific IAM;
- Cloud Audit Logs.

Again, the resource oracle decides when revocation becomes effective.

---

# Resource-oracle recipes

## PostgreSQL

Best pattern:

- actor uses restricted application role;
- assessor/resource oracle uses separate read/audit identity;
- mutations occur in disposable schema/table;
- audit/event rows correlate request, authority, and outcome;
- revocation uses role/session/credential controls that can be exercised safely.

## Object storage

Observe object existence/version/metadata from an assessor identity. Test normal SDK paths plus direct HTTP/alternate credential routes available to the actor.

## Filesystem

Use a disposable directory and observe from a separate process/identity where possible. For A4, the actor must not be able to bypass mediation using raw filesystem privileges.

## HTTP APIs

Create a synthetic endpoint or test tenant. The resource oracle should query authoritative server state or server-side audit—not the agent's HTTP response alone.

## Queues and background jobs

Track enqueue, admission, execution, cancellation, retry, and orphan status. Root revocation must extend to queued and delegated work within the declared bound.

---

# Evidence patterns

Preferred sources can be composed:

- OpenTelemetry traces for correlated runtime events;
- cloud audit logs for IAM/resource events;
- AAS-1 records for agent action/audit evidence;
- database/resource audit for effect truth;
- Asimov evidence manifests for package integrity;
- Sigstore for signer identity, signed timestamp, and transparency proof.

Evidence systems should preserve disagreement. If the orchestrator says "success" and the resource says "denied," both belong in the assessment.

---

# Example adapter layout

```text
my_asimov_adapter/
  adapter.py
  providers/
    driver.py
    authority.py
    resource.py
    lifecycle.py
    supervision.py
    evidence.py
  fixtures/
    disposable_target.py
  tests/
    test_adapter_contract.py
```

The top-level adapter composes the providers. Framework-specific code stays in the driver; AWS/Azure/GCP/database/Kubernetes integrations remain reusable across agent frameworks.

---

# Assessment, review, and verification workflow

For external deployments, prefer the staged workflow because it generates the correct review records and binds their attestations into the evidence package.

```bash
# 1. Prepare scope, review obligations, and organization identities.
asimov prepare-assessment \
  --adapter ./my_adapter.py:MyAdapter \
  --level A5 \
  --assessor "Assessment Team" \
  --subject-organization "Example AI Corp" \
  --assessor-organization "Independent Safety Labs" \
  --mode independent_assessment \
  --output ./assessment

# 2. Acknowledge obligations, run probes, and complete the generated JSON reviews.
asimov acknowledge-assessment ./assessment \
  --reviewer "Assessment Lead" \
  --reviewer-role "Lead assessor"

asimov run-assessment ./assessment --adapter ./my_adapter.py:MyAdapter

# 3. After each human decision is complete, sign its exact record.
asimov sign-review assessment/reviews/requirements/ACC-006.json \
  --provider google \
  --identity reviewer@independent.example

# Repeat sign-review for every completed HYBRID / REVIEW_REQUIRED family review.
# Preconditions remain structured records but do not each require a separate Sigstore attestation in 0.2.

# 4. Finalize only after required review attestations exist.
asimov finalize-assessment ./assessment

# 5. Authenticate the overall package/report.
cd assessment
asimov sign-report report.html \
  --statement asimov-statement.json \
  --provider google \
  --identity assessor@independent.example

# 6. Verify evidence binding, package provenance, and all review attestations.
asimov verify-package assessment.json \
  --evidence-manifest evidence-manifest.json \
  --evidence-root ./evidence \
  --statement asimov-statement.json \
  --report report.html \
  --bundle asimov.sigstore.json \
  --certificate-identity assessor@independent.example \
  --certificate-oidc-issuer https://accounts.google.com \
  --json-output verification-receipt.json \
  --html-output verification-receipt.html
```

`verify-package` checks each copied **test-family** review record's companion Sigstore attestation in addition to evidence integrity, report/scope binding, and the package signer. Planning/precondition records remain bound by the evidence manifest but do not each require a separate review signature in 0.2.

See [Human review and reviewer attestations](REVIEW-ATTESTATIONS.md) for the field-by-field implementation contract and THIRD_PARTY examples.

For public readers, the website remains static. The definitive cryptographic signer check is performed locally with `asimov verify-report`; no Asimov verification service is required.
