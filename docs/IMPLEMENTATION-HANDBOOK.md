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


# Common framework patterns

## OpenAI Agents API / Agents SDK

OpenAI now distinguishes a managed **Agents API** from the application-hosted **Agents SDK**. For Asimov, the key question is where the action loop and enforcement actually run.

**Agents SDK:** the application owns the runtime, tool implementations, storage, approval decisions, and much of the execution path. This gives the adapter direct hooks into Runner/tool/handoff/session behavior.

**Agents API:** the managed harness becomes an additional provider-controlled action surface. Use the API as the action driver, but treat hosted tools and provider-side execution as distinct paths that require provider/resource-side evidence.

**Use for:** agent loop, tools, handoffs, sessions, tracing, human-in-the-loop.

Recommended mapping:

| Asimov surface | OpenAI Agents deployment |
|---|---|
| Action driver | `Runner` / application entry point |
| Function-tool observation | SDK tracing + application events |
| Delegation | handoffs / agents-as-tools, correlated with external authority records |
| Mediation | function-tool guardrails plus an external policy/authority layer |
| Resource oracle | the actual DB/API/filesystem/cloud resource |
| Supervisor | separate policy/supervisor service or infrastructure control plane |
| Evidence | SDK traces + external resource/audit evidence |

Important boundary: OpenAI's tool guardrail pipeline applies to function tools and configured local MCP tools, but several hosted/built-in tool paths use different execution pipelines. Treat provider-hosted capabilities as separate action paths and pair them with provider/resource-side evidence rather than assuming one SDK hook sees everything.

Official SDK: https://openai.github.io/openai-agents-python/

### Practical composition

```text
OpenAI Agents SDK      -> ActionDriver
AWS IAM / policy API   -> AuthorityController
PostgreSQL             -> ResourceOracle
Kubernetes             -> LifecycleController
separate supervisor    -> SupervisionProvider
OpenTelemetry + DB log -> EvidenceOracle
```

A1/A2 can usually be added with limited application changes. A3 requires the supervisor/control authority to live outside the agent's effective privileges.

---

## Claude Agent SDK

Recommended mapping:

- SDK client/session -> action driver;
- tool permission configuration -> declared capability surface;
- PreToolUse/PostToolUse hooks -> proposal/dispatch evidence and policy hooks;
- separate IAM/OS/cloud controls -> enforceable authority;
- target database/API/filesystem -> independent effect oracle;
- external supervisor process/service -> A3+.

Hooks are useful evidence and interception surfaces, but a hook running with the same unrestricted privileges as generated code is not automatically an independent enforcement boundary.

Official platform: https://platform.claude.com/

---

## Google Agent Development Kit (ADK)

Recommended mapping:

- ADK runner / workflow -> action driver;
- before/after agent, model, and tool callbacks -> orchestration evidence and mediation hooks;
- session/event service -> lifecycle evidence;
- Vertex/Google Cloud service account -> actor identity and authority;
- Agent Runtime sandbox / Cloud Run / GKE -> execution and lifecycle boundary;
- Cloud Audit Logs + protected resource state -> independent evidence.

ADK callbacks are excellent adapter hooks, but the protected resource or cloud control plane should remain the oracle for consequential effects.

Official documentation: https://google.github.io/adk-docs/

---

## LangGraph / LangChain

**Use for:** durable graph orchestration, tool execution, checkpoints, long-running agent workflows.

Recommended mapping:

- graph invocation / tool nodes -> action driver;
- middleware/callback/event surfaces -> proposal and lifecycle evidence;
- checkpoint store -> orchestration-state evidence, not the sole external oracle;
- database/API/cloud resource -> independent effect oracle;
- IAM/policy gateway -> authority and revocation;
- Kubernetes/process manager -> restart and partition fixtures;
- separate supervisor service -> A3+ intervention.

Do not treat a graph checkpoint as proof that an external action occurred. Observe the target resource itself.

A strong deployment pattern is:

```text
LangGraph
   |
policy gateway ---- IAM / short-lived capability
   |
tool/API ---------- protected resource
   |                     |
OTel trace          resource audit
        \             /
          evidence store
```

---

## CrewAI

**Use for:** role-based multi-agent teams, crews, tools, delegated work, MCP-connected capabilities.

Recommended mapping:

- crew kickoff/application API -> action driver;
- tool hooks/callbacks -> action proposal/dispatch evidence;
- agent/crew task graph -> delegation lineage;
- MCP/tool provider -> enumerate as individual consequential paths;
- external IAM/policy -> enforce authority independently of role prompts;
- target resource -> independent oracle;
- separate supervisor/operator path -> A3+.

Crew role definitions are descriptive context, not security identities. Bind consequential authority to authenticated principals outside model-written role labels.

---

## Microsoft Agent Governance Toolkit / OWASP ACS

This is a particularly natural Asimov integration because AGT/ACS already provides runtime-governance mechanisms.

Recommended mapping:

| Asimov | AGT / ACS role |
|---|---|
| action snapshot / request | ACS snapshot or framework hook |
| admission decision | Guardian/policy verdict |
| mediation | host enforcement |
| supervisor state | governance control plane |
| evidence | ACS/AGT trace + resource-side observation |
| fault/resilience | AGT SRE/chaos tooling plus infrastructure faults |

Asimov does not replace ACS or AGT. It supplies the cross-framework **property and conformance layer**: does the deployed combination actually satisfy the Constant under the tested threat model?

Microsoft AGT: https://microsoft.github.io/agent-governance-toolkit/

---

## Custom Python / local models / Ollama

This is often the easiest architecture to understand because you own the whole stack.

Suggested composition:

```text
Python orchestrator / local model API
             |
      tool dispatcher
             |
      policy boundary
       /           \
filesystem/DB      HTTP APIs
      |               |
separate observer / audit process
             |
       evidence store

independent supervisor process
             |
     stop / revoke state
```

For A3, do not put the only stop/supervisor latch in the same unrestricted process that runs generated code. Use a separate process/service or OS-level authority boundary.

Lifecycle providers by OS:

- macOS: launchd / process controller;
- Linux: systemd, containers, cgroups, namespaces;
- Windows: Service Control Manager, Job Objects, Windows identities/ACLs.

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
