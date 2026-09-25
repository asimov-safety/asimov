# Asimov Provider & Stack Guide

**Catalog checked:** September 25, 2026

This guide answers one practical question:

> **I already use a particular agent framework, cloud, and resource stack. How do I connect it to Asimov?**

The machine-readable source for these mappings is
`asimov_conformance/adapter_catalog.json`. Studio and the CLI use that same
catalog.

## Start with the Adapter Assistant

The easiest path is Studio:

```bash
asimov studio
```

Open **Adapter Assistant**, choose the runtime, hosting, authority system,
protected resources, and evidence sources, then generate a starter.

The CLI exposes the same capability:

```bash
asimov adapter-catalog

asimov adapter-scaffold \
  --runtime openai-agents-api \
  --hosting kubernetes \
  --authority aws-iam \
  --resource postgresql \
  --evidence opentelemetry \
  --evidence resource-audit \
  --integration mcp \
  --output ./asimov-adapter
```

A generated adapter intentionally reports **zero capabilities**. It is a wiring
guide, not a conformance shortcut. Add a capability only after its real
deployment surface is implemented and testable.

## The six questions every stack must answer

| Asimov surface | Question |
|---|---|
| Action driver | How does Asimov exercise the real agent/tool route? |
| Authority controller | What real mechanism grants, bounds, expires, and revokes authority? |
| Resource truth | What authoritative source tells Asimov what actually happened? |
| Lifecycle | What can safely restart, partition, stop, or fault the deployment? |
| Supervision | What authenticated intervention path remains outside actor authority? |
| Evidence | What records reconstruct requests, decisions, effects, failures, and control changes? |

Framework hooks are often useful for **attempt** and **orchestration** evidence.
They are rarely enough by themselves for **authority** or **resource truth**.

---

# Current agent runtimes

## OpenAI Agents API

OpenAI's current recommendation for new agent applications is the **Agents API**,
which runs a managed Codex harness. OpenAI manages the harness, orchestration,
durable session state, and—when selected—hosted sandbox infrastructure. Your
application still owns surrounding integrations and chooses where execution
occurs.

**Asimov mapping**

- **Action:** real Agents API session/task/event flow.
- **Authority:** external IAM, policy gateway, or resource-side authorization
  for consequential tools; credentials should remain outside agent-controlled
  sandboxes.
- **Resource truth:** authoritative database/API/cloud resource.
- **Lifecycle:** Agents environment/session controls plus your application's
  hosting control plane.
- **Supervision:** operator/policy/infrastructure path outside the session.
- **Evidence:** Agents events + application integration logs + resource/provider
  audit.

**Do not assume:** provider session history proves that an external resource
changed. Provider-hosted tools and sandboxes are real action surfaces that must
remain in scope.

Starter:

```bash
asimov adapter-scaffold --runtime openai-agents-api --output ./asimov-adapter
```

Official docs: https://developers.openai.com/api/docs/guides/agents

## OpenAI Agents SDK

The Agents SDK agent loop runs in your application. OpenAI now describes it as
feature-complete: maintenance and compatibility work continue, but major new
features are not planned, and the Agents API is recommended for new agent
applications.

This architecture gives you more direct application hooks, but it does **not**
make those hooks independent enforcement.

**Asimov mapping**

- **Action:** SDK Runner/application entry point.
- **Authority:** real IAM/resource authorization or an external policy layer.
- **Resource truth:** target DB/API/filesystem/cloud service.
- **Lifecycle:** application process/container/orchestrator.
- **Supervision:** separate service or infrastructure control plane for A3+.
- **Evidence:** SDK traces/tool/handoff/session events + resource-side evidence.

Official docs: https://developers.openai.com/api/docs/guides/agents/sdk

## OpenAI Responses API / custom loop

Use this selection when your application owns the loop around Responses rather
than using the managed Agents API or the Agents SDK.

Hosted capabilities and client-executed tools may have different trust
boundaries. Keep them distinct in the action inventory.

Official overview: https://developers.openai.com/api/docs/guides/agents

---

## Claude Managed Agents

Claude Managed Agents is Anthropic's managed harness. Anthropic can host the
agent loop, tool execution, long-running state, and sandbox environment; the
platform also supports self-hosted environments.

**Asimov mapping**

- **Action:** managed session/event API.
- **Authority:** environment/tool policy plus external resource/IAM controls.
- **Resource truth:** protected resource or service audit.
- **Lifecycle:** Managed Agent session/environment controls plus any self-hosted
  infrastructure control plane.
- **Supervision:** operator/policy path outside the agent session.
- **Evidence:** session events + environment logs + resource/IAM audit.

Built-in and MCP tools are individual action paths. Do not hide them behind the
single label "Managed Agent."

Official docs: https://platform.claude.com/docs/en/managed-agents/overview

## Claude Agent SDK

The Claude Agent SDK runs the harness in a process you operate. Anthropic's
migration documentation explicitly distinguishes this from Managed Agents:
the Agent SDK runs locally/in your infrastructure, while Managed Agents moves
the harness into Anthropic infrastructure.

Hooks and permission callbacks are useful adapter surfaces. A hook with the
same unrestricted privileges as generated code is not automatically an
independent authority boundary.

Official migration/reference:
https://platform.claude.com/docs/en/managed-agents/migration

## Claude Messages API / custom loop

Use this path when your application owns the tool loop. Anthropic distinguishes
client tools that your application executes from server tools executed by
Anthropic. Asimov should preserve that distinction in the action surface.

Official tool-use docs:
https://platform.claude.com/docs/en/agents-and-tools/tool-use/overview

---

## Google Agent Development Kit (ADK)

ADK can run locally or in Google-hosted infrastructure. Current Google agent
tooling includes ADK, Agent Runtime/Cloud Run/GKE deployment paths, callbacks,
sessions/events, and sandboxed code-execution options.

**Asimov mapping**

- **Action:** ADK runner/workflow or deployed endpoint.
- **Authority:** service accounts/workload identity and resource IAM.
- **Resource truth:** target application or Google Cloud resource.
- **Lifecycle:** Agent Runtime, Cloud Run, GKE, or local process controls.
- **Supervision:** operator/cloud path outside the agent's service identity.
- **Evidence:** ADK events/traces + Cloud Audit Logs + resource truth.

Callbacks are orchestration hooks, not automatically independent enforcement.

Official docs: https://google.github.io/adk-docs/

---

## Microsoft Agent Framework

Microsoft Agent Framework is Microsoft's current agent SDK layer with agents,
workflows, harness agents, middleware, sessions, HITL, checkpoints/resume, and
multiple hosting paths. Current documentation supports Python and .NET, with Go
also developing under preview/current feature constraints.

**Asimov mapping**

- **Action:** agent run, workflow, or harness-agent entry point.
- **Authority:** Entra/RBAC, workload identity, resource policy, or separate
  policy gateway.
- **Resource truth:** protected destination service.
- **Lifecycle:** selected self-hosted/Azure Functions/durable hosting control.
- **Supervision:** authenticated governance/operator path outside actor
  authority.
- **Evidence:** framework events/checkpoints + Azure/resource audit.

Official docs: https://learn.microsoft.com/en-us/agent-framework/

---

## LangGraph / LangChain agents

LangGraph's durable graph execution, checkpoints, interrupts, and deployment
runtime are useful orchestration/lifecycle surfaces.

A checkpoint says what the graph believes happened. It is **not** proof that a
database row, API-side state, queue item, or cloud resource actually changed.

Recommended composition:

```text
LangGraph / LangChain
        |
 policy / IAM boundary
        |
     tool/API -------- protected resource
        |                    |
 graph/checkpoint       resource audit
          \              /
             evidence
```

Official docs: https://docs.langchain.com/oss/python/langgraph/overview

---

## CrewAI

CrewAI's current architecture uses agents, crews, and flows. A flow can provide
the surrounding state/control workflow while crews perform agent work.

Crew roles are behavioral descriptions, not authenticated security identities.
Consequential authority should be tied to external principals and resource
authorization.

Official docs: https://docs.crewai.com/

---

## Custom / local open-weight stack

Use this for custom Python, Ollama, vLLM, llama.cpp, and similar systems.

Owning the entire stack makes integration easier, but it does not make the
surfaces independent. For A3+, the only stop/supervisor latch should not live
inside the same unrestricted process that executes generated code.

Typical lifecycle boundaries:

- macOS: launchd / process controller;
- Linux: systemd, containers, cgroups, namespaces;
- Windows: Service Control Manager, Job Objects, identities/ACLs;
- larger deployments: Kubernetes or cloud orchestration.

---

# MCP

Model Context Protocol is an integration/transport layer, not one universal
Asimov control.

Every consequential MCP server/tool family belongs in the action inventory.
Different servers may have different identities, authorization models,
deployment locations, resource effects, and audit quality.

The MCP client saying "tool succeeded" is not an independent resource oracle.

Official docs: https://modelcontextprotocol.io/docs/

---

# Hosting and lifecycle

## Local process

Use OS process/service controls. For A3+, separate actor and supervision
privileges.

## Docker

Use separate control containers/processes. Do not expose the Docker socket to
the actor if container isolation is part of the claimed boundary.

## Kubernetes

Use workload identity, NetworkPolicy/service mesh/policy gateways where
appropriate, and the Kubernetes API for lifecycle operations. A4/A5 testing
should exercise partitions and common-mode dependencies rather than only normal
pod restarts.

## AWS

Use IAM roles/STS, short-lived authority, resource policies, and CloudTrail or
service-native audit. Measure revocation when the protected resource stops
accepting the authority—not when the IAM API returns success.

## Azure

Use Entra identities/managed identities, Azure RBAC/resource policies, Key
Vault or equivalent credential authority, and Azure/resource logs. Token
lifetimes and propagation belong in the revocation bound.

## Google Cloud

Use service accounts/workload identity, short-lived credentials, resource IAM,
and Cloud Audit Logs. Again, resource-side effectiveness is the measurement.

---

# Protected resource recipes

## PostgreSQL / SQL

Use a restricted actor/application role and a separate assessor/audit identity.
Run mutations in a disposable database/schema/table. Correlate database truth
with action and authority records.

## HTTP / SaaS APIs

Use a synthetic endpoint or test tenant. Query authoritative server-side state
or audit after the action.

## Filesystem

Use a disposable directory. Prefer observation from a separate process or
identity when the profile requires stronger separation.

## Object storage

Observe object version/existence/metadata and provider audit from an assessor
identity.

## Queues / background jobs

Track enqueue, admission, execution, cancellation, retry, and orphan state.
Revocation must include queued/delegated work within the declared bound.

## Cloud control-plane resources

Use the provider API/resource state plus cloud audit. Never treat the model's
returned text as the effect oracle.

---

# Keeping this guide current

Provider APIs evolve faster than the Asimov Core specification.

The update order is:

1. update `asimov_conformance/adapter_catalog.json`;
2. update this guide where the conceptual architecture changed;
3. tests verify that Studio and generated scaffolds still consume the catalog;
4. the public Architecture page renders the catalog rather than maintaining its
   own provider taxonomy.

Provider-specific mappings are informative implementation guidance. The
normative pass/fail requirements remain in Asimov Core and the Test Catalog.
