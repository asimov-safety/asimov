# Asimov Studio

Asimov Studio is the local, browser-based interface for the Asimov reference implementation.

It is designed for people who want the rigor and portability of Asimov assessments without hand-editing JSON and Markdown files.

## Standard versus implementation

**Asimov Core does not require Python.** The standard defines deployment properties, evidence requirements, review relationships, and result semantics that can be implemented in any language.

The current **Asimov reference engine and Asimov Studio require Python 3.10+**. Studio is a user interface over that same engine. It does not define a second set of assessment rules.

## Launch

After installing Asimov:

```bash
asimov studio
```

or:

```bash
asimov ui
```

Studio chooses an available local port and opens your browser automatically.

To open a specific assessment workspace:

```bash
asimov studio --workspace ./assessment
```

To print the URL without opening a browser:

```bash
asimov studio --no-browser
```

## What Studio does

Studio supports the full staged assessment workflow:

0. **Adapter Assistant** — choose a current agent runtime, hosting model, authority system, protected resources, and evidence sources; inspect the six-surface mapping; optionally generate a fail-closed starter adapter.
1. **Workspace** — create or reopen an assessment and identify the deployment, assessor, organizations, adapter, and target assurance level.
2. **Scope** — describe the deployment, threat model, and explicit exclusions without editing `scope.json`.
3. **Readiness** — run the same fail-closed capability diagnostics as `asimov doctor`.
4. **Test** — acknowledge pre-run human obligations and run the same technical assessment engine as the CLI.
5. **Review** — complete structured preconditions and HUMAN / ROLE_SEPARATED / THIRD_PARTY family reviews using forms rather than raw JSON.
6. **Finish** — finalize the assessment, sign family-review judgments, sign the public report, and verify the complete package.

Studio writes the ordinary Asimov workspace files. A Studio-created assessment remains usable from the CLI, and a CLI-created assessment can be opened in Studio.

## Adapter Assistant

Provider APIs change faster than the Asimov Core specification. Studio's Adapter Assistant is driven by the packaged `adapter_catalog.json`, which distinguishes managed and application-owned runtimes rather than treating a vendor as one architecture.

The catalog currently covers OpenAI Agents API / Agents SDK / custom Responses loops, Claude Managed Agents / Claude Agent SDK / custom Messages loops, Google ADK and managed Agent Runtime, Microsoft Agent Framework and Foundry Agent Service, Amazon Bedrock AgentCore Runtime, LangGraph, CrewAI, custom/local open-weight stacks, MCP, common cloud/lifecycle options, authority systems, protected resources, and evidence sources.

Generated starters contain three files:

```text
adapter.py
README.md
asimov-adapter.json
```

The generated `capabilities()` is intentionally empty. Studio can suggest where a framework hook maps into Asimov, but it cannot turn the presence of a framework feature into proof that the deployment satisfies a control.

The same catalog/generator is available from the CLI with `asimov adapter-catalog` and `asimov adapter-scaffold`. See [Provider & Stack Guide](ADAPTER-PROVIDERS.md).

## Local-first architecture

Studio is intentionally not a hosted service.

```text
Browser
   |
   | localhost + per-launch session token
   v
Asimov Studio server
   |
   v
Existing Python assessment engine
   |
   v
Deployment adapter / native controls
```

The server:

- binds only to `127.0.0.1`;
- chooses a random session token on every launch;
- requires that token for every API action;
- does not enable CORS;
- sends restrictive browser security headers;
- stores no account or cloud-side Studio state;
- does not persist adapter settings or credentials into assessment files.

Adapter settings entered in Studio are held only in the browser session. The assessment workspace remains the durable source of truth.

## Review signing

For HYBRID / REVIEW_REQUIRED test-family judgments, Studio uses the same Sigstore/Cosign review-attestation flow as the CLI. When the reviewer selects **Save & sign review**, Studio writes the completed record, launches Cosign authentication, verifies the resulting attestation, and keeps the bundle beside the review record.

Editing a signed review invalidates that signature. Studio removes the old bundle and clears the expected signing identity so the changed judgment must be signed again.

Assessment preconditions remain structured and package-bound but are not individually Sigstore-attested in Asimov 0.2.

## No lock-in

Studio is a convenience layer, not a required conformance surface. Implementers may:

- use the CLI only;
- build another UI over the published formats;
- implement Asimov Core in another programming language;
- generate and verify conforming assessment artifacts independently.

The normative requirements remain in Asimov Core and the machine-readable catalog.
