# Ecosystem crosswalk and originality boundary

**Reviewed September 24, 2026.** These are contextual mappings, not endorsements or tested integrations. The field is active enough that Asimov should assume upstream projects will evolve quickly.

| Existing work | What it already does | Overlap with Asimov | What Asimov should do |
|---|---|---|---|
| OWASP Agent Control Standard (ACS) | Runtime Guardian wire protocol, lifecycle hooks, allow/deny/modify/ask/defer decisions, Trace/Inspect pillars, audit chain, conformance profiles | **High at the runtime-control plumbing layer** | Reuse/map ACS as an implementation path. Do not invent a competing wire protocol. Asimov tests whether deployment-level control properties actually hold. |
| Microsoft Agent Governance Toolkit (AGT) | Extensive runtime policy, identity, sandboxing, zero-trust agent mesh, SRE/chaos features, evidence verification, multi-language SDKs; current public preview has thousands of tests | **High for implementation mechanisms** | Treat AGT as a potential reference implementation of many Asimov requirements, not as evidence that those requirements are universally satisfied. |
| ControlArena (UK AISI / Redwood) | Infrastructure for AI-control experiments with untrusted models, monitors, control protocols, and adversarial settings | **Medium for A4/A5 experimental methodology** | Reuse for adversarial campaigns/statistical control evaluations where appropriate. It is not itself a deployment conformance standard. |
| AAS-1 Agent Auditability Standard | Portable audit-grade action records, SHA-256/JCS, signatures, timestamping, Merkle batching, audit assertions and auditor determinations | **High for accountability/evidence format** | Map ACC requirements to AAS-1 where possible. Do not invent a rival action-log schema merely to carry Asimov branding. |
| Sigstore / in-toto | Identity-bound artifact signing, transparency proofs, general attestation statement model | **High for evidence authenticity** | Use them for Asimov report/evidence attestations instead of custom cryptography. |
| OpenTelemetry GenAI conventions | Shared telemetry vocabulary and traces | **Medium for observation transport** | Export/consume compatible events, while separately testing completeness and trust boundaries. |
| MCP security guidance | Protocol-specific authorization and trust-boundary mitigations | **Medium for MCP-enabled paths** | Use MCP-specific test branches; never equate MCP support with Asimov conformance. |
| NIST AI Agent Standards Initiative | Standards/interoperability initiative encouraging secure and interoperable agent ecosystems | **Strategic context** | Align vocabulary and submit/comment when mature; no endorsement implied. |
| ISO/IEC 42001 / NIST AI RMF | Organizational AI management and risk-governance frameworks | **Low-to-medium** | Crosswalk organizational obligations to technical evidence; Asimov should not try to replace management-system standards. |

## How close is existing work?

### OWASP ACS: closest on the control interface

ACS is substantially closer than a simple "hook spec." Its current repository describes a Guardian that intercepts agent lifecycle events, includes an audit chain, defines conformance profiles, and supports optional trace/inspection/provenance/signing profiles. Its v0.1 reference implementation is still early: the public documentation calls out incomplete authentication and fail-open behavior in the reference Guardian and states that no independent party verifies self-declared conformance in v0.1.

**Conclusion:** duplicating ACS would be wasteful. Asimov can instead say *what must be true* (e.g., revocation survives partitions) and accept ACS as one possible mechanism for achieving/testing it.

### Microsoft AGT: closest on production mechanisms

AGT is broad and increasingly production-oriented: policy enforcement, identity, sandboxing, runtime evidence, chaos/reliability work, ACS integration, and multi-language SDKs. It is much more software than Asimov should attempt to become.

**Conclusion:** Asimov should not build another runtime-governance platform. It should test properties across AGT, proprietary vendor controls, cloud IAM, local sandboxes, ACS guardians, or other implementations.

### ControlArena: closest on adversarial control research

ControlArena helps researchers run experiments against potentially untrusted models and compare monitoring/control strategies. That is directly useful for Asimov A4/A5 adversarial methodology, but a research evaluation environment is not the same as a vendor-neutral deployment conformance profile tied to real permissions, revocation, human intervention, and evidence.

### AAS-1: closest on accountability evidence

AAS-1 has already done significant work on exactly the area an earlier Asimov design might otherwise reinvent: canonical records, hashes, identity binding, signatures, timestamps, Merkle aggregation, auditor assertions, and audit engagements.

**Conclusion:** Asimov should narrow `Accountability` to the control/evidence properties needed for its conformance claim and support AAS-1 as a preferred evidence source/profile where technically compatible.

## What is still plausibly distinct?

The hypothesis worth testing is a **small deployment-level control model that is implementation-agnostic and falsifiable**:

1. Seven memorable control invariants.
2. Cumulative A0–A5 assurance profiles with no averaging.
3. Operational tests of real authority, revocation, oversight isolation, delegation, human intervention, and accountability.
4. Higher profiles that explicitly test hostile workloads, partitions, common-mode failure, independent control paths, and domain-critical safety cases.
5. Verifiable evidence binding without declaring any one runtime framework to be the standard.

That is not obviously duplicated by ACS, AGT, ControlArena, AAS-1, NIST, or ISO individually. The risk is **combinatorial duplication**: those projects together cover most primitives. Asimov only has legs if the Seven-Constant abstraction and conformance semantics prove useful enough that implementers prefer a common cross-framework claim rather than separate vendor-specific claims.

## Primary references

- OWASP ACS: https://github.com/GenAI-Security-Project/agent-control-standard
- Microsoft AGT: https://github.com/microsoft/agent-governance-toolkit
- ControlArena: https://github.com/UKGovernmentBEIS/control-arena
- AAS-1: https://aas-1.org/
- Sigstore: https://docs.sigstore.dev/
- in-toto: https://in-toto.io/
- OpenTelemetry GenAI: https://github.com/open-telemetry/semantic-conventions-genai
- NIST AI Agent Standards Initiative: https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative
