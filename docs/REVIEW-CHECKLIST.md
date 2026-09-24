# Founding draft review checklist

This checklist is a review aid, not another scored conformance profile.

**Scope:** Does the manifest cover outputs consumed by automation, outbound provider requests, browser sessions, direct APIs, subprocesses, callbacks, queues and remote jobs? Does a component-only result remain visibly component-only?

**Trust boundary:** Can generated code run with the same privileges as the supervisor? Can a tool's broader credential act as an unbounded deputy? Are monitor identity and decision channels protected? Which host, identity, operator and provider assumptions remain?

**Evidence:** Can an external observer distinguish a proposed action from a committed one? Are timeouts and uncertain outcomes explicit? What can the actor, operator and storage administrator each rewrite? How is truncation or rollback detected, and what tail remains unanchored?

**Revocation:** Are the deadlines tied to hazards and measured from a documented point? Do admission, completion and irreversibility have separate semantics? Do queues, cached credentials, child grants, disconnected recipients and restored checkpoints remain revoked?

**Delegation:** Are capability scope and aggregate budgets conserved? Are nested and scheduled tasks visible? Does a signed recipient manifest receive authority without independently establishing the recipient's constraints?

**Human control:** Is the stop path independent of agent cooperation and the normal UI? Does a restart preserve the latch? Does approval bind to the real executable action? Does load cause silent auto-approval or unusable intervention?

**Test quality:** Does a vulnerable variant fail? Can the target pass by refusing everything? Does the direct driver have the agent's real effective permissions? Are unexecuted branches and missing evidence visible? Are stochastic results reported as empirical trials rather than proof?

**Claim discipline:** Is the profile versioned and deployment-bound? Are A0 and A4/A5 correctly described? Are self-assessment and independent review distinguished? Are mutable model references labeled? Is conformance being confused with ethical correctness or domain safety?

**Interoperability:** Could another implementer satisfy the requirement without this package? Is there an existing ACS, ControlArena, identity, or telemetry mechanism to reuse? Is the contribution genuinely useful beyond a different set of names?
