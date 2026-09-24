# Security and disclosure

This is an experimental specification and report-aggregation prototype. It is **not a security boundary**, sandbox, runtime supervisor or certification verifier. Do not use its exit codes or profile labels as a production authorization decision.

The prototype accepts local JSON and performs no agent execution, remote evidence fetch, network probing or signature verification. Evidence references are strings; their existence, authenticity and adequacy are not verified. Treat reports and claimed assessor identities as untrusted until separately reviewed.

Testing controls can itself create harmful effects. Use owner-authorized disposable targets, synthetic data, restrictive credentials, bounded budgets, external resource observation and an independent stop mechanism. Do not test third-party services or production systems merely because a catalog example suggests a pattern.

**Private disclosure channel: not configured in this unpublished starter.** Before publication, the maintainer must configure and document a private channel. Until then, do not put sensitive live vulnerability details in a public issue. An actual configured address or repository advisory channel must replace this pre-release notice; no reporting endpoint is invented here.

Potential flaws in the standard, test oracle or result aggregator are security-relevant: a false assurance claim can be as important as a missed control. Preserve reproductions without private data and distinguish a demonstrated bypass from a hypothetical limitation.
