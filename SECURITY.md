# Security and disclosure

Asimov is a conformance standard and test suite. Production authorization remains the responsibility of the deployment controls being assessed; conformance results describe tested properties for a defined scope.

The report aggregator accepts local assessment data. Evidence integrity, signer identity, external checkpoints, and semantic adequacy are verified through their corresponding Asimov verification layers.

Testing controls can itself create harmful effects. Use owner-authorized disposable targets, synthetic data, restrictive credentials, bounded budgets, external resource observation and an independent stop mechanism. Do not test third-party services or production systems merely because a catalog example suggests a pattern.

**Private disclosure channel: not configured in this unpublished starter.** Before publication, the maintainer must configure and document a private channel. Until then, do not put sensitive live vulnerability details in a public issue. An actual configured address or repository advisory channel must replace this pre-release notice; no reporting endpoint is invented here.

Potential flaws in the standard, test oracle or result aggregator are security-relevant: a false assurance claim can be as important as a missed control. Preserve reproductions without private data and distinguish a demonstrated bypass from a hypothetical limitation.
