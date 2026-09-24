# Asimov roadmap

## Current — executable A1–A5 reference harness

- Seven Safety Contracts.
- A0–A5 cumulative assurance profiles.
- 42 normative requirement families.
- **42/42 executable reference probes.**
- **42/42 paired deliberate control-removal mutations detected.**
- Framework-neutral semantic adapter interface.
- Fail-closed readiness diagnostics and reporting.
- Evidence digest/manifest tooling.
- Cross-platform core target: Linux, macOS, and Windows.

## Next — portability

1. Run the same A1–A5 semantics through independently designed real deployments.
2. Keep normative acceptance criteria fixed while adapters translate native controls.
3. Build reusable resource oracles for filesystem, HTTP/network, IAM/credentials, queues/jobs, databases, and cloud resources.
4. Publish compatibility matrices by semantic capability and profile.

## Verification

- publish an Asimov in-toto predicate;
- add Sigstore/Cosign identity-bound attestations;
- verify signer identity, timestamp/transparency inclusion, scope/configuration binding, and evidence hashes;
- map/import AAS-1 action evidence where appropriate;
- distinguish integrity, identity, checkpoint, evidence-review, and independent-assessment verification states.

## External review

Invite review from AI-control research, security engineering, SRE, safety engineering, human factors, standards practitioners, and high-consequence domains. Incorporate review through AEPs and versioned releases.

## Adoption UX

- `asimov init` creates a cross-platform deployment scaffold.
- `asimov doctor --level A5` performs fail-closed readiness discovery.
- Provider composition minimizes framework-specific code.
- Missing mandatory observability/control surfaces are blockers, not partial credit.
