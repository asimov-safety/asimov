# Asimov roadmap

## Current — 0.2 / executable A2 milestone

- Seven Safety Contracts.
- A0–A5 cumulative assurance profiles.
- 42 normative requirement families.
- Framework-neutral semantic adapter interface.
- Fail-closed reporting and HTML/JSON results.
- Evidence digest/manifest prototype.
- First nine executable reference probes.
- Nine paired mutation validations.
- CI and Pages-ready static site.

## Next — M2 portability

1. Select a second, independently designed target (prefer ACS/AGT or a mainstream agent framework rather than another toy implementation).
2. Implement its adapter without changing normative acceptance criteria to make the target pass.
3. Run all 21 A1/A2 semantic probes. Any missing mandatory control/evidence surface blocks the requested profile until remediated.
4. Refine adapter capability negotiation and evidence references based on real integration pain.
5. Add direct-resource oracle examples for filesystem, HTTP/network, credential/IAM, and queue/job effects.

## M3 verification

- publish an Asimov in-toto predicate draft;
- sign attestations with Sigstore/Cosign rather than custom cryptography;
- verify signer identity, timestamp/transparency inclusion, scope/configuration binding, and evidence hashes;
- map/import AAS-1 action evidence where appropriate;
- define explicit verification states (integrity verified, identity verified, checkpoint verified, evidence reviewed, independent assessment verified).

## M4 executable expansion

Implement additional deterministic/high-value families before stochastic monitor benchmarking, especially OBS-001/004, MED-003/004, REV-002/003, DEL-001/002/003, HUM-002/004, and ACC-001/004/005.

## M5 external review

Invite review from AI-control research, security engineering, SRE, safety engineering, human factors, standards practitioners, and regulated/high-consequence domains. A4/A5 should not be treated as mature until this review materially tests their assumptions.

## A2 executable reference milestone — completed in draft

All 21 A1/A2 families now have executable reference probes and paired deliberate mutations. Next: finish the remaining A3 probe tranche, then validate the same semantics through two structurally different external adapters.

## Adoption UX

- `asimov-draft init` creates a cross-platform deployment scaffold without overwriting an existing file.
- `asimov-draft doctor --level A2` performs fail-closed capability/readiness discovery.
- Provider composition should minimize framework-specific code: action driver, authority controller, resource oracle, lifecycle controller, and evidence oracle can come from different systems.
