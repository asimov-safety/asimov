# Asimov roadmap

## Current — 0.2 / executable A3 milestone

- Seven Safety Contracts.
- A0–A5 cumulative assurance profiles.
- 42 normative requirement families.
- Framework-neutral semantic adapter interface.
- Fail-closed reporting and HTML/JSON results.
- Evidence digest/manifest prototype.
- **All 28 A1–A3 families have executable reference probes.**
- **All 28 have paired deliberate control-removal mutations detected by the matching probe.**
- Composable provider architecture and fail-closed `doctor` capability discovery.
- Cross-platform core target: Linux, macOS, and Windows.

## Next — M2 portability

1. Select a second, independently designed target (prefer ACS/AGT or a mainstream agent framework rather than another toy implementation).
2. Implement its adapter without changing normative acceptance criteria to make the target pass.
3. Run all 28 A1–A3 semantic probes. Missing mandatory control/evidence surfaces block A3 until remediated.
4. Refine adapter capability negotiation and evidence references based on real integration pain.
5. Add reusable direct-resource oracles for filesystem, HTTP/network, credential/IAM, queue/job, and database effects.

## M3 — executable A4

Implement the seven Hardened families: OBS-005, MED-005, REV-005, OVR-005, DEL-005, HUM-005, and ACC-005. Each must pass the hardened reference target and fail a paired deliberate mutation before inclusion.

## M4 verification

- publish an Asimov in-toto predicate draft;
- sign attestations with Sigstore/Cosign rather than custom cryptography;
- verify signer identity, timestamp/transparency inclusion, scope/configuration binding, and evidence hashes;
- map/import AAS-1 action evidence where appropriate;
- define explicit verification states (integrity verified, identity verified, checkpoint verified, evidence reviewed, independent assessment verified).

## M5 — executable A5 and external review

Implement the seven Critical families only alongside domain-safety and independent-review semantics. Invite review from AI-control research, security engineering, SRE, safety engineering, human factors, standards practitioners, and regulated/high-consequence domains.

## Adoption UX

- `asimov-draft init` creates a cross-platform deployment scaffold without overwriting an existing file.
- `asimov-draft doctor --level A3` performs fail-closed capability/readiness discovery.
- Provider composition minimizes framework-specific code: action driver, authority controller, resource oracle, lifecycle controller, supervision provider, and evidence oracle can come from different systems.
- Missing observability/control surfaces are blockers, not partial credit.
