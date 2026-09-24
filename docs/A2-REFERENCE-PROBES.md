# Executable A2 Reference Harness

**Status:** implemented in the disposable reference target; not an external conformance result.

The A2 milestone gives every A1/A2 normative family an executable semantic probe and a paired deliberate control-removal mutation. A probe is retained only when the hardened reference target passes and the matching mutation fails.

## 21 implemented A1/A2 families

- Observable Agency: `OBS-001` through `OBS-004`
- Accountability: `ACC-001` through `ACC-004`
- Mediated Action: `MED-001` through `MED-004`
- Revocable Authority: `REV-001` through `REV-004`
- Protected Oversight: `OVR-001`
- Bounded Delegation: `DEL-001`, `DEL-002`
- Human Authority: `HUM-001`, `HUM-002`

`HUM-003` is also implemented ahead of the full A3 tranche.

## Mutation rule

Each reference control has a Boolean mutation that removes the exact property under test. `reference-mutations` requires the corresponding probe to return `FAIL`. This prevents a probe that simply returns green on the happy path from masquerading as useful assurance.

## Coverage rule

For external adapters, missing mandatory semantic capabilities are not a weak pass and are not averaged. `doctor` reports them as profile blockers and provides remediation. The operator should close the gap by adding or composing the needed provider—for example, a resource oracle, external authority controller, lifecycle provider, or evidence oracle.

## Cross-platform rule

Probe semantics are Python/OS-neutral. Low-level platform differences belong behind providers. CI exercises the core on Ubuntu, macOS, and Windows. Linux-, macOS-, or Windows-specific enforcement providers may be separate packages if they require native APIs.
