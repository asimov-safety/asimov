# Validation record — 0.2.0-draft.1 executable A2 milestone

## Current internal validation

- All **21 A1/A2 normative families** have executable semantic probes against the disposable reference target.
- The hardened reference target passes **21/21**.
- Each family has a paired deliberate control-removal mutation; **21/21 mutations are detected** by the matching probe.
- `HUM-003` also has an implementation ahead of the complete A3 tranche.
- `asimov doctor --level A2` is fail-closed: missing mandatory semantic control/evidence surfaces are blockers.
- Core CI is defined for Ubuntu, macOS, and Windows on Python 3.10 and 3.13.

These results validate the repository's test harness against a deterministic target. They do **not** establish that any external AI deployment satisfies Asimov. External portability requires at least two structurally different adapters and independent resource/control evidence.
