# Validation status — executable A3 milestone

Current reference-harness validation:

- All **28 A1–A3 normative families** have executable semantic probes against the disposable reference target.
- The hardened reference target passes **28/28**.
- Each family has a paired deliberate control-removal mutation; **28/28 mutations are detected** by the matching probe.
- `doctor --level A3` reports the reference target ready with zero capability blockers.
- A2 remains a fully executable 21-family subset.
- A4 and A5 remain specified but are not yet fully executable.

This validates probe mechanics only. It is **not** an A3 conformance result for an external deployment. Portability requires the same normative semantics to run through independent real-world adapters without weakening acceptance criteria.
