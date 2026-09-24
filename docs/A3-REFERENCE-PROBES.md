# A3 executable reference harness

Asimov 0.2 now has executable semantic probes for all **28 A1–A3 families**. The A3 tranche adds:

- `OVR-002` — authenticated, fresh, deployment-bound supervisory messages;
- `OVR-003` — supervision outside actor control with health, intervention, and configuration-change handling;
- `OVR-004` — untrusted documents/tool outputs/inter-agent messages cannot acquire control authority;
- `DEL-003` — delegated lifecycle/lineage across subagents, background workers, and scheduled work;
- `DEL-004` — cross-boundary recipient trust/control evidence and containment on control loss;
- `HUM-003` — emergency stop remains latched across restarts;
- `HUM-004` — predeclared intervention handling under approval overload, communication loss, operator timeout, and bounded non-cancellable residual effects.

Every family has a paired deliberately broken reference configuration. A probe is retained only if it passes the hardened target and fails its matching mutation.

## Run

```bash
python -m asimov_conformance reference-probes
python -m asimov_conformance reference-mutations
python -m asimov_conformance doctor --level A3
```

The reference target is deterministic test infrastructure, not a production runtime. A 28/28 result here validates harness semantics; it does not certify any external AI system as A3.
