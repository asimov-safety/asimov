# Build an Asimov adapter — quick start

This guide is for engineers who want to test an existing AI/agent deployment without rewriting it around Asimov.

> **Your adapter translates your infrastructure into Asimov's semantic test operations. It must not invent controls your system does not actually have.**

If a required control surface cannot be observed or exercised, the corresponding A-level is blocked until you add that real control or oracle.

## 1. Install Asimov

```bash
git clone https://github.com/asimov-safety/asimov.git
cd asimov
python -m pip install -e .
```

Confirm the reference harness works:

```bash
asimov reference-probes
asimov reference-mutations
asimov doctor --level A5
```

## 2. Start with Adapter Assistant

You do not need to begin by writing 40+ protocol methods from a blank file.

Launch Studio:

```bash
asimov studio
```

Use **Adapter Assistant** to select the runtime, hosting, authority system, protected resources, evidence sources, and optional integrations. Studio shows how those pieces map to the six Asimov surfaces and can generate a starter adapter.

CLI equivalent:

```bash
asimov adapter-catalog

asimov adapter-scaffold \
  --runtime openai-agents-api \
  --hosting kubernetes \
  --authority aws-iam \
  --resource postgresql \
  --evidence opentelemetry \
  --evidence resource-audit \
  --output ./asimov-adapter
```

The scaffold **does not claim any Asimov capability**. Its `capabilities()` method starts empty. That is deliberate: provider selection is guidance, not evidence.

For current provider-specific mappings, see [ADAPTER-PROVIDERS.md](ADAPTER-PROVIDERS.md).

## 3. Map your existing architecture first

| Asimov semantic | Usually comes from |
|---|---|
| `attempt()` | agent framework / API / orchestrator |
| `observe()` | database, filesystem, API, queue, executor, cloud resource |
| `issue_grant()` | IAM, token service, policy engine, task permission state |
| `revoke()` | IAM, lease, credential revocation, policy controller |
| `stop()` | out-of-band operator control / supervisor service |
| `restart()` | process manager, container runtime, service manager |
| `delegate()` | subagent/job/task orchestration |
| supervisor messages | independent control channel |
| `supervision_snapshot()` | supervisor service / control-plane health |
| `ingest_untrusted()` | document/tool/inter-agent input path |
| `delegation_snapshot()` | orchestration store / task graph |
| evidence | audit log, OpenTelemetry, AAS-1, resource-side records |

**Do not use the agent's own text response as the oracle for an external effect.**

## 4. Start with the smallest useful adapter

```python
from asimov_conformance.adapter import ActionRequest, ActionObservation

class MyAdapter:
    adapter_id = "my-platform/dev"

    def capabilities(self) -> set[str]:
        return {"attempt", "observe"}  # only claim what is real

    def reset_fixture(self) -> None:
        ...

    def deployment_snapshot(self) -> dict:
        return {"deployment_id": "my-agent-dev", "version": "...", "config_digest": "..."}

    def attempt(self, request: ActionRequest) -> ActionObservation:
        ...
        return ActionObservation(
            admitted=True,
            outcome="completed",
            external_state={},
            evidence_refs=("event:123",),
        )

    def observe(self, resource: str) -> dict:
        # Read from a source outside the acting agent's control.
        ...
```

Do **not** implement dummy methods just to make `doctor` green.

## 5. Prepare the assessment before probes run

Do not jump from an adapter directly to a raw probe command for a real assessment. Generate the complete assessment/review plan first:

```bash
asimov prepare-assessment \
  --adapter ./my_adapter.py:MyAdapter \
  --adapter-kwargs '{}' \
  --level A5 \
  --assessor "Your Name or Assessment Team" \
  --subject-organization "Organization operating the deployment" \
  --assessor-organization "Organization performing the assessment" \
  --mode self_assessment \
  --output ./assessment
```

This creates, **before technical execution**:

- `scope.json`;
- every mandatory profile precondition record;
- a review record for every HYBRID / REVIEW_REQUIRED family;
- `REVIEW-CHECKLIST.md`;
- a profile-specific `verification-plan.json`.

The technical suite will not start until each mandatory human/review obligation has been explicitly acknowledged and assigned. An acknowledgement is not a PASS.

A5 is cumulative, so an A5 assessment runs all A1–A5 technical families once and the final report calculates every profile separately.

After the pre-run records are acknowledged:

```bash
asimov run-assessment ./assessment \
  --adapter ./my_adapter.py:MyAdapter \
  --adapter-kwargs '{}'
```

Then complete the generated human/review records against the actual evidence. Each record declares one of `HUMAN`, `ROLE_SEPARATED`, or `THIRD_PARTY`; satisfy that relationship before signing it.

```bash
asimov assessment-status ./assessment

# Example: sign a completed review with the reviewer's own authenticated identity.
asimov sign-review ./assessment/reviews/requirements/ACC-006.json \
  --provider google \
  --identity reviewer@example.org

asimov verify-review ./assessment/reviews/requirements/ACC-006.json

# Sign every other completed HYBRID / REVIEW_REQUIRED family review, then:
asimov finalize-assessment ./assessment
```

For `ROLE_SEPARATED`, the reviewer may be in the same organization but cannot be the implementation/control owner being judged. For `THIRD_PARTY`, the reviewer must act for a separate legal entity from the Assessment Subject and complete the signed independence declaration.

**Fail-closed merge rule:** a required human review may complete a technical PASS; it can never override a technical FAIL, ERROR, NOT_TESTED or INCONCLUSIVE result. Missing, unsigned, wrong-identity, improperly separated, or otherwise invalid review makes the family INCONCLUSIVE.

Precondition records are still required and are bound into the evidence package, but Asimov 0.2 does not require a separate Sigstore attestation for every precondition.

For the complete workflow, including independent-review and signing/checkpoint requirements, read [ASSESSMENT-WORKFLOW.md](ASSESSMENT-WORKFLOW.md) and [Human review and reviewer attestations](REVIEW-ATTESTATIONS.md).

`doctor()` remains useful while developing an adapter:

```python
from asimov_conformance.onboarding import doctor
print(doctor(MyAdapter(), "A2"))
```

A blocker means the deployment lacks or does not expose the required control. Fix the deployment or wire the real control; do not fake it in the adapter.

## 6. Compose providers instead of one giant adapter

```text
Agent framework / orchestrator  -> action driver
AWS/Azure/Vault/IAM             -> authority controller
Postgres/S3/filesystem/API      -> resource oracle
Kubernetes/systemd/launchd      -> lifecycle controller
Supervisor service              -> supervision provider
OTel/AAS-1/audit store          -> evidence oracle
```

## 7. Common recipes

### Local desktop agent
Use the local API/Python entry point as the driver, disposable SQLite/files as resource oracles, process/service restart for lifecycle, and a separate controller/process for A3 stop/supervision.

### Kubernetes/cloud agent
Use the service/API as driver, cloud IAM for authority, Kubernetes for lifecycle, database/cloud APIs as resource oracles, and cloud audit/OTel/AAS-1 for evidence.

### Agent framework + database/API tools
Use framework hooks for proposals/delegation, but verify effects at the database/API itself. Use a separate IAM/policy layer for admission/revocation and a separate supervisor for A3.

## 8. Adapter glue vs. real controls

Adapter glue may translate IDs/state, call APIs, correlate events, normalize evidence, create disposable fixtures, and trigger safe faults.

Adapter glue must **not** create test-only approvals/revocation, fake independent supervision, synthesize missing evidence, treat an LLM refusal as enforcement, or omit a consequential path.

## 9. A-level expectations

- **A1:** usually low-friction observation/evidence.
- **A2:** real mediation, revocation, bounded delegation, and human control.
- **A3:** genuine independent supervision/intervention.
- **A4/A5:** intentionally more invasive resilience and assurance infrastructure.

## 10. Portability rule

You may change your adapter implementation. You may **not** weaken an Asimov requirement or acceptance criterion because your framework makes it inconvenient.

## 11. Contributing an adapter

Include the architecture mapping, capability list, disposable fixtures, independent-oracle description, supported families, known gaps, and tests proving both passing and deliberately broken controls.

For complete framework/cloud/resource recipes, see [IMPLEMENTATION-HANDBOOK.md](IMPLEMENTATION-HANDBOOK.md). For family-by-family semantics, see [ADAPTER-GUIDE.md](ADAPTER-GUIDE.md).
