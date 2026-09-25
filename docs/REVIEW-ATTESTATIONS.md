# Human review and reviewer attestations

Asimov uses human judgment only where the test method cannot truthfully be reduced to an automated assertion. Human judgment is therefore treated as structured evidence, not as an informal note attached after the fact.

This document explains the implementation contract for review-bearing test families.

## 1. Two different questions

Every review-bearing family answers two separate questions:

1. **Does this test require a human judgment?**
2. **How independent must that human be from the implementation being assessed?**

These are not the same question. A review can require a competent human without requiring an outside organization.

The machine-readable catalog declares `review_requirement` for every family:

| Value | Meaning |
|---|---|
| `NONE` | No family-specific human adjudication is required. |
| `HUMAN` | A named human reviewer must evaluate the required evidence. The reviewer may belong to the assessed organization. |
| `ROLE_SEPARATED` | A named human reviewer is required and must be separated from the implementation/control-owner role for the item being reviewed. The reviewer may belong to the same organization. |
| `THIRD_PARTY` | A named reviewer acting for an organization independent of the assessment subject is required. |

`NONE` appears only on adapter-automatable families. Human review records use the other three classes.

### Profile progression

Asimov 0.2 deliberately increases reviewer separation with assurance level:

- A1–A3 review-bearing families use `HUMAN` unless a future family explicitly says otherwise. Self-assessment is permitted.
- Human-reviewed families introduced at A4 use `ROLE_SEPARATED`.
- Human-reviewed families introduced at A5 use `ROLE_SEPARATED`, except `OVR-006` (independent red team) and `ACC-006` (independent assessment), which require `THIRD_PARTY`.

This keeps the lower profiles usable for small teams while making reviewer independence progressively stronger where the assurance claim becomes stronger.

## 2. What the adapter does — and does not do

The adapter supplies technical execution and evidence surfaces. It does not decide whether a human reviewer is sufficiently independent and it must not manufacture a human PASS.

For a HYBRID family, the adapter runs the technical probe and preserves its evidence. The human review is then completed separately against that evidence.

For a REVIEW_REQUIRED family, the adapter may collect artifacts, run exercises, or execute supporting probes, but the normative judgment remains a human review.

The merge is fail-closed:

| Technical result | Required human review | Family result |
|---|---|---|
| PASS | PASS | PASS |
| PASS | FAIL | FAIL |
| PASS | missing / invalid / inconclusive | INCONCLUSIVE |
| FAIL | anything | FAIL |
| ERROR / NOT_TESTED / INCONCLUSIVE | anything | same technical state |

A human review can complete a technical PASS. It cannot erase a technical failure.

## 3. Review records

`prepare-assessment` creates one JSON record for every HYBRID or REVIEW_REQUIRED family.

Typical fields include:

```json
{
  "item_id": "OVR-005",
  "review_requirement": "ROLE_SEPARATED",
  "reviewer": "Jane Smith",
  "reviewer_role": "Evidence assurance",
  "reviewer_organization": "Example AI",
  "subject_organization": "Example AI",
  "party_class": "FIRST_PARTY",
  "role_separated_from_implementation": true,
  "decision": "PASS",
  "reviewed_at": "2026-09-25T14:32:00Z",
  "rationale": "The retained evidence supports the requirement...",
  "evidence_refs": ["manual/acc-001-review.txt"],
  "signing_identity": {
    "type": "sigstore",
    "expected_subject": "jane@example.org",
    "expected_issuer": "https://accounts.google.com"
  }
}
```

The exact schema is `schemas/review-record.schema.json`.

A PASS review must cite evidence, include a rationale and timestamp, and complete every generated checklist item.

## 4. ROLE_SEPARATED reviews

`ROLE_SEPARATED` means the same organization may perform the review, but the reviewer must not be the person or function responsible for implementing or owning the control under review.

Examples:

- an internal assurance engineer reviewing evidence produced by the platform team;
- a security-review function reviewing the developers' evidence;
- an internal audit or risk function reviewing a control it did not design or operate.

The record must set:

```json
"role_separated_from_implementation": true
```

This is an attributable declaration. Asimov cannot cryptographically determine an organization's internal reporting structure.

## 5. THIRD_PARTY reviews

`THIRD_PARTY` is stronger. The reviewer must act for an organization independent of the organization responsible for the assessed deployment.

The record must declare:

```json
{
  "review_requirement": "THIRD_PARTY",
  "party_class": "THIRD_PARTY",
  "review_type": "independent_assessment",
  "reviewer_organization": "Independent Safety Labs",
  "subject_organization": "Example AI",
  "relationship_to_target": "Independent contracted assessor",
  "independence": {
    "separate_legal_entity": true,
    "subject_controls_assessment": false,
    "outcome_contingent_compensation": false,
    "conflicts_disclosed": [],
    "attested": true
  }
}
```

Being paid by the assessment subject does not by itself prevent third-party review. The subject must not control the finding, compensation must not be contingent on a PASS, and material conflicts must be disclosed.

A contractor acting under the subject's control is not made third-party merely by having a different company name.

### Package signer versus independent assessor

Independence is evaluated between the **reviewer/assessor and the assessment subject**, not between the reviewer and the person who signs the final report package.

If an independent assessment firm performs the assessment and signs the resulting package, the same organization may legitimately be both the independent assessor and package signer.

## 6. Sign each completed family review

A completed family review is separately attributable. The reference tooling uses Sigstore/Cosign blob attestations.

After completing a review record:

```bash
asimov sign-review assessment/reviews/requirements/OVR-005.json \
  --provider google \
  --identity jane@example.org
```

Asimov writes the expected signer subject and issuer into the review record, asks Cosign to authenticate that identity, and creates:

```text
OVR-005.json
OVR-005.sigstore.json
```

The companion bundle authenticates the exact review record. If the review JSON is edited afterward, verification fails.

To check one review locally:

```bash
asimov verify-review assessment/reviews/requirements/OVR-005.json
```

The custom review predicate type is:

```text
https://asimov-safety.github.io/attestations/review/v1
```

## 7. What Cosign establishes

For a valid review attestation, local verification can establish that:

- the exact review record was attested;
- the Sigstore signature is valid;
- the authenticated signer matches the review's expected identity;
- the review's declared relationship class is structurally consistent;
- a THIRD_PARTY record names different reviewer and subject organizations and contains the required independence declarations.

Cosign does **not** prove that a declaration about organizational independence is factually true.

For example, cryptography cannot discover an undisclosed ownership relationship between two companies. What Asimov provides is a durable, authenticated record of exactly what the reviewer represented.

## 8. Assessment workflow

A practical review-bearing assessment is:

```text
prepare-assessment
    |
acknowledge pre-run obligations
    |
run-assessment
    |
complete each family review JSON
    |
sign-review each completed family review
    |
finalize-assessment
    |
sign-report / checkpoint as required
    |
verify-package
```

For organization-aware assessments, prepare the workspace with explicit parties:

```bash
asimov prepare-assessment \
  --adapter ./my_adapter.py:MyAdapter \
  --level A5 \
  --assessor "Jane Smith" \
  --subject-organization "Example AI" \
  --assessor-organization "Independent Safety Labs" \
  --mode independent_assessment \
  --output ./assessment
```

These fields describe the assessment parties. They do not replace the per-review attestations.

## 9. Final package verification

`finalize-assessment` copies the review records and their companion Sigstore bundles into the bound evidence set. The evidence manifest therefore detects removal or substitution.

`asimov verify-package` then verifies the review attestations locally in addition to evidence integrity, report binding, and the optional final-package signature.

A failed review attestation fails package verification.

The cryptographic verifier deliberately does not claim that the reviewer made a correct judgment or that every independence fact is externally proven. Those remain semantic and governance questions.

## 10. Preconditions

Assessment preconditions such as deployment binding, threat-model review, and timing plans remain structured human records, but Asimov 0.2 does not require a separate Sigstore attestation for every precondition.

The separate signed-attestation requirement applies to the HYBRID / REVIEW_REQUIRED **test-family reviews** that directly contribute human adjudication to a family result.
