from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from asimov_conformance.assessment import (
    AssessmentWorkflowError,
    acknowledge_assessment,
    assessment_status,
    finalize_assessment,
    prepare_assessment,
    run_assessment,
)
from asimov_conformance.reference_target import ReferenceTarget


class AssessmentWorkflowTests(unittest.TestCase):
    def _prepare(self, root: Path, profile: str = "A5"):
        adapter = ReferenceTarget()
        prepare_assessment(
            adapter,
            profile,
            root,
            assessor="Workflow Test",
            mode="self_assessment",
            adapter_spec="asimov_conformance.reference_target:ReferenceTarget",
        )
        return adapter

    def _acknowledge(self, root: Path, *, independent: bool = False):
        plan = json.loads((root / "assessment-plan.json").read_text())
        for name in plan["required_preconditions"]:
            path = root / "reviews" / "preconditions" / f"{name}.json"
            record = json.loads(path.read_text())
            record["pre_run_acknowledged"] = True
            record["reviewer"] = "Workflow Test"
            record["reviewer_role"] = "Test reviewer"
            path.write_text(json.dumps(record, indent=2) + "\n")
        for rid in plan["human_review_requirements"]:
            path = root / "reviews" / "requirements" / f"{rid}.json"
            record = json.loads(path.read_text())
            record["pre_run_acknowledged"] = True
            record["reviewer"] = "Independent Test" if rid in plan["independent_review_requirements"] and independent else "Workflow Test"
            record["reviewer_role"] = "Independent reviewer" if rid in plan["independent_review_requirements"] and independent else "Test reviewer"
            if rid in plan["independent_review_requirements"] and independent:
                record["review_type"] = "independent_assessment"
                record["relationship_to_target"] = "Independent test fixture reviewer"
            path.write_text(json.dumps(record, indent=2) + "\n")

    def _complete_reviews(self, root: Path, *, independent: bool = True):
        plan = json.loads((root / "assessment-plan.json").read_text())
        manual = root / "evidence" / "manual"
        manual.mkdir(parents=True, exist_ok=True)
        scope_path = root / "scope.json"
        scope = json.loads(scope_path.read_text())
        scope["scope_description"] = "Disposable reference target assessment."
        scope["threat_model"] = "Reference actor is treated as untrusted relative to the reference controls."
        scope_path.write_text(json.dumps(scope, indent=2) + "\n")
        for name in plan["required_preconditions"]:
            path = root / "reviews" / "preconditions" / f"{name}.json"
            record = json.loads(path.read_text())
            record["decision"] = "PASS"
            record["reviewed_at"] = "2026-09-24T22:00:00Z"
            record["rationale"] = f"Completed test review for {name}."
            record["reviewer_organization"] = "Workflow Test Org"
            record["subject_organization"] = "Reference Target Org"
            record["party_class"] = "FIRST_PARTY"
            record["signing_identity"] = {
                "type": "sigstore",
                "expected_subject": "reviewer@example.com",
                "expected_issuer": "https://accounts.google.com",
            }
            (manual / f"{name}.txt").write_text(f"evidence for {name}\n")
            record["evidence_refs"] = [f"manual/{name}.txt"]
            for item in record["checklist"]:
                item["status"] = "PASS"
                item["evidence_refs"] = [f"manual/{name}.txt"]
            path.write_text(json.dumps(record, indent=2) + "\n")

        for rid in plan["human_review_requirements"]:
            path = root / "reviews" / "requirements" / f"{rid}.json"
            record = json.loads(path.read_text())
            record["subject_organization"] = "Reference Target Org"
            record["reviewer_organization"] = "Reference Target Org"
            record["party_class"] = "FIRST_PARTY"
            record["signing_identity"] = {
                "type": "sigstore",
                "expected_subject": "reviewer@example.com",
                "expected_issuer": "https://accounts.google.com",
            }
            if record.get("review_requirement") == "ROLE_SEPARATED":
                record["role_separated_from_implementation"] = True
            if rid in plan["independent_review_requirements"] and independent:
                record["review_type"] = "independent_assessment"
                record["relationship_to_target"] = "Independent test fixture reviewer"
                record["reviewer"] = "Independent Test"
                record["reviewer_role"] = "Independent reviewer"
                record["reviewer_organization"] = "Independent Test Org"
                record["party_class"] = "THIRD_PARTY"
                record["independence"] = {
                    "separate_legal_entity": True,
                    "subject_controls_assessment": False,
                    "outcome_contingent_compensation": False,
                    "conflicts_disclosed": [],
                    "attested": True,
                }
            record["decision"] = "PASS"
            record["reviewed_at"] = "2026-09-24T22:00:00Z"
            record["rationale"] = f"Completed test review for {rid}."
            (manual / f"{rid}.txt").write_text(f"evidence for {rid}\n")
            record["evidence_refs"] = [f"manual/{rid}.txt"]
            for item in record["checklist"]:
                item["status"] = "PASS"
                item["evidence_refs"] = [f"manual/{rid}.txt"]
            path.write_text(json.dumps(record, indent=2) + "\n")
            path.with_suffix(".sigstore.json").write_text("{}\n")

    def test_prepare_generates_all_profile_obligations_before_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "assessment"
            self._prepare(root, "A5")
            plan = json.loads((root / "assessment-plan.json").read_text())
            self.assertEqual(len(plan["requirements"]), 42)
            self.assertEqual(len(plan["human_review_requirements"]), 24)
            self.assertIn("OVR-006", plan["independent_review_requirements"])
            self.assertIn("ACC-006", plan["independent_review_requirements"])
            self.assertEqual(plan["review_requirements"]["ACC-006"], "THIRD_PARTY")
            self.assertEqual(plan["review_requirements"]["OVR-005"], "ROLE_SEPARATED")
            self.assertEqual(plan["review_requirements"]["ACC-001"], "HUMAN")
            self.assertEqual(plan["review_requirements"]["HUM-001"], "HUMAN")
            self.assertTrue((root / "REVIEW-CHECKLIST.md").exists())
            self.assertTrue((root / "verification-plan.json").exists())

    def test_bulk_acknowledgement_allows_a5_technical_run_without_independent_reviewer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "assessment"
            adapter = self._prepare(root, "A5")
            result = acknowledge_assessment(
                root,
                reviewer="Workflow Test",
                reviewer_role="System owner / self-assessor",
            )
            self.assertGreater(result["count"], 0)
            self.assertIn("ACC-006", result["independent_review_requirements"])
            status = assessment_status(root)
            self.assertTrue(status["pre_run_ready"])
            technical = run_assessment(adapter, root)
            self.assertEqual(len(technical["results"]), 42)

    def test_run_refuses_silent_missing_pre_run_acknowledgement(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "assessment"
            adapter = self._prepare(root, "A2")
            with self.assertRaisesRegex(AssessmentWorkflowError, "Pre-run review acknowledgement"):
                run_assessment(adapter, root)

    def test_hybrid_machine_pass_is_inconclusive_until_review_completed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "assessment"
            adapter = self._prepare(root, "A2")
            self._acknowledge(root)
            run_assessment(adapter, root)
            result = finalize_assessment(root)
            findings = {x["requirement_id"]: x for x in result["findings"]}
            self.assertEqual(findings["OBS-001"]["status"], "INCONCLUSIVE")

    def test_completed_reviews_allow_reference_target_to_satisfy_a5(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "assessment"
            adapter = self._prepare(root, "A5")
            self._acknowledge(root, independent=True)
            run_assessment(adapter, root)
            self._complete_reviews(root, independent=True)
            result = finalize_assessment(root)
            self.assertEqual(result["profiles"]["A1"]["state"], "REPORTED_PASS")
            self.assertEqual(result["profiles"]["A2"]["state"], "REPORTED_PASS")
            self.assertEqual(result["profiles"]["A3"]["state"], "REPORTED_PASS")
            self.assertEqual(result["profiles"]["A4"]["state"], "REPORTED_PASS")
            self.assertEqual(result["profiles"]["A5"]["state"], "REPORTED_PASS")
            self.assertTrue((root / "evidence-manifest.json").exists())
            self.assertTrue((root / "asimov-statement.json").exists())
            self.assertTrue((root / "public-verification.json").exists())
            self.assertTrue((root / "VERIFICATION-INSTRUCTIONS.md").exists())

    def test_missing_family_review_attestation_keeps_profile_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "assessment"
            adapter = self._prepare(root, "A1")
            self._acknowledge(root)
            run_assessment(adapter, root)
            self._complete_reviews(root)

            bundle = root / "reviews" / "requirements" / "OBS-001.sigstore.json"
            bundle.unlink()

            result = finalize_assessment(root)
            findings = {x["requirement_id"]: x for x in result["findings"]}
            self.assertEqual(findings["OBS-001"]["status"], "INCONCLUSIVE")
            self.assertEqual(result["profiles"]["A1"]["state"], "REPORTED_INCOMPLETE")

    def test_independence_required_review_rejects_self_assessment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "assessment"
            adapter = self._prepare(root, "A5")
            self._acknowledge(root, independent=True)
            run_assessment(adapter, root)
            self._complete_reviews(root, independent=True)

            path = root / "reviews" / "requirements" / "ACC-006.json"
            record = json.loads(path.read_text())
            record["review_type"] = "self_assessment"
            record["relationship_to_target"] = ""
            path.write_text(json.dumps(record, indent=2) + "\n")

            result = finalize_assessment(root)
            findings = {x["requirement_id"]: x for x in result["findings"]}
            self.assertEqual(findings["ACC-006"]["status"], "INCONCLUSIVE")
            self.assertEqual(result["profiles"]["A5"]["state"], "REPORTED_INCOMPLETE")

    def test_role_separated_review_rejects_implementer_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "assessment"
            adapter = self._prepare(root, "A4")
            self._acknowledge(root)
            run_assessment(adapter, root)
            self._complete_reviews(root)

            path = root / "reviews" / "requirements" / "OVR-005.json"
            record = json.loads(path.read_text())
            record["role_separated_from_implementation"] = False
            path.write_text(json.dumps(record, indent=2) + "\n")

            result = finalize_assessment(root)
            findings = {x["requirement_id"]: x for x in result["findings"]}
            self.assertEqual(findings["OVR-005"]["status"], "INCONCLUSIVE")

    def test_role_separated_review_cannot_downgrade_to_human(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "assessment"
            adapter = self._prepare(root, "A4")
            self._acknowledge(root)
            run_assessment(adapter, root)
            self._complete_reviews(root)

            path = root / "reviews" / "requirements" / "OVR-005.json"
            record = json.loads(path.read_text())
            record["review_requirement"] = "HUMAN"
            record["role_separated_from_implementation"] = False
            path.write_text(json.dumps(record, indent=2) + "\n")

            result = finalize_assessment(root)
            findings = {x["requirement_id"]: x for x in result["findings"]}
            self.assertEqual(findings["OVR-005"]["status"], "INCONCLUSIVE")
            self.assertIn("downgrade/mismatch", findings["OVR-005"]["reason"])

    def test_third_party_review_rejects_same_organization(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "assessment"
            adapter = self._prepare(root, "A5")
            self._acknowledge(root, independent=True)
            run_assessment(adapter, root)
            self._complete_reviews(root, independent=True)

            path = root / "reviews" / "requirements" / "ACC-006.json"
            record = json.loads(path.read_text())
            record["reviewer_organization"] = record["subject_organization"]
            path.write_text(json.dumps(record, indent=2) + "\n")

            result = finalize_assessment(root)
            findings = {x["requirement_id"]: x for x in result["findings"]}
            self.assertEqual(findings["ACC-006"]["status"], "INCONCLUSIVE")
            self.assertEqual(result["profiles"]["A5"]["state"], "REPORTED_INCOMPLETE")

    def test_status_surfaces_pending_human_work(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "assessment"
            self._prepare(root, "A3")
            status = assessment_status(root)
            self.assertFalse(status["pre_run_ready"])
            self.assertTrue(status["pending_requirement_reviews"])
            self.assertTrue(status["pending_preconditions"])


if __name__ == "__main__":
    unittest.main()
