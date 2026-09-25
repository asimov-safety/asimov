from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from asimov_conformance.evidence import build_evidence_manifest
from asimov_conformance.__main__ import main
from asimov_conformance.verification import (
    build_public_verification_record,
    build_verification_statement,
    embed_public_verification_record,
    verify_package,
    extract_public_verification_record,
    verify_public_report,
    verify_statement_binding,
)


def _assessment(scope_sha: str) -> dict:
    from asimov_conformance.gate import ALL_PRECONDITIONS
    ids = [
        "OBS-001", "OBS-002", "OBS-003", "OBS-004",
        "ACC-001", "ACC-002", "ACC-003", "ACC-004",
    ]
    return {
        "spec_version": "0.2.0",
        "catalog_version": "0.2.0",
        "report_id": "verification-test",
        "created_at": "2026-09-24T18:00:00Z",
        "assessment": {"mode": "self_assessment", "assessor": "test@example.com"},
        "system": {"id": "test-system", "configuration_sha256": "a" * 64},
        "scope_manifest_sha256": scope_sha,
        "requested_profile": "A1",
        "preconditions": {
            name: {"status": "PASS", "reason": "test", "evidence_refs": ["evidence/test"]}
            for name in ALL_PRECONDITIONS[:5]
        },
        "results": [
            {"requirement_id": rid, "status": "PASS", "reason": "test", "evidence_refs": ["evidence/test"]}
            for rid in ids
        ],
        "limitations": ["test fixture"],
    }


class VerificationTests(unittest.TestCase):
    def test_statement_binds_assessment_manifest_and_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "evidence"; evidence.mkdir()
            (evidence / "event.json").write_text("{}", encoding="utf-8")
            manifest = build_evidence_manifest(evidence)
            manifest_path = root / "evidence-manifest.json"
            manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

            assessment_path = root / "assessment.json"
            assessment_path.write_text(json.dumps(_assessment("b" * 64), indent=2) + "\n", encoding="utf-8")
            report_path = root / "report.html"; report_path.write_text("<h1>report</h1>", encoding="utf-8")

            statement = build_verification_statement(assessment_path, manifest_path, [report_path])
            self.assertEqual(verify_statement_binding(statement, assessment_path, manifest_path, [report_path]), [])

            report_path.write_text("<h1>changed</h1>", encoding="utf-8")
            self.assertIn(
                "artifact subject digests do not match",
                verify_statement_binding(statement, assessment_path, manifest_path, [report_path]),
            )

    def test_package_local_verification_and_sigstore_mock(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "evidence"; evidence.mkdir()
            (evidence / "event.json").write_text("{}", encoding="utf-8")
            manifest = build_evidence_manifest(evidence)
            manifest_path = root / "evidence-manifest.json"
            manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
            assessment_path = root / "assessment.json"
            assessment_path.write_text(json.dumps(_assessment("c" * 64), indent=2) + "\n", encoding="utf-8")
            report_path = root / "report.html"; report_path.write_text("report", encoding="utf-8")
            statement_path = root / "statement.json"
            statement_path.write_text(
                json.dumps(build_verification_statement(assessment_path, manifest_path, [report_path]), indent=2) + "\n",
                encoding="utf-8",
            )
            local = verify_package(
                assessment_path=assessment_path,
                evidence_manifest_path=manifest_path,
                evidence_root=evidence,
                statement_path=statement_path,
                report_paths=[report_path],
            )
            self.assertEqual(local["overall"], "LOCAL_BINDING_VERIFIED")

            # Embedding the public verification capsule must not break the full-package binding.
            public_record = build_public_verification_record(statement_path, report_path)
            embed_public_verification_record(report_path, public_record)
            embedded_local = verify_package(
                assessment_path=assessment_path,
                evidence_manifest_path=manifest_path,
                evidence_root=evidence,
                statement_path=statement_path,
                report_paths=[report_path],
            )
            self.assertEqual(embedded_local["overall"], "LOCAL_BINDING_VERIFIED")

            bundle = root / "bundle.sigstore.json"; bundle.write_text("{}", encoding="utf-8")
            with patch("asimov_conformance.verification.sigstore_verify", return_value=(True, "verified")):
                full = verify_package(
                    assessment_path=assessment_path,
                    evidence_manifest_path=manifest_path,
                    evidence_root=evidence,
                    statement_path=statement_path,
                    report_paths=[report_path],
                    bundle_path=bundle,
                    certificate_identity="test@example.com",
                    certificate_oidc_issuer="https://accounts.google.com",
                )
            self.assertEqual(full["overall"], "VERIFIED")


    def test_public_report_sidecar_detects_tampering_and_preserves_statement_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "evidence"; evidence.mkdir()
            (evidence / "event.json").write_text("{}", encoding="utf-8")
            manifest_path = root / "evidence-manifest.json"
            manifest_path.write_text(json.dumps(build_evidence_manifest(evidence), indent=2) + "\n", encoding="utf-8")
            assessment_path = root / "assessment.json"
            assessment_path.write_text(json.dumps(_assessment("e" * 64), indent=2) + "\n", encoding="utf-8")
            report_path = root / "report.html"; report_path.write_text("<h1>public report</h1>", encoding="utf-8")
            statement_path = root / "asimov-statement.json"
            statement_path.write_text(
                json.dumps(build_verification_statement(assessment_path, manifest_path, [report_path]), indent=2) + "\n",
                encoding="utf-8",
            )

            record = build_public_verification_record(statement_path, report_path)
            record_path = root / "public-verification.json"
            record_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
            self.assertEqual(record["statement"]["text"].encode("utf-8"), statement_path.read_bytes())

            verified = verify_public_report(report_path, record_path)
            self.assertEqual(verified["overall"], "LOCAL_MATCH_ONLY")
            self.assertEqual(verified["report_integrity"]["state"], "VERIFIED")
            self.assertEqual(verified["provenance"]["state"], "UNSIGNED")

            embed_public_verification_record(report_path, record)
            embedded = verify_public_report(report_path)
            self.assertEqual(embedded["overall"], "LOCAL_MATCH_ONLY")
            self.assertEqual(embedded["report_integrity"]["state"], "VERIFIED")

            # Changing only the verification capsule does not alter the report-content digest.
            capsule_record = json.loads(record_path.read_text())
            capsule_record["meaning"]["semantic_limit"] = "Updated explanatory text."
            embed_public_verification_record(report_path, capsule_record)
            still_bound = verify_public_report(report_path)
            self.assertEqual(still_bound["report_integrity"]["state"], "VERIFIED")

            # Changing substantive report content must break the bound report digest.
            report_text = report_path.read_text(encoding="utf-8")
            report_path.write_text(report_text.replace("<h1>public report</h1>", "<h1>tampered public report</h1>"), encoding="utf-8")
            tampered = verify_public_report(report_path, record_path)
            self.assertEqual(tampered["overall"], "FAILED")
            self.assertEqual(tampered["report_integrity"]["state"], "FAILED")

    def test_public_record_cli_and_verify_report_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "evidence"; evidence.mkdir()
            (evidence / "event.json").write_text("{}", encoding="utf-8")
            manifest_path = root / "evidence-manifest.json"
            manifest_path.write_text(json.dumps(build_evidence_manifest(evidence), indent=2) + "\n", encoding="utf-8")
            assessment_path = root / "assessment.json"
            assessment_path.write_text(json.dumps(_assessment("f" * 64), indent=2) + "\n", encoding="utf-8")
            report_path = root / "report.html"; report_path.write_text("<html><body><h1>public report</h1></body></html>", encoding="utf-8")
            statement_path = root / "asimov-statement.json"
            statement_path.write_text(
                json.dumps(build_verification_statement(assessment_path, manifest_path, [report_path]), indent=2) + "\n",
                encoding="utf-8",
            )
            record_path = root / "public-verification.json"
            self.assertEqual(main([
                "public-record",
                "--statement", str(statement_path),
                "--report", str(report_path),
                "--output", str(record_path),
            ]), 0)
            receipt_path = root / "public-receipt.json"
            self.assertEqual(main([
                "verify-report", str(report_path),
                "--json-output", str(receipt_path),
            ]), 0)
            receipt = json.loads(receipt_path.read_text())
            self.assertEqual(receipt["overall"], "LOCAL_MATCH_ONLY")

    def test_public_verification_is_cross_platform_newline_stable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "evidence"; evidence.mkdir()
            (evidence / "event.json").write_text("{}", encoding="utf-8")
            manifest_path = root / "evidence-manifest.json"
            manifest_path.write_text(json.dumps(build_evidence_manifest(evidence), indent=2) + "\n", encoding="utf-8")
            assessment_path = root / "assessment.json"
            assessment_path.write_text(json.dumps(_assessment("8" * 64), indent=2) + "\n", encoding="utf-8")

            # Simulate a Windows-authored HTML report with CRLF line endings.
            report_path = root / "report.html"
            report_path.write_bytes(b"<html>\r\n<body>\r\n<h1>public report</h1>\r\n</body>\r\n</html>\r\n")

            statement_obj = build_verification_statement(assessment_path, manifest_path, [report_path])
            statement_text = json.dumps(statement_obj, indent=2) + "\n"
            statement_path = root / "asimov-statement.json"
            # Simulate the exact bytes Cosign would sign on Windows.
            statement_path.write_bytes(statement_text.replace("\n", "\r\n").encode("utf-8"))

            record = build_public_verification_record(statement_path, report_path)
            record_path = root / "public-verification.json"
            record_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")

            verified = verify_public_report(report_path, record_path)
            self.assertEqual(verified["overall"], "LOCAL_MATCH_ONLY")
            self.assertEqual(verified["report_integrity"]["state"], "VERIFIED")

            embed_public_verification_record(report_path, record)
            embedded = verify_public_report(report_path)
            self.assertEqual(embedded["overall"], "LOCAL_MATCH_ONLY")
            self.assertEqual(embedded["report_integrity"]["state"], "VERIFIED")

    def test_sign_report_cli_embeds_authenticated_signer_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "evidence"; evidence.mkdir()
            (evidence / "event.json").write_text("{}", encoding="utf-8")
            manifest_path = root / "evidence-manifest.json"
            manifest_path.write_text(json.dumps(build_evidence_manifest(evidence), indent=2) + "\n", encoding="utf-8")
            assessment_path = root / "assessment.json"
            assessment_path.write_text(json.dumps(_assessment("9" * 64), indent=2) + "\n", encoding="utf-8")
            report_path = root / "report.html"
            report_path.write_text("<html><body><h1>signed report</h1></body></html>", encoding="utf-8")
            statement_path = root / "asimov-statement.json"
            statement_path.write_text(
                json.dumps(build_verification_statement(assessment_path, manifest_path, [report_path]), indent=2) + "\n",
                encoding="utf-8",
            )

            def fake_sign(statement, bundle, **kwargs):
                bundle.write_text("{}", encoding="utf-8")
                return 0

            with patch("asimov_conformance.__main__.sigstore_sign", side_effect=fake_sign), \
                 patch("asimov_conformance.__main__.sigstore_verify", return_value=(True, "verified")):
                code = main([
                    "sign-report", str(report_path),
                    "--statement", str(statement_path),
                    "--provider", "google",
                    "--identity", "test@example.com",
                ])
            self.assertEqual(code, 0)
            embedded = extract_public_verification_record(report_path)
            self.assertEqual(embedded["sigstore"]["certificate_identity"], "test@example.com")
            self.assertEqual(
                embedded["sigstore"]["certificate_oidc_issuer"],
                "https://accounts.google.com",
            )
            self.assertTrue((root / "asimov.sigstore.json").exists())

    def _write_review_fixture(self, evidence: Path) -> Path:
        reviews = evidence / "reviews" / "requirements"
        reviews.mkdir(parents=True, exist_ok=True)
        review_path = reviews / "ACC-001.json"
        review = {
            "schema_version": "1",
            "item_type": "requirement",
            "item_id": "ACC-001",
            "title": "Review fixture",
            "review_requirement": "HUMAN",
            "reviewer": "Review Test",
            "reviewer_role": "Evidence reviewer",
            "reviewer_organization": "Example Org",
            "subject_organization": "Example Org",
            "party_class": "FIRST_PARTY",
            "role_separated_from_implementation": False,
            "review_type": "self_assessment",
            "relationship_to_target": "Internal independent reviewer",
            "independence": {
                "separate_legal_entity": None,
                "subject_controls_assessment": None,
                "outcome_contingent_compensation": None,
                "conflicts_disclosed": [],
                "attested": False,
            },
            "signing_identity": {
                "type": "sigstore",
                "expected_subject": "reviewer@example.com",
                "expected_issuer": "https://accounts.google.com",
            },
            "decision": "PASS",
            "reviewed_at": "2026-09-25T01:00:00Z",
            "rationale": "Fixture review.",
            "evidence_refs": ["event.json"],
            "checklist": [],
        }
        review_path.write_text(json.dumps(review, indent=2) + "\n", encoding="utf-8")
        review_path.with_suffix(".sigstore.json").write_text("{}\n", encoding="utf-8")
        return review_path

    def test_verify_package_checks_human_review_attestations(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "evidence"; evidence.mkdir()
            (evidence / "event.json").write_text("{}", encoding="utf-8")
            self._write_review_fixture(evidence)
            manifest_path = root / "evidence-manifest.json"
            manifest_path.write_text(json.dumps(build_evidence_manifest(evidence), indent=2) + "\n", encoding="utf-8")
            assessment_path = root / "assessment.json"
            assessment_path.write_text(json.dumps(_assessment("7" * 64), indent=2) + "\n", encoding="utf-8")
            report_path = root / "report.html"; report_path.write_text("<h1>review attestation</h1>", encoding="utf-8")
            statement_path = root / "statement.json"
            statement_path.write_text(
                json.dumps(build_verification_statement(assessment_path, manifest_path, [report_path]), indent=2) + "\n",
                encoding="utf-8",
            )

            with patch(
                "asimov_conformance.verification.sigstore_verify_blob_attestation",
                return_value=(True, "verified"),
            ):
                receipt = verify_package(
                    assessment_path=assessment_path,
                    evidence_manifest_path=manifest_path,
                    evidence_root=evidence,
                    statement_path=statement_path,
                    report_paths=[report_path],
                )
            self.assertEqual(receipt["overall"], "LOCAL_BINDING_VERIFIED")
            self.assertEqual(receipt["checks"]["review_attestations"]["state"], "VERIFIED")
            self.assertEqual(
                receipt["checks"]["review_attestations"]["reviews"][0]["signer_identity"],
                "reviewer@example.com",
            )

    def test_verify_review_rejects_catalog_review_requirement_downgrade(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            review_path = root / "OVR-005.json"
            review = {
                "schema_version": "1",
                "item_type": "requirement",
                "item_id": "OVR-005",
                "title": "Common-mode review fixture",
                "review_requirement": "HUMAN",
                "reviewer": "Review Test",
                "reviewer_role": "Reviewer",
                "reviewer_organization": "Example Org",
                "subject_organization": "Example Org",
                "party_class": "FIRST_PARTY",
                "role_separated_from_implementation": False,
                "review_type": "self_assessment",
                "relationship_to_target": "",
                "independence": {
                    "separate_legal_entity": None,
                    "subject_controls_assessment": None,
                    "outcome_contingent_compensation": None,
                    "conflicts_disclosed": [],
                    "attested": False,
                },
                "signing_identity": {
                    "type": "sigstore",
                    "expected_subject": "reviewer@example.com",
                    "expected_issuer": "https://accounts.google.com",
                },
                "decision": "PASS",
                "reviewed_at": "2026-09-25T01:00:00Z",
                "rationale": "Fixture review.",
                "evidence_refs": ["external:test"],
                "checklist": [],
            }
            review_path.write_text(json.dumps(review, indent=2) + "\n", encoding="utf-8")
            review_path.with_suffix(".sigstore.json").write_text("{}\n", encoding="utf-8")

            with patch(
                "asimov_conformance.verification.sigstore_verify_blob_attestation",
                return_value=(True, "verified"),
            ):
                from asimov_conformance.verification import verify_review_attestation
                result = verify_review_attestation(review_path)
            self.assertEqual(result["state"], "FAILED")
            self.assertIn("catalog requires ROLE_SEPARATED", result["detail"])

    def test_failed_review_attestation_fails_package_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "evidence"; evidence.mkdir()
            (evidence / "event.json").write_text("{}", encoding="utf-8")
            self._write_review_fixture(evidence)
            manifest_path = root / "evidence-manifest.json"
            manifest_path.write_text(json.dumps(build_evidence_manifest(evidence), indent=2) + "\n", encoding="utf-8")
            assessment_path = root / "assessment.json"
            assessment_path.write_text(json.dumps(_assessment("6" * 64), indent=2) + "\n", encoding="utf-8")
            report_path = root / "report.html"; report_path.write_text("<h1>review attestation</h1>", encoding="utf-8")
            statement_path = root / "statement.json"
            statement_path.write_text(
                json.dumps(build_verification_statement(assessment_path, manifest_path, [report_path]), indent=2) + "\n",
                encoding="utf-8",
            )

            with patch(
                "asimov_conformance.verification.sigstore_verify_blob_attestation",
                return_value=(False, "identity mismatch"),
            ):
                receipt = verify_package(
                    assessment_path=assessment_path,
                    evidence_manifest_path=manifest_path,
                    evidence_root=evidence,
                    statement_path=statement_path,
                    report_paths=[report_path],
                )
            self.assertEqual(receipt["overall"], "FAILED")
            self.assertEqual(receipt["checks"]["review_attestations"]["state"], "FAILED")

    def test_sign_review_cli_records_and_verifies_reviewer_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            review_path = root / "ACC-001.json"
            review_path.write_text(json.dumps({
                "schema_version": "1",
                "item_type": "requirement",
                "item_id": "ACC-001",
                "title": "Review fixture",
                "review_requirement": "HUMAN",
                "reviewer": "Review Test",
                "reviewer_role": "Reviewer",
                "reviewer_organization": "Example Org",
                "subject_organization": "Example Org",
                "party_class": "FIRST_PARTY",
                "role_separated_from_implementation": False,
                "review_type": "self_assessment",
                "relationship_to_target": "",
                "independence": {
                    "separate_legal_entity": None,
                    "subject_controls_assessment": None,
                    "outcome_contingent_compensation": None,
                    "conflicts_disclosed": [],
                    "attested": False,
                },
                "signing_identity": {
                    "type": "sigstore",
                    "expected_subject": "",
                    "expected_issuer": "",
                },
                "decision": "PASS",
                "reviewed_at": "2026-09-25T01:00:00Z",
                "rationale": "Fixture review.",
                "evidence_refs": ["event.json"],
                "checklist": [],
            }, indent=2) + "\n", encoding="utf-8")

            def fake_attest(subject, predicate, bundle, **kwargs):
                bundle.write_text("{}\n", encoding="utf-8")
                return 0

            with patch("asimov_conformance.__main__.sigstore_attest_blob", side_effect=fake_attest), \
                 patch(
                     "asimov_conformance.verification.sigstore_verify_blob_attestation",
                     return_value=(True, "verified"),
                 ):
                code = main([
                    "sign-review", str(review_path),
                    "--provider", "google",
                    "--identity", "reviewer@example.com",
                ])
            self.assertEqual(code, 0)
            signed = json.loads(review_path.read_text())
            self.assertEqual(signed["signing_identity"]["expected_subject"], "reviewer@example.com")
            self.assertEqual(
                signed["signing_identity"]["expected_issuer"],
                "https://accounts.google.com",
            )
            self.assertTrue(review_path.with_suffix(".sigstore.json").exists())

    def test_cli_statement_and_local_verification_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "evidence"; evidence.mkdir()
            (evidence / "event.json").write_text("{}", encoding="utf-8")
            manifest_path = root / "evidence-manifest.json"
            manifest_path.write_text(json.dumps(build_evidence_manifest(evidence), indent=2) + "\n", encoding="utf-8")
            assessment_path = root / "assessment.json"
            assessment_path.write_text(json.dumps(_assessment("d" * 64), indent=2) + "\n", encoding="utf-8")
            report_path = root / "report.html"; report_path.write_text("<h1>shareable report</h1>", encoding="utf-8")
            statement_path = root / "statement.json"
            self.assertEqual(main([
                "verification-statement", str(assessment_path),
                "--evidence-manifest", str(manifest_path),
                "--report", str(report_path),
                "--output", str(statement_path),
            ]), 0)
            receipt_json = root / "receipt.json"
            receipt_html = root / "receipt.html"
            self.assertEqual(main([
                "verify-package", str(assessment_path),
                "--evidence-manifest", str(manifest_path),
                "--evidence-root", str(evidence),
                "--statement", str(statement_path),
                "--report", str(report_path),
                "--json-output", str(receipt_json),
                "--html-output", str(receipt_html),
            ]), 0)
            receipt = json.loads(receipt_json.read_text())
            self.assertEqual(receipt["overall"], "LOCAL_BINDING_VERIFIED")
            self.assertIn("Verification receipt", receipt_html.read_text())

            report_path.write_text("<h1>tampered report</h1>", encoding="utf-8")
            self.assertEqual(main([
                "verify-package", str(assessment_path),
                "--evidence-manifest", str(manifest_path),
                "--evidence-root", str(evidence),
                "--statement", str(statement_path),
                "--report", str(report_path),
            ]), 1)


if __name__ == "__main__":
    unittest.main()
