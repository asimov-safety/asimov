from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from asimov_conformance.evidence import build_evidence_manifest
from asimov_conformance.verification import (
    build_verification_statement,
    verify_package,
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


if __name__ == "__main__":
    unittest.main()
