from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from asimov_conformance.__main__ import main
from asimov_conformance.probes import A2_REQUIREMENTS, A3_REQUIREMENTS, A4_REQUIREMENTS, A5_REQUIREMENTS, PROBES, run_initial_probes, run_mutation_validation, run_reference_probes
from asimov_conformance.reference_target import ReferenceTarget, mutated_config


class ReferenceProbeTests(unittest.TestCase):
    def test_reference_target_passes_full_a5(self):
        report = run_initial_probes(ReferenceTarget())
        self.assertTrue(report["selected_all_pass"])
        self.assertEqual(report["counts"]["PASS"], 42)
        self.assertEqual([r["requirement_id"] for r in report["results"]], list(A5_REQUIREMENTS))
        self.assertEqual(report["scope"], "A5_REFERENCE_HARNESS")

    def test_lower_profiles_remain_executable_subsets(self):
        for requirements, expected, scope in (
            (A2_REQUIREMENTS, 21, "A2_REFERENCE_HARNESS"),
            (A3_REQUIREMENTS, 28, "A3_REFERENCE_HARNESS"),
            (A4_REQUIREMENTS, 35, "A4_REFERENCE_HARNESS"),
        ):
            with self.subTest(scope=scope):
                report = run_reference_probes(ReferenceTarget(), requirements)
                self.assertTrue(report["selected_all_pass"])
                self.assertEqual(report["counts"]["PASS"], expected)
                self.assertEqual(report["scope"], scope)

    def test_each_deliberate_control_removal_is_detected(self):
        report = run_mutation_validation()
        self.assertTrue(report["all_mutations_detected"])
        self.assertEqual(len(report["rows"]), 42)
        self.assertTrue(all(r["probe_status"] == "FAIL" for r in report["rows"]))

    def test_each_targeted_mutation_fails_matching_probe(self):
        for rid in A5_REQUIREMENTS:
            with self.subTest(requirement=rid):
                result = PROBES[rid](ReferenceTarget(mutated_config(rid)))
                self.assertEqual(result.status, "FAIL")

    def test_acc001_accepts_nonreference_external_operator_identity(self):
        class ExternalOperatorTarget(ReferenceTarget):
            def evidence_snapshot(self):
                payload = super().evidence_snapshot()
                if "operator" in payload:
                    payload["operator"] = "external-operator-42"
                return payload

        result = PROBES["ACC-001"](ExternalOperatorTarget())
        self.assertEqual(result.status, "PASS")
        self.assertEqual(result.details["operator"], "external-operator-42")
        self.assertTrue(result.details["operator_ok"])

    def test_missing_adapter_capabilities_never_become_passes(self):
        class SparseAdapter:
            adapter_id = "sparse"
            def capabilities(self): return set()
        report = run_initial_probes(SparseAdapter())
        self.assertFalse(report["selected_all_pass"])
        self.assertEqual(len(report["results"]), 42)
        self.assertTrue(all(r["status"] == "NOT_TESTED" for r in report["results"]))

    def test_cli_outputs_json_and_html(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            json_path = root / "probes.json"
            html_path = root / "probes.html"
            self.assertEqual(main(["reference-probes", "--json-output", str(json_path), "--html-output", str(html_path)]), 0)
            report = json.loads(json_path.read_text())
            self.assertTrue(report["selected_all_pass"])
            self.assertEqual(report["counts"]["PASS"], 42)
            html = html_path.read_text()
            self.assertIn("Asimov A1-A5 Reference Harness", html)
            self.assertIn("ACC-006", html)

    def test_mutation_cli_outputs_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mutations.json"
            self.assertEqual(main(["reference-mutations", "--json-output", str(path)]), 0)
            report = json.loads(path.read_text())
            self.assertTrue(report["all_mutations_detected"])
            self.assertEqual(len(report["rows"]), 42)


if __name__ == "__main__":
    unittest.main()
