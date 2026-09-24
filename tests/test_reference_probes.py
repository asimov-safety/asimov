from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from asimov_conformance.__main__ import main
from asimov_conformance.probes import A2_REQUIREMENTS, A3_REQUIREMENTS, PROBES, run_initial_probes, run_mutation_validation, run_reference_probes
from asimov_conformance.reference_target import ReferenceTarget, mutated_config


class ReferenceProbeTests(unittest.TestCase):
    def test_hardened_reference_target_passes_full_a3(self):
        report = run_initial_probes(ReferenceTarget())
        self.assertTrue(report["selected_all_pass"])
        self.assertEqual(report["counts"]["PASS"], 28)
        self.assertEqual([r["requirement_id"] for r in report["results"]], list(A3_REQUIREMENTS))
        self.assertEqual(report["scope"], "A3_REFERENCE_HARNESS")

    def test_a2_subset_remains_fully_executable(self):
        report = run_reference_probes(ReferenceTarget(), A2_REQUIREMENTS)
        self.assertTrue(report["selected_all_pass"])
        self.assertEqual(report["counts"]["PASS"], 21)
        self.assertEqual(report["scope"], "A2_REFERENCE_HARNESS")

    def test_each_deliberate_control_removal_is_detected(self):
        report = run_mutation_validation()
        self.assertTrue(report["all_mutations_detected"])
        self.assertEqual(len(report["rows"]), 28)
        self.assertTrue(all(r["probe_status"] == "FAIL" for r in report["rows"]))

    def test_each_targeted_mutation_fails_matching_probe(self):
        for rid in A3_REQUIREMENTS:
            with self.subTest(requirement=rid):
                result = PROBES[rid](ReferenceTarget(mutated_config(rid)))
                self.assertEqual(result.status, "FAIL")

    def test_missing_adapter_capabilities_never_become_passes(self):
        class SparseAdapter:
            adapter_id = "sparse"
            def capabilities(self): return set()
        report = run_initial_probes(SparseAdapter())
        self.assertFalse(report["selected_all_pass"])
        self.assertEqual(len(report["results"]), 28)
        self.assertTrue(all(r["status"] == "NOT_TESTED" for r in report["results"]))

    def test_cli_outputs_json_and_html(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            json_path = root / "probes.json"
            html_path = root / "probes.html"
            self.assertEqual(main(["reference-probes", "--json-output", str(json_path), "--html-output", str(html_path)]), 0)
            report = json.loads(json_path.read_text())
            self.assertTrue(report["selected_all_pass"])
            self.assertEqual(report["counts"]["PASS"], 28)
            html = html_path.read_text()
            self.assertIn("Reference Probe Results", html)
            self.assertIn("OVR-003", html)
            self.assertIn("not an A-profile conformance result", html)

    def test_mutation_cli_outputs_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mutations.json"
            self.assertEqual(main(["reference-mutations", "--json-output", str(path)]), 0)
            report = json.loads(path.read_text())
            self.assertTrue(report["all_mutations_detected"])
            self.assertEqual(len(report["rows"]), 28)


if __name__ == "__main__":
    unittest.main()
