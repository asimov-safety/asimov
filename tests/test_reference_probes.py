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

    def test_vacuous_positive_paths_are_rejected(self):
        class AlwaysDenyTarget(ReferenceTarget):
            def attempt(self, request):
                obs = super().attempt(request)
                if request.action == "write" and obs.admitted is True:
                    # Undo any effect and force a denied result while preserving the
                    # rest of the reference fixture semantics.
                    self.resources[request.resource] = self.resources.get(request.resource, 0) - int(request.parameters.get("delta", 1))
                    from asimov_conformance.adapter import ActionObservation
                    return ActionObservation(False, "denied", {"value": self.resources.get(request.resource, 0)}, obs.evidence_refs)
                return obs

        for rid in ("OBS-004", "REV-003", "DEL-001", "HUM-002", "HUM-003", "REV-005", "OVR-005", "HUM-005", "REV-006", "HUM-006"):
            with self.subTest(requirement=rid):
                self.assertEqual(PROBES[rid](AlwaysDenyTarget()).status, "FAIL")

    def test_empty_or_nonuseful_evidence_cannot_pass_accountability(self):
        class EmptyEvidenceTarget(ReferenceTarget):
            def evidence_snapshot(self):
                payload = super().evidence_snapshot()
                payload["events"] = []
                return payload

        class EmptyRoutineTarget(ReferenceTarget):
            def evidence_report(self, role="viewer"):
                return {"role": role, "events": [], "operator": "reference-operator"}

        self.assertEqual(PROBES["ACC-001"](EmptyEvidenceTarget()).status, "FAIL")
        self.assertEqual(PROBES["ACC-003"](EmptyRoutineTarget()).status, "FAIL")

    def test_critical_observation_requires_independent_evidence_refs(self):
        class UnsupportedCriticalObservation(ReferenceTarget):
            def exercise_critical_transition(self, scenario):
                states = {
                    "success": "occurred",
                    "denial": "denied",
                    "partial_failure": "partially-committed",
                    "sensor_loss": "observation-lost",
                    "ambiguous": "uncertain",
                }
                return {
                    "scenario": scenario,
                    "state": states[scenario],
                    "covered": True,
                    "independent_evidence": False,
                    "evidence_refs": [],
                }

        self.assertEqual(PROBES["OBS-006"](UnsupportedCriticalObservation()).status, "FAIL")

    def test_critical_defense_in_depth_requires_working_baseline(self):
        class AlwaysDeniedCriticalPath(ReferenceTarget):
            def critical_barrier_test(self, barrier):
                remaining = "resource_guard" if barrier == "policy" else "policy"
                return {
                    "baseline_effect_admitted": False,
                    "failed_barrier": barrier,
                    "remaining_barrier": remaining,
                    "remaining_independent": True,
                    "critical_effect_admitted": False,
                }

        self.assertEqual(PROBES["MED-006"](AlwaysDeniedCriticalPath()).status, "FAIL")

    def test_delegation_stress_requires_attributable_scenario_coverage(self):
        class SummaryOnlyDelegationStress(ReferenceTarget):
            def delegation_stress(self):
                return {
                    "peak_children": 24,
                    "aggregate_budget": 10,
                    "settled_budget": 10,
                    "budget_reset": False,
                    "orphaned_unattributed": 0,
                    "root_revocation_propagated": True,
                    "restart_preserved_lineage": True,
                    "partition_residual_bounded": True,
                }

        self.assertEqual(PROBES["DEL-005"](SummaryOnlyDelegationStress()).status, "FAIL")

    def test_a5_assurance_rejects_unreviewed_limitations(self):
        class IgnoresLimitations(ReferenceTarget):
            def verify_assurance_package(self, package):
                result = super().verify_assurance_package(package)
                if package.get("limitations_reviewed") is False:
                    result["valid"] = True
                return result

        self.assertEqual(PROBES["ACC-006"](IgnoresLimitations()).status, "FAIL")

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
