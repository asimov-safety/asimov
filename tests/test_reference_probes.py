from __future__ import annotations

import ast
import inspect
import json
import tempfile
import unittest
from pathlib import Path

from asimov_conformance.__main__ import main
from asimov_conformance.probes import A1_REQUIREMENTS, A2_REQUIREMENTS, A3_REQUIREMENTS, A4_REQUIREMENTS, A5_REQUIREMENTS, PROBE_CAPABILITIES, PROBES, probe_obs_004, run_initial_probes, run_mutation_validation, run_reference_probes
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
            (A1_REQUIREMENTS, 8, "A1_REFERENCE_HARNESS"),
            (A2_REQUIREMENTS, 21, "A2_REFERENCE_HARNESS"),
            (A3_REQUIREMENTS, 28, "A3_REFERENCE_HARNESS"),
            (A4_REQUIREMENTS, 35, "A4_REFERENCE_HARNESS"),
        ):
            with self.subTest(scope=scope):
                report = run_reference_probes(ReferenceTarget(), requirements)
                self.assertTrue(report["selected_all_pass"])
                self.assertEqual(report["counts"]["PASS"], expected)
                self.assertEqual(report["scope"], scope)

    def test_obs004_a1_marks_gap_without_requiring_a2_deny_posture(self):
        class A1ObservationOnlyTarget(ReferenceTarget):
            def _authorized(self, request):
                if not self.observation_available and self.config.visible_observation_failure:
                    unavailable = self.observation_available
                    self.observation_available = True
                    try:
                        return super()._authorized(request)
                    finally:
                        self.observation_available = unavailable
                return super()._authorized(request)

        a1 = probe_obs_004(A1ObservationOnlyTarget(), profile_level=1)
        self.assertEqual(a1.status, "PASS")
        self.assertTrue(a1.details["evidence_marked_incomplete"])
        self.assertTrue(a1.details["outage_action"]["admitted"])
        self.assertFalse(a1.details["bounded_posture_required"])

        a2 = probe_obs_004(A1ObservationOnlyTarget(), profile_level=2)
        self.assertEqual(a2.status, "FAIL")
        self.assertTrue(a2.details["outage_action"]["admitted"])
        self.assertTrue(a2.details["bounded_posture_required"])

    def test_obs004_requires_bounded_gap_and_sampling_visibility(self):
        result = probe_obs_004(ReferenceTarget(), profile_level=2)
        self.assertEqual(result.status, "PASS")
        self.assertTrue(result.details["gap_bound_ok"])
        self.assertTrue(result.details["sequence_gap_visible"])
        self.assertTrue(result.details["sampling_violation_visible_and_not_applied"])

    def test_probe_capability_map_covers_every_direct_adapter_method(self):
        method_capability = {
            "discover_action_surface": "action_surface",
            "attempt": "attempt",
            "observe": "observe",
            "issue_grant": "issue_grant",
            "issue_approval": "issue_approval",
            "approval_view": "approval_view",
            "revoke": "revoke",
            "refresh_grant": "refresh_grant",
            "delegate": "delegate",
            "stop": "stop",
            "reset_stop": "stop_reset",
            "restart": "restart",
            "inject_fault": "fault_injection",
            "issue_supervisor_message": "supervisor_auth",
            "deliver_supervisor_message": "supervisor_auth",
            "supervision_snapshot": "independent_supervision",
            "ingest_untrusted": "untrusted_content_isolation",
            "delegation_snapshot": "delegation_lifecycle",
            "delegate_external": "cross_boundary_delegation",
            "intervention_plan": "intervention_exercise",
            "exercise_intervention": "intervention_exercise",
            "high_consequence_observation": "high_consequence_observation",
            "common_mode_snapshot": "common_mode_analysis",
            "delegation_stress": "delegation_churn",
            "assessment_attestation": "assessment_attestation",
            "verify_assessment_attestation": "assessment_attestation",
            "critical_transition_plan": "critical_observation",
            "exercise_critical_transition": "critical_observation",
            "critical_barrier_test": "critical_barriers",
            "secondary_containment": "secondary_containment",
            "adversarial_assurance": "adversarial_assurance",
            "emergency_recovery": "emergency_recovery",
            "independent_assurance_package": "independent_assurance",
            "verify_assurance_package": "independent_assurance",
            "evidence_snapshot": "external_events",
            "evidence_report": "evidence_access",
            "read_raw_evidence": "evidence_access",
            "assessment_binding": "assessment_binding",
            "validate_assessment_binding": "assessment_binding",
            "verify_evidence_integrity": "evidence_integrity",
        }

        for rid, probe in PROBES.items():
            tree = ast.parse(inspect.getsource(probe))
            direct_methods = {
                node.attr
                for node in ast.walk(tree)
                if isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id == "adapter"
                and node.attr in method_capability
            }
            helper_missing = set()
            if "_action_route_inventory(" in inspect.getsource(probe) and "action_surface" not in PROBE_CAPABILITIES[rid]:
                helper_missing.add("action_surface")
            with self.subTest(requirement=rid):
                missing = {
                    method_capability[name]
                    for name in direct_methods
                    if method_capability[name] not in PROBE_CAPABILITIES[rid]
                } | helper_missing
                self.assertFalse(
                    missing,
                    f"{rid} calls adapter methods whose capabilities are not required: {sorted(missing)}",
                )

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

    def test_empty_probe_and_mutation_selections_never_report_success(self):
        empty_probes = run_reference_probes(ReferenceTarget(), ())
        self.assertFalse(empty_probes["selected_all_pass"])
        self.assertEqual(empty_probes["results"], [])

        empty_mutations = run_mutation_validation(())
        self.assertFalse(empty_mutations["all_mutations_detected"])
        self.assertEqual(empty_mutations["rows"], [])

    def test_duplicate_or_unknown_requirement_selection_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            run_reference_probes(ReferenceTarget(), ("MED-001", "MED-001"))
        with self.assertRaisesRegex(ValueError, "unknown requirement"):
            run_reference_probes(ReferenceTarget(), ("MED-001", "NOT-A-REQUIREMENT"))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            run_mutation_validation(("REV-001", "REV-001"))
        with self.assertRaisesRegex(ValueError, "unknown requirement"):
            run_mutation_validation(("REV-001", "NOT-A-REQUIREMENT"))

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
