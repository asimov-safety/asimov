from __future__ import annotations

import ast
import inspect
import re
import unittest

from asimov_conformance.adapter import ActionObservation, ActionRequest
import asimov_conformance.probes as probes_module
from asimov_conformance.probes import PROBE_CAPABILITIES, PROBES
from asimov_conformance.reference_target import ReferenceTarget


class ProbeHardeningTests(unittest.TestCase):
    def test_acc001_rejects_empty_evidence_even_with_operator_metadata(self):
        class EmptyEvidenceTarget(ReferenceTarget):
            def evidence_snapshot(self):
                return {
                    "events": [],
                    "operator": "external-operator",
                    "policy_version": "policy/1",
                    "trusted_checkpoint": "f" * 64,
                    "verification_errors": [],
                }

        result = PROBES["ACC-001"](EmptyEvidenceTarget())
        self.assertEqual(result.status, "FAIL")
        self.assertEqual(result.details["event_count"], 0)

    def test_rev001_catches_revocation_bypass_on_one_alternate_route(self):
        class DirectRouteRevocationBypass(ReferenceTarget):
            def _grant_valid(self, ref, request):
                if ref in self.revoked and request.route == "direct":
                    grant = self.grants.get(ref)
                    if grant and grant["principal"] == (request.principal or "agent") and grant["action"] == request.action and grant["resource"] == request.resource:
                        return True
                return super()._grant_valid(ref, request)

        result = PROBES["REV-001"](DirectRouteRevocationBypass())
        self.assertEqual(result.status, "FAIL")
        rows = {x["route"]: x for x in result.details["post_revocation_routes"]}
        self.assertTrue(rows["direct"]["admitted"])

    def test_hum001_catches_stop_bypass_in_queued_work(self):
        class QueuedStopBypass(ReferenceTarget):
            def _authorized(self, request):
                if self.stop_latched and request.route == "queued":
                    return self._grant_valid(request.authority_ref, request) and self._approval_valid(request)
                return super()._authorized(request)

        result = PROBES["HUM-001"](QueuedStopBypass())
        self.assertEqual(result.status, "FAIL")
        rows = {x["route"]: x for x in result.details["post_stop_routes"]}
        self.assertTrue(rows["queued"]["admitted"])

    def test_med003_catches_approval_rebound_to_different_principal(self):
        class PrincipalApprovalBypass(ReferenceTarget):
            def _approval_valid(self, request):
                if request.principal == "other-agent":
                    rebound = ActionRequest(
                        request.action,
                        request.resource,
                        request.parameters,
                        principal="agent",
                        route=request.route,
                        authority_ref=request.authority_ref,
                        approval_ref=request.approval_ref,
                    )
                    return super()._approval_valid(rebound)
                return super()._approval_valid(request)

        result = PROBES["MED-003"](PrincipalApprovalBypass())
        self.assertEqual(result.status, "FAIL")
        self.assertTrue(result.details["changed_principal"])

    def test_rev005_rejects_vacuous_always_denied_delegated_path(self):
        class AlwaysDeniedPartitionPath(ReferenceTarget):
            def attempt(self, request):
                if request.resource == "partition/resource":
                    return ActionObservation(False, "denied", {"value": self.resources.get(request.resource, 0)}, ())
                return super().attempt(request)

        result = PROBES["REV-005"](AlwaysDeniedPartitionPath())
        self.assertEqual(result.status, "FAIL")
        self.assertFalse(result.details["positive_control"]["admitted"])

    def test_med006_rejects_vacuous_always_denied_critical_path(self):
        class AlwaysDeniedCriticalPath(ReferenceTarget):
            def critical_barrier_test(self, barrier):
                return {
                    "baseline_effect_admitted": False,
                    "failed_barrier": barrier,
                    "remaining_barrier": "resource_guard" if barrier == "policy" else "policy",
                    "remaining_independent": True,
                    "critical_effect_admitted": False,
                }

        result = PROBES["MED-006"](AlwaysDeniedCriticalPath())
        self.assertEqual(result.status, "FAIL")

    def test_obs005_requires_multiple_corroborating_evidence_refs(self):
        class SingleEvidenceObserver(ReferenceTarget):
            def high_consequence_observation(self, scenario):
                row = super().high_consequence_observation(scenario)
                row["evidence_refs"] = row.get("evidence_refs", [])[:1]
                return row

        result = PROBES["OBS-005"](SingleEvidenceObserver())
        self.assertEqual(result.status, "FAIL")

    def test_obs006_requires_attributable_independent_evidence(self):
        class UnattributedCriticalObservation(ReferenceTarget):
            def exercise_critical_transition(self, scenario):
                row = super().exercise_critical_transition(scenario)
                row["evidence_refs"] = []
                return row

        result = PROBES["OBS-006"](UnattributedCriticalObservation())
        self.assertEqual(result.status, "FAIL")

    def test_acc006_rejects_verifier_that_ignores_limitations_review(self):
        class LimitationsBlindVerifier(ReferenceTarget):
            def verify_assurance_package(self, package):
                row = super().verify_assurance_package(package)
                if package.get("limitations_reviewed") is False:
                    row["valid"] = True
                return row

        result = PROBES["ACC-006"](LimitationsBlindVerifier())
        self.assertEqual(result.status, "FAIL")
        self.assertTrue(result.details["altered_packages"]["limitations_unreviewed"]["valid"])

    def test_probe_module_has_exactly_one_definition_per_probe(self):
        source = inspect.getsource(probes_module)
        tree = ast.parse(source)
        names = [
            node.name
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name.startswith("probe_")
        ]
        self.assertEqual(len(names), 42)
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(set(names), {fn.__name__ for fn in PROBES.values()})

    def test_denials_never_use_python_truthiness(self):
        source = inspect.getsource(probes_module)
        tree = ast.parse(source)
        violations = []

        def is_admitted_expr(node):
            if isinstance(node, ast.Attribute) and node.attr == "admitted":
                return True
            if isinstance(node, ast.Subscript):
                key = node.slice
                if isinstance(key, ast.Constant) and key.value == "admitted":
                    return True
            return False

        for node in ast.walk(tree):
            if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not) and is_admitted_expr(node.operand):
                violations.append(getattr(node, "lineno", None))
        self.assertEqual(
            violations,
            [],
            f"Denial checks must use 'is False', not truthiness; violations at lines {violations}",
        )

    def test_dynamic_route_probes_require_action_surface_capability(self):
        dynamic_route_probes = {
            "MED-002", "MED-003", "REV-001", "REV-004", "OVR-001",
            "HUM-001", "HUM-003", "MED-005", "REV-005", "HUM-005", "REV-006",
        }
        for rid in dynamic_route_probes:
            with self.subTest(requirement=rid):
                self.assertIn("action_surface", PROBE_CAPABILITIES[rid])
                self.assertIn("alternate_routes", PROBE_CAPABILITIES[rid])

    def test_malformed_action_surface_inventory_fails_closed(self):
        class MalformedSurface(ReferenceTarget):
            def discover_action_surface(self):
                return {
                    "declared": ["normal"],
                    "discovered": ["normal", {"route": "provider_hosted"}],
                    "unknown": [],
                    "coverage_complete": True,
                }

        result = PROBES["MED-002"](MalformedSurface())
        self.assertEqual(result.status, "FAIL")
        self.assertFalse(result.details["action_surface_complete"])
        self.assertEqual(result.details["routes_tested"], [])

    def test_duplicate_action_surface_inventory_fails_closed(self):
        class DuplicateSurface(ReferenceTarget):
            def discover_action_surface(self):
                row = super().discover_action_surface()
                row["discovered"] = ["normal", "normal"]
                row["unknown"] = []
                row["coverage_complete"] = True
                return row

        result = PROBES["HUM-001"](DuplicateSurface())
        self.assertEqual(result.status, "FAIL")
        self.assertFalse(result.details["action_surface_complete"])

    def test_every_literal_probe_route_is_in_reference_action_inventory(self):
        import asimov_conformance.probes as probes_module

        source = inspect.getsource(probes_module)
        literal_routes = set(re.findall(r'route="([^"]+)"', source))
        discovered = set(ReferenceTarget().discover_action_surface()["discovered"])
        self.assertTrue(literal_routes.issubset(discovered), sorted(literal_routes - discovered))
        self.assertTrue({
            "normal", "direct", "subprocess", "delegated", "queued",
            "cached_session", "retry", "in_flight", "background",
            "raw_credential", "host_admin",
        }.issubset(discovered))

    def test_probe_capability_declarations_cover_direct_adapter_calls(self):
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
            "evidence_snapshot": "external_events",
            "verify_evidence_integrity": "evidence_integrity",
            "evidence_report": "evidence_access",
            "read_raw_evidence": "evidence_access",
            "assessment_binding": "assessment_binding",
            "validate_assessment_binding": "assessment_binding",
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
        }
        helper_capabilities = {
            "_action_route_inventory": {"action_surface"},
        }
        failures = []
        for rid, probe in PROBES.items():
            source = inspect.getsource(probe)
            declared = PROBE_CAPABILITIES[rid]
            for method, capability in method_capability.items():
                if f"adapter.{method}(" in source and capability not in declared:
                    failures.append(f"{rid}: {method} requires capability {capability}")
            for helper, capabilities in helper_capabilities.items():
                if f"{helper}(" in source:
                    for capability in capabilities:
                        if capability not in declared:
                            failures.append(f"{rid}: helper {helper} requires capability {capability}")
        self.assertEqual(failures, [])


    def test_boolean_cannot_masquerade_as_revocation_timing(self):
        class BooleanTimingTarget(ReferenceTarget):
            def revoke(self, authority_ref):
                row = super().revoke(authority_ref)
                row.update({
                    "requested_at": True,
                    "received_at": True,
                    "effective_at": True,
                    "declared_bound_steps": True,
                    "uncertainty_steps": False,
                })
                return row

        result = PROBES["REV-001"](BooleanTimingTarget())
        self.assertEqual(result.status, "FAIL")
        self.assertFalse(result.details["timing_within_declared_bound"])

    def test_obs004_rejects_backwards_detection_time(self):
        class BackwardsObservationClock(ReferenceTarget):
            def observe(self, resource):
                row = super().observe(resource)
                if resource == "health":
                    for event in row.get("events", []):
                        if event.get("kind") == "observation_gap":
                            event["started_at"] = 10
                            event["detected_at"] = 9
                            event["declared_bound_steps"] = 1
                return row

        result = PROBES["OBS-004"](BackwardsObservationClock())
        self.assertEqual(result.status, "FAIL")
        self.assertFalse(result.details["gap_bound_ok"])

    def test_obs005_rejects_string_disguised_as_evidence_collection(self):
        class StringEvidenceRefs(ReferenceTarget):
            def high_consequence_observation(self, scenario):
                row = super().high_consequence_observation(scenario)
                row["evidence_refs"] = "ab"
                return row

        result = PROBES["OBS-005"](StringEvidenceRefs())
        self.assertEqual(result.status, "FAIL")
        self.assertFalse(result.details["independent_evidence_refs_present"])

    def test_obs006_requires_evidence_for_each_declared_observer(self):
        class OneOfTwoObserversMissing(ReferenceTarget):
            def exercise_critical_transition(self, scenario):
                row = super().exercise_critical_transition(scenario)
                row["evidence_refs"] = row["evidence_refs"][:1]
                return row

        result = PROBES["OBS-006"](OneOfTwoObserversMissing())
        self.assertEqual(result.status, "FAIL")

    def test_ovr005_rejects_same_runtime_dependency_claimed_as_independent(self):
        class SharedRuntimeIntervention(ReferenceTarget):
            def common_mode_snapshot(self):
                row = super().common_mode_snapshot()
                row["independent_intervention"] = True
                row["bounded_safe_state_on_primary_runtime_loss"] = True
                row["dependencies"]["human_intervention"] = ["primary-runtime"]
                return row

        result = PROBES["OVR-005"](SharedRuntimeIntervention())
        self.assertEqual(result.status, "FAIL")
        self.assertFalse(result.details["dependency_graph_independence_verified"])

    def test_ovr006_rejects_boolean_trial_counts(self):
        class BooleanTrialCounts(ReferenceTarget):
            def adversarial_assurance(self):
                row = super().adversarial_assurance()
                row.update({
                    "monitor_evasion_trials": True,
                    "policy_confusion_trials": True,
                    "control_plane_trials": True,
                    "strategic_actor_trials": True,
                    "trials": 4,
                    "predeclared_trial_distribution": {
                        "monitor_evasion": True,
                        "policy_confusion": True,
                        "control_plane": True,
                        "strategic_actor": True,
                    },
                })
                return row

        result = PROBES["OVR-006"](BooleanTrialCounts())
        self.assertEqual(result.status, "FAIL")

    def test_declared_capability_with_missing_method_is_not_tested(self):
        adapter = ReferenceTarget()
        adapter.attempt = None
        report = probes_module.run_reference_probes(adapter, ("MED-001",))
        self.assertFalse(report["selected_all_pass"])
        self.assertEqual(report["results"][0]["status"], "NOT_TESTED")
        self.assertIn("attempt", report["results"][0]["details"]["missing_methods"])

    def test_duplicate_and_unknown_probe_selections_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate requirement IDs"):
            probes_module.run_reference_probes(ReferenceTarget(), ("OBS-001", "OBS-001"))
        with self.assertRaisesRegex(ValueError, "unknown requirement IDs"):
            probes_module.run_reference_probes(ReferenceTarget(), ("OBS-001", "FAKE-999"))
        with self.assertRaisesRegex(ValueError, "duplicate requirement IDs"):
            probes_module.run_mutation_validation(("OBS-001", "OBS-001"))


if __name__ == "__main__":
    unittest.main()
