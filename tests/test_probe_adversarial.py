from __future__ import annotations

import unittest

from asimov_conformance.adapter import ActionObservation
from asimov_conformance.probes import PROBES, run_reference_probes
from asimov_conformance.reference_target import ReferenceTarget


class ProbeAdversarialTests(unittest.TestCase):
    def test_falsey_external_adapter_is_never_replaced_by_reference_target(self):
        class FalseySparseAdapter:
            adapter_id = "falsey-sparse"
            def __bool__(self): return False
            def capabilities(self): return set()

        report = run_reference_probes(FalseySparseAdapter())
        self.assertEqual(report["adapter_id"], "falsey-sparse")
        self.assertFalse(report["selected_all_pass"])
        self.assertEqual(report["counts"]["PASS"], 0)
        self.assertTrue(all(row["status"] == "NOT_TESTED" for row in report["results"]))

    def test_capability_discovery_failure_fails_closed_instead_of_crashing(self):
        class BrokenCapabilitiesAdapter:
            adapter_id = "broken-capabilities"
            def capabilities(self):
                raise RuntimeError("capability backend unavailable")

        report = run_reference_probes(BrokenCapabilitiesAdapter())
        self.assertFalse(report["selected_all_pass"])
        self.assertEqual(report["counts"]["ERROR"], len(report["results"]))
        self.assertEqual(report["coverage_blockers"], [row["requirement_id"] for row in report["results"]])
        self.assertTrue(all("failed closed" in row["summary"] for row in report["results"]))

    def test_malformed_capability_declaration_fails_closed(self):
        class StringCapabilitiesAdapter:
            adapter_id = "string-capabilities"
            def capabilities(self): return "attempt"

        report = run_reference_probes(StringCapabilitiesAdapter())
        self.assertEqual(report["counts"]["ERROR"], len(report["results"]))
        self.assertEqual(report["counts"]["PASS"], 0)

    def test_rev002_requires_declared_residual_semantics(self):
        class NoResidualDeclarationTarget(ReferenceTarget):
            def revoke(self, authority_ref):
                row = super().revoke(authority_ref)
                row.pop("residual_effect_bound", None)
                row.pop("residual_effects_observed", None)
                row.pop("admission_semantics", None)
                row.pop("non_cancellable_handling", None)
                return row

        result = PROBES["REV-002"](NoResidualDeclarationTarget())
        self.assertEqual(result.status, "FAIL")
        self.assertTrue(any(not row["residual_semantics_declared"] for row in result.details["routes"]))

    def test_rev004_requires_disconnected_descendant_revocation(self):
        class PartitionBlindCascadeTarget(ReferenceTarget):
            def revoke(self, authority_ref):
                partitioned = set(self.partitioned_recipients)
                row = super().revoke(authority_ref)
                for ref in list(row.get("revoked", [])):
                    principal = self.grants.get(ref, {}).get("principal")
                    if principal in partitioned:
                        self.revoked.discard(ref)
                        row["revoked"].remove(ref)
                return row

        result = PROBES["REV-004"](PartitionBlindCascadeTarget())
        self.assertEqual(result.status, "FAIL")

    def test_hum002_requires_complete_trusted_approval_view(self):
        class IncompleteHumanViewTarget(ReferenceTarget):
            def approval_view(self, approval_ref):
                row = super().approval_view(approval_ref)
                row.pop("uncertainty", None)
                row.pop("policy_context", None)
                return row

        result = PROBES["HUM-002"](IncompleteHumanViewTarget())
        self.assertEqual(result.status, "FAIL")
        self.assertFalse(result.details["trusted_view_complete"])

    def test_acc002_rejects_actor_controlled_checkpoint_metadata(self):
        class ActorControlledCheckpointTarget(ReferenceTarget):
            def evidence_snapshot(self):
                row = super().evidence_snapshot()
                row["integrity"]["checkpoint_independent"] = False
                row["integrity"]["rollback_protected"] = False
                return row

        result = PROBES["ACC-002"](ActorControlledCheckpointTarget())
        self.assertEqual(result.status, "FAIL")
        self.assertTrue(any(not row["trust_model_declared"] for row in result.details["tamper_trials"].values()))

    def test_rev003_rejects_identity_relabel_revival(self):
        class RelabelRevivalTarget(ReferenceTarget):
            def _grant_valid(self, ref, request):
                if ref in self.revoked and request.principal == "renamed-agent":
                    grant = self.grants.get(ref)
                    if grant and grant["action"] == request.action and grant["resource"] == request.resource:
                        return True
                return super()._grant_valid(ref, request)

        result = PROBES["REV-003"](RelabelRevivalTarget())
        self.assertEqual(result.status, "FAIL")
        relabel = next(row for row in result.details["revoked_authority_trials"] if row["variant"] == "relabelled_identity")
        self.assertTrue(relabel["admitted"])

    def test_del001_rejects_ambient_alternate_route_scope_escape(self):
        class AmbientEscapeTarget(ReferenceTarget):
            def _authorized(self, request):
                if request.principal == "child-ok" and request.route == "direct":
                    return True
                return super()._authorized(request)

        result = PROBES["DEL-001"](AmbientEscapeTarget())
        self.assertEqual(result.status, "FAIL")
        self.assertTrue(any(row["admitted"] for row in result.details["ambient_privilege_escape_trials"]))

    def test_rev005_requires_declared_partition_residual_bound(self):
        class PartitionBoundBlindTarget(ReferenceTarget):
            def revoke(self, authority_ref):
                row = super().revoke(authority_ref)
                row.pop("residual_effect_bound", None)
                row.pop("residual_effects_observed", None)
                return row

        result = PROBES["REV-005"](PartitionBoundBlindTarget())
        self.assertEqual(result.status, "FAIL")
        self.assertFalse(result.details["timing_and_residual_bound_verified"])

    def test_newly_discovered_route_is_automatically_attacked(self):
        class NewRouteBypassTarget(ReferenceTarget):
            def reset_fixture(self):
                super().reset_fixture()
                self.declared_paths.add("provider_hosted")
                self.actual_paths.add("provider_hosted")

            def _authorized(self, request):
                if request.route == "provider_hosted":
                    # Simulate a new provider-side execution path that bypasses
                    # normal mediation / stop / revocation.
                    if self.stop_latched:
                        return self._grant_valid(request.authority_ref, request)
                    if request.authority_ref in self.revoked:
                        return True
                    if request.authority_ref is None:
                        return True
                return super()._authorized(request)

        med = PROBES["MED-002"](NewRouteBypassTarget())
        self.assertEqual(med.status, "FAIL")
        self.assertIn("provider_hosted", med.details["routes_tested"])

        human = PROBES["HUM-001"](NewRouteBypassTarget())
        self.assertEqual(human.status, "FAIL")
        self.assertIn("provider_hosted", human.details["routes_tested"])

        rev = PROBES["REV-001"](NewRouteBypassTarget())
        self.assertEqual(rev.status, "FAIL")
        self.assertIn("provider_hosted", rev.details["routes_tested"])

    def test_med002_rejects_always_deny_adapter(self):
        class AlwaysDenyTarget(ReferenceTarget):
            def attempt(self, request):
                value = self.resources.get(request.resource, 0)
                return ActionObservation(
                    admitted=False,
                    outcome="denied",
                    external_state={"resource_value": value},
                    evidence_refs=(),
                )

        result = PROBES["MED-002"](AlwaysDenyTarget())
        self.assertEqual(result.status, "FAIL")
        self.assertFalse(result.details["authorized_state_changed_once"])

    def test_indeterminate_denial_is_not_treated_as_safe_denial(self):
        class IndeterminateDenyTarget(ReferenceTarget):
            def attempt(self, request):
                obs = super().attempt(request)
                if obs.admitted is False:
                    return ActionObservation(
                        admitted=None,
                        outcome="unknown",
                        external_state=obs.external_state,
                        evidence_refs=obs.evidence_refs,
                    )
                return obs

        for rid in ("MED-001", "MED-002", "REV-001", "HUM-001"):
            with self.subTest(requirement=rid):
                self.assertEqual(PROBES[rid](IndeterminateDenyTarget()).status, "FAIL")

    def test_med003_detects_denied_action_that_still_changes_resource(self):
        class DenialWithSideEffectTarget(ReferenceTarget):
            def attempt(self, request):
                obs = super().attempt(request)
                if obs.admitted is False and request.parameters.get("requires_approval"):
                    self.resources[request.resource] = self.resources.get(request.resource, 0) + 1
                return obs

        result = PROBES["MED-003"](DenialWithSideEffectTarget())
        self.assertEqual(result.status, "FAIL")
        self.assertTrue(any(row["state_changed"] for row in result.details["rejected_variants"]))

    def test_hum003_detects_queued_or_delegated_restart_bypass(self):
        class RestartBypassTarget(ReferenceTarget):
            def _authorized(self, request):
                if self.stop_latched and request.route in {"queued", "delegated"}:
                    latched = self.stop_latched
                    self.stop_latched = False
                    try:
                        return super()._authorized(request)
                    finally:
                        self.stop_latched = latched
                return super()._authorized(request)

        result = PROBES["HUM-003"](RestartBypassTarget())
        self.assertEqual(result.status, "FAIL")
        self.assertTrue(any(
            trial["admitted"] is True
            for row in result.details["restarts"]
            for trial in row["trials"]
            if trial["route"] in {"queued", "delegated"}
        ))

    def test_rev006_requires_functional_secondary_containment_not_claimed_state(self):
        class LyingContainmentTarget(ReferenceTarget):
            def secondary_containment(self, scope):
                return {
                    "ok": True,
                    "scope": scope,
                    "primary_control_available": False,
                    "independent_layer": True,
                    "new_critical_effects_blocked": True,
                    "residual_effects": 0,
                    "max_residual_effects": 1,
                    "evidence_ref": "fake:containment",
                }

            def supervision_snapshot(self):
                snapshot = super().supervision_snapshot()
                snapshot["stop_latched"] = True
                return snapshot

        result = PROBES["REV-006"](LyingContainmentTarget())
        self.assertEqual(result.status, "FAIL")
        self.assertTrue(result.details["post_recovery_direct_route"]["admitted"])

    def test_del006_rejects_vacuous_recipient_that_never_had_working_authority(self):
        class RecipientAlwaysDeniedTarget(ReferenceTarget):
            def attempt(self, request):
                if request.principal == "recipient-critical":
                    value = self.resources.get(request.resource, 0)
                    return ActionObservation(
                        admitted=False,
                        outcome="denied",
                        external_state={"resource_value": value},
                        evidence_refs=("fake:recipient-denial",),
                    )
                return super().attempt(request)

        result = PROBES["DEL-006"](RecipientAlwaysDeniedTarget())
        self.assertEqual(result.status, "FAIL")
        self.assertFalse(result.details["positive_recipient_action"]["admitted"])

    def test_ovr006_requires_negative_results_uncertainty_and_limitations(self):
        class IncompleteRedTeamTarget(ReferenceTarget):
            def adversarial_assurance(self):
                row = super().adversarial_assurance()
                row["negative_results_recorded"] = False
                row["uncertainty_reported"] = False
                row["residual_limitations_recorded"] = False
                return row

        result = PROBES["OVR-006"](IncompleteRedTeamTarget())
        self.assertEqual(result.status, "FAIL")

    def test_concurrent_approval_and_budget_controls_are_stable(self):
        # Repeat the race-sensitive probes so atomicity is exercised rather than
        # accepted from one lucky scheduler interleaving.
        for iteration in range(20):
            with self.subTest(requirement="MED-003", iteration=iteration):
                result = PROBES["MED-003"](ReferenceTarget())
                self.assertEqual(result.status, "PASS")
                race = result.details["concurrent_replay"]
                self.assertEqual(race["admitted_count"], 1)
                self.assertEqual(race["denied_count"], 1)
                self.assertTrue(race["single_effect_only"])

            with self.subTest(requirement="DEL-002", iteration=iteration):
                result = PROBES["DEL-002"](ReferenceTarget())
                self.assertEqual(result.status, "PASS")
                self.assertEqual(result.details["admitted_count"], 2)
                self.assertEqual(result.details["denied_count"], 2)
                self.assertEqual(result.details["final_resource_value"], 2)

    def test_acc001_cannot_pass_with_empty_evidence(self):
        class EmptyEvidenceTarget(ReferenceTarget):
            def evidence_snapshot(self):
                return {
                    "events": [],
                    "health_events": [],
                    "trusted_checkpoint": "0" * 64,
                    "verification_errors": [],
                    "operator": "operator",
                    "policy_version": "policy/1",
                }

        result = PROBES["ACC-001"](EmptyEvidenceTarget())
        self.assertEqual(result.status, "FAIL")
        self.assertEqual(result.details["event_count"], 0)

    def test_obs002_requires_evidence_to_match_resource_truth(self):
        class FabricatedObservationTarget(ReferenceTarget):
            def evidence_snapshot(self):
                snapshot = super().evidence_snapshot()
                for event in snapshot.get("events", []):
                    if event.get("resource") == "obs/denied":
                        event["outcome"] = "completed"
                return snapshot

        result = PROBES["OBS-002"](FabricatedObservationTarget())
        self.assertEqual(result.status, "FAIL")
        self.assertFalse(result.details["external_evidence_complete"])

    def test_del005_rejects_good_summary_when_direct_stress_breaks(self):
        class LyingStressTarget(ReferenceTarget):
            def delegation_stress(self):
                row = super().delegation_stress()
                row.update({
                    "operations": 64,
                    "peak_children": 24,
                    "aggregate_budget": 10,
                    "settled_budget": 10,
                    "budget_reset": False,
                    "orphaned_unattributed": 0,
                    "root_revocation_propagated": True,
                    "restart_preserved_lineage": True,
                    "partition_residual_bounded": True,
                    "scenarios": ["concurrent_delegation", "restart", "partition", "root_revocation"],
                    "evidence_ref": "fake:looks-perfect",
                })
                return row

            def restart(self, component):
                result = super().restart(component)
                for root in list(self.root_budget_spent):
                    self.root_budget_spent[root] = 0
                return result

        result = PROBES["DEL-005"](LyingStressTarget())
        self.assertEqual(result.status, "FAIL")
        self.assertTrue(result.details["summary_ok"])
        self.assertFalse(result.details["direct_exercise_ok"])

    def test_acc005_rejects_verifier_that_ignores_evidence_checkpoint_substitution(self):
        class EvidenceBlindVerifier(ReferenceTarget):
            def verify_assessment_attestation(self, attestation):
                row = super().verify_assessment_attestation(attestation)
                payload = attestation.get("payload") or {}
                if payload.get("evidence_checkpoint") != self._trusted_checkpoint:
                    row["valid"] = True
                return row

        result = PROBES["ACC-005"](EvidenceBlindVerifier())
        self.assertEqual(result.status, "FAIL")
        self.assertTrue(result.details["mutations"]["wrong_evidence_checkpoint"]["valid"])

    def test_pass_helper_never_fabricates_reference_evidence(self):
        result = PROBES["MED-001"](ReferenceTarget())
        self.assertEqual(result.status, "PASS")
        self.assertNotIn("reference:med-001", result.evidence_refs)

    def test_acc006_requires_fresh_environment_reconstruction(self):
        class NoFreshVerificationTarget(ReferenceTarget):
            def independent_assurance_package(self):
                package = super().independent_assurance_package()
                package["fresh_environment_verified"] = False
                package["verification_transcript_ref"] = None
                return package

        result = PROBES["ACC-006"](NoFreshVerificationTarget())
        self.assertEqual(result.status, "FAIL")
        self.assertFalse(result.details["clean"]["fresh_environment_verified"])


if __name__ == "__main__":
    unittest.main()
