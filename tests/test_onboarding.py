from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from asimov_conformance.onboarding import doctor, init_project
from asimov_conformance.reference_target import ReferenceTarget


class OnboardingTests(unittest.TestCase):
    def test_reference_target_is_ready_for_every_executable_profile(self):
        expected = {"A1": 8, "A2": 21, "A3": 28, "A4": 35, "A5": 42}
        for profile, requirements in expected.items():
            with self.subTest(profile=profile):
                report = doctor(ReferenceTarget(), profile)
                self.assertTrue(report["ready"])
                self.assertEqual(report["blockers"], 0)
                self.assertEqual(report["requirements"], requirements)

    def test_missing_capability_blocks_profile(self):
        class Sparse:
            adapter_id = "sparse"
            def capabilities(self): return {"attempt"}
        report = doctor(Sparse(), "A1")
        self.assertFalse(report["ready"])
        self.assertGreater(report["blockers"], 0)

    def test_init_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "asimov.toml"
            result = init_project(path)
            self.assertTrue(path.exists())
            self.assertIn("platform", result["environment"])
            with self.assertRaises(FileExistsError):
                init_project(path)


    def test_claimed_capability_without_callable_method_is_blocked(self):
        class Overclaiming:
            adapter_id = "overclaiming"
            def capabilities(self):
                return {"action_surface", "fault_injection", "attempt", "issue_grant", "alternate_routes", "observe"}
            def discover_action_surface(self): return {"declared": ["normal"], "discovered": ["normal"], "unknown": [], "coverage_complete": True}
            def inject_fault(self, *args, **kwargs): return {"ok": True}
            def attempt(self, *args, **kwargs): return None
            def issue_grant(self, *args, **kwargs): return "grant"
            observe = None

        report = doctor(Overclaiming(), "A1")
        self.assertFalse(report["ready"])
        obs001 = next(x for x in report["findings"] if x["requirement_id"] == "OBS-001")
        self.assertEqual(obs001["state"], "BLOCKED_MISSING_ADAPTER_METHOD")
        self.assertIn("observe", obs001["missing_methods"])

    def test_malformed_capability_declaration_fails_readiness_closed(self):
        class Broken:
            adapter_id = "broken"
            def capabilities(self): return "attempt"

        report = doctor(Broken(), "A1")
        self.assertFalse(report["ready"])
        self.assertEqual(report["blockers"], report["requirements"])
        self.assertTrue(all(x["state"] == "BLOCKED_INVALID_ADAPTER_CAPABILITIES" for x in report["findings"]))



if __name__ == "__main__":
    unittest.main()
