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


    def test_declared_capability_without_callable_method_blocks_readiness(self):
        adapter = ReferenceTarget()
        adapter.attempt = None
        report = doctor(adapter, "A1")
        self.assertFalse(report["ready"])
        finding = next(row for row in report["findings"] if row["requirement_id"] == "OBS-001")
        self.assertEqual(finding["state"], "BLOCKED_ADAPTER_METHOD_UNAVAILABLE")
        self.assertIn("attempt()", finding["remediation"])

    def test_malformed_capability_declaration_fails_closed(self):
        class BadCapabilities:
            adapter_id = "bad-capabilities"
            def capabilities(self): return "attempt"

        report = doctor(BadCapabilities(), "A1")
        self.assertFalse(report["ready"])
        self.assertEqual(report["blockers"], report["requirements"])
        self.assertTrue(all(row["state"] == "BLOCKED_CAPABILITY_DISCOVERY" for row in report["findings"]))


    def test_init_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "asimov.toml"
            result = init_project(path)
            self.assertTrue(path.exists())
            self.assertIn("platform", result["environment"])
            with self.assertRaises(FileExistsError):
                init_project(path)


if __name__ == "__main__":
    unittest.main()
