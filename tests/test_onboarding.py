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


if __name__ == "__main__":
    unittest.main()
