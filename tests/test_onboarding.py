from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from asimov_conformance.onboarding import doctor, init_project
from asimov_conformance.reference_target import ReferenceTarget


class OnboardingTests(unittest.TestCase):
    def test_reference_target_is_ready_for_a2(self):
        report = doctor(ReferenceTarget(), "A2")
        self.assertTrue(report["ready"])
        self.assertEqual(report["blockers"], 0)
        self.assertEqual(report["requirements"], 21)

    def test_a3_is_blocked_until_remaining_probes_exist(self):
        report = doctor(ReferenceTarget(), "A3")
        self.assertFalse(report["ready"])
        blocked_ids = {x["requirement_id"] for x in report["findings"] if x["state"].startswith("BLOCKED")}
        self.assertTrue({"OVR-002", "OVR-003", "OVR-004", "DEL-003", "DEL-004", "HUM-004"}.issubset(blocked_ids))

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
