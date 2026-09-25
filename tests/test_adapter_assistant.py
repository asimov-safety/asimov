from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from asimov_conformance.__main__ import main
from asimov_conformance.adapter_assistant import (
    AdapterAssistantError,
    adapter_catalog,
    generate_adapter,
    recommendation,
)
from asimov_conformance.assessment import load_adapter
from asimov_conformance.onboarding import doctor


class AdapterAssistantTests(unittest.TestCase):
    def test_catalog_has_current_common_runtime_families_and_six_surfaces(self):
        data = adapter_catalog()
        self.assertEqual(data["schema_version"], "1.0")
        self.assertEqual(len(data["surfaces"]), 6)
        ids = {row["id"] for row in data["runtime_options"]}
        for expected in {
            "openai-agents-api",
            "openai-agents-sdk",
            "openai-responses-custom",
            "anthropic-managed-agents",
            "claude-agent-sdk",
            "anthropic-messages-custom",
            "google-adk",
            "microsoft-agent-framework",
            "langgraph",
            "crewai",
            "custom-local",
        }:
            self.assertIn(expected, ids)
        for row in data["runtime_options"]:
            self.assertTrue(row["docs_url"])
            self.assertIn(row["ownership"], {"managed", "application", "application_or_managed", "application_or_remote"})
            for surface in ("action", "authority", "resource", "lifecycle", "supervision", "evidence"):
                self.assertTrue(row["recommended"].get(surface), f"{row['id']} missing {surface}")

    def test_recommendation_surfaces_stack_specific_gaps(self):
        rec = recommendation(
            runtime="openai-agents-api",
            hosting="kubernetes",
            authority="aws-iam",
            resources=["postgresql", "http-api"],
            evidence=["opentelemetry", "resource-audit"],
            integrations=["mcp"],
        )
        self.assertEqual(rec["runtime"]["id"], "openai-agents-api")
        self.assertEqual(rec["hosting"]["id"], "kubernetes")
        self.assertEqual(rec["authority"]["id"], "aws-iam")
        self.assertEqual({x["id"] for x in rec["resources"]}, {"postgresql", "http-api"})
        self.assertTrue(any("zero Asimov capabilities" in x for x in rec["gaps"]))

    def test_generated_adapter_loads_but_claims_zero_capabilities(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "adapter"
            result = generate_adapter(
                out,
                runtime="claude-agent-sdk",
                hosting="docker",
                authority="os-identity",
                resources=["filesystem"],
                evidence=["application-events", "resource-audit"],
                class_name="GeneratedClaudeAdapter",
                adapter_id="claude-test",
            )
            adapter = load_adapter(result["adapter_spec"], {})
            self.assertEqual(adapter.adapter_id, "claude-test")
            self.assertEqual(adapter.capabilities(), set())
            readiness = doctor(adapter, "A1")
            self.assertFalse(readiness["ready"])
            self.assertGreater(readiness["blockers"], 0)
            self.assertEqual(json.loads((out / "asimov-adapter.json").read_text())["capability_claims"], [])
            self.assertIn("THIS FILE DOES NOT CLAIM CONFORMANCE", (out / "adapter.py").read_text())
            self.assertIn("Claude Agent SDK", (out / "README.md").read_text())

    def test_generator_refuses_nonempty_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "adapter"
            out.mkdir()
            (out / "keep.txt").write_text("do not overwrite", encoding="utf-8")
            with self.assertRaisesRegex(AdapterAssistantError, "refusing to overwrite"):
                generate_adapter(out, runtime="custom-local")

    def test_cli_adapter_catalog_and_scaffold(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            catalog_path = root / "catalog.json"
            self.assertEqual(main(["adapter-catalog", "--json-output", str(catalog_path)]), 0)
            data = json.loads(catalog_path.read_text())
            self.assertGreater(len(data["runtime_options"]), 5)

            out = root / "starter"
            self.assertEqual(
                main([
                    "adapter-scaffold",
                    "--runtime", "google-adk",
                    "--hosting", "gcp",
                    "--authority", "gcp-iam",
                    "--resource", "cloud-resource",
                    "--evidence", "cloud-audit",
                    "--output", str(out),
                ]),
                0,
            )
            self.assertTrue((out / "adapter.py").is_file())
            self.assertTrue((out / "README.md").is_file())
            self.assertTrue((out / "asimov-adapter.json").is_file())


if __name__ == "__main__":
    unittest.main()
