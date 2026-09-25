from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

from asimov_conformance.__main__ import main
from asimov_conformance.studio import (
    acknowledge_from_payload,
    adapter_recommendation_from_payload,
    create_server,
    finalize_from_payload,
    generate_adapter_from_payload,
    get_review,
    prepare_from_payload,
    run_from_payload,
    save_review,
    save_scope,
    sign_review_from_payload,
    workspace_state,
)


class StudioTests(unittest.TestCase):
    def test_server_is_local_and_api_requires_session_token(self):
        server, url, token = create_server(0, token="studio-test-token")
        self.assertEqual(server.server_address[0], "127.0.0.1")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = url.split("/?", 1)[0]
            with urllib.request.urlopen(base + "/", timeout=5) as response:
                self.assertEqual(response.status, 200)
                self.assertIn(b"Asimov Studio", response.read())

            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(base + "/api/catalog", timeout=5)
            self.assertEqual(ctx.exception.code, 403)

            request = urllib.request.Request(
                base + "/api/catalog",
                headers={"X-Asimov-Studio-Token": token},
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                data = json.loads(response.read())
                self.assertEqual(data["version"], "0.2.0")
                self.assertEqual(len(data["requirements"]), 42)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_adapter_assistant_preview_and_generation(self):
        rec = adapter_recommendation_from_payload({
            "runtime": "microsoft-agent-framework",
            "hosting": "azure",
            "authority": "azure-entra-rbac",
            "resources": ["http-api"],
            "evidence": ["cloud-audit"],
            "integrations": [],
        })
        self.assertEqual(rec["runtime"]["id"], "microsoft-agent-framework")
        self.assertEqual(rec["hosting"]["id"], "azure")

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "starter"
            result = generate_adapter_from_payload({
                "output_dir": str(out),
                "runtime": "openai-agents-api",
                "hosting": "kubernetes",
                "authority": "aws-iam",
                "resources": ["postgresql"],
                "evidence": ["opentelemetry", "resource-audit"],
                "integrations": ["mcp"],
                "class_name": "StudioGeneratedAdapter",
                "adapter_id": "studio-generated",
            })
            self.assertTrue((out / "adapter.py").is_file())
            self.assertIn("StudioGeneratedAdapter", (out / "adapter.py").read_text())
            self.assertEqual(result["recommendation"]["runtime"]["id"], "openai-agents-api")
            self.assertTrue(result["adapter_spec"].endswith(":StudioGeneratedAdapter"))

    def test_prepare_reference_workspace_and_read_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "assessment"
            state = prepare_from_payload({
                "workspace": str(root),
                "adapter": "asimov_conformance.reference_target:ReferenceTarget",
                "adapter_kwargs": {},
                "level": "A1",
                "assessor": "Studio Test",
                "subject_organization": "Target Org",
                "assessor_organization": "Target Org",
                "mode": "self_assessment",
            })
            self.assertTrue(state["prepared"])
            self.assertEqual(state["plan"]["requested_profile"], "A1")
            self.assertEqual(state["plan"]["subject_organization"], "Target Org")
            self.assertTrue(state["reviews"])

            reread = workspace_state(root)
            self.assertEqual(reread["plan"]["assessor"], "Studio Test")
            self.assertFalse(reread["finalized"])

    def test_editing_review_invalidates_existing_attestation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "assessment"
            prepare_from_payload({
                "workspace": str(root),
                "adapter": "asimov_conformance.reference_target:ReferenceTarget",
                "adapter_kwargs": {},
                "level": "A1",
                "assessor": "Studio Test",
                "subject_organization": "Target Org",
                "assessor_organization": "Target Org",
                "mode": "self_assessment",
            })
            path = root / "reviews" / "requirements" / "OBS-001.json"
            bundle = path.with_suffix(".sigstore.json")
            bundle.write_text("{}\n", encoding="utf-8")

            record = get_review(str(root), "requirement", "OBS-001")
            updated = dict(record)
            updated.pop("_studio", None)
            updated["rationale"] = "Changed after signing."

            result = save_review({
                "workspace": str(root),
                "item_type": "requirement",
                "item_id": "OBS-001",
                "record": updated,
            })
            self.assertFalse(bundle.exists())
            self.assertEqual(result["rationale"], "Changed after signing.")
            self.assertEqual(result["signing_identity"]["expected_subject"], "")
            self.assertEqual(result["signing_identity"]["expected_issuer"], "")

    def test_full_studio_a1_workflow_uses_portable_workspace_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "assessment"
            adapter = "asimov_conformance.reference_target:ReferenceTarget"
            prepare_from_payload({
                "workspace": str(root),
                "adapter": adapter,
                "adapter_kwargs": {},
                "level": "A1",
                "assessor": "Studio Test",
                "subject_organization": "Target Org",
                "assessor_organization": "Target Org",
                "mode": "self_assessment",
            })
            save_scope({
                "workspace": str(root),
                "scope_description": "Disposable Studio reference assessment.",
                "threat_model": "Reference actor is untrusted relative to reference controls.",
                "exclusions": [],
            })
            acknowledged = acknowledge_from_payload({
                "workspace": str(root),
                "reviewer": "Studio Test",
                "reviewer_role": "Reference assessor",
            })
            self.assertTrue(acknowledged["status"]["pre_run_ready"])

            run_state = run_from_payload({
                "workspace": str(root),
                "adapter": adapter,
                "adapter_kwargs": {},
            })
            self.assertEqual(run_state["technical"]["counts"]["PASS"], 8)

            manual = root / "evidence" / "manual"
            manual.mkdir(parents=True, exist_ok=True)
            plan = json.loads((root / "assessment-plan.json").read_text())

            for item_type, ids in (
                ("precondition", plan["required_preconditions"]),
                ("requirement", plan["human_review_requirements"]),
            ):
                for item_id in ids:
                    evidence = manual / f"{item_id}.txt"
                    evidence.write_text(f"Studio evidence for {item_id}\n", encoding="utf-8")
                    record = get_review(str(root), item_type, item_id)
                    record.pop("_studio", None)
                    record["decision"] = "PASS"
                    record["reviewed_at"] = "2026-09-25T02:00:00Z"
                    record["rationale"] = f"Studio completed review for {item_id}."
                    record["reviewer_organization"] = "Target Org"
                    record["subject_organization"] = "Target Org"
                    record["evidence_refs"] = [f"manual/{item_id}.txt"]
                    for check in record["checklist"]:
                        check["status"] = "PASS"
                        check["evidence_refs"] = [f"manual/{item_id}.txt"]
                    save_review({
                        "workspace": str(root),
                        "item_type": item_type,
                        "item_id": item_id,
                        "record": record,
                    })
                    if item_type == "requirement":
                        def fake_attest(subject, predicate, bundle, **kwargs):
                            bundle.write_text("{}\n", encoding="utf-8")
                            return 0

                        with patch("asimov_conformance.studio.sigstore_attest_blob", side_effect=fake_attest), \
                             patch(
                                 "asimov_conformance.studio.verify_review_attestation",
                                 return_value={"state": "VERIFIED", "item_id": item_id},
                             ):
                            sign_review_from_payload({
                                "workspace": str(root),
                                "item_type": "requirement",
                                "item_id": item_id,
                                "identity": "studio@example.com",
                                "provider": "google",
                            })

            final_state = finalize_from_payload({"workspace": str(root)})
            self.assertTrue(final_state["finalized"])
            self.assertEqual(
                final_state["result"]["reported_outcome"],
                "REPORTED_PASS",
                final_state["result"]["profiles"]["A1"]["unmet"],
            )
            self.assertTrue((root / "assessment.json").is_file())
            self.assertTrue((root / "report.html").is_file())
            self.assertTrue((root / "evidence-manifest.json").is_file())

            # Studio has not created a private database or alternate project format.
            self.assertFalse((root / "studio.db").exists())
            self.assertEqual(workspace_state(root)["result"]["reported_outcome"], "REPORTED_PASS")

    def test_studio_cli_launch_path(self):
        with patch("asimov_conformance.__main__.launch_studio") as launch:
            self.assertEqual(
                main(["studio", "--no-browser", "--port", "0", "--workspace", "./assessment"]),
                0,
            )
            launch.assert_called_once()
            kwargs = launch.call_args.kwargs
            self.assertEqual(kwargs["port"], 0)
            self.assertFalse(kwargs["open_browser"])
            self.assertEqual(kwargs["workspace"], Path("./assessment"))

    def test_studio_assets_are_packaged_source_files(self):
        from importlib.resources import files

        root = files("asimov_conformance").joinpath("studio_assets")
        for name in ("index.html", "studio.css", "studio.js", "asimov-mark.svg"):
            self.assertTrue(root.joinpath(name).is_file(), name)

    def test_studio_javascript_parses_when_node_is_available(self):
        node = shutil.which("node")
        if node is None:
            self.skipTest("Node.js is not installed")
        from importlib.resources import files

        script = files("asimov_conformance").joinpath("studio_assets", "studio.js")
        proc = subprocess.run(
            [node, "--check", str(script)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main()
