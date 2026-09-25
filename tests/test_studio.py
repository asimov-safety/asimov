from __future__ import annotations

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

from asimov_conformance.__main__ import main
from asimov_conformance.studio import (
    create_server,
    get_review,
    prepare_from_payload,
    save_review,
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


if __name__ == "__main__":
    unittest.main()
