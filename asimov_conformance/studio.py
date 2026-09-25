"""Local-first web interface for Asimov assessments.

Studio deliberately uses only the Python standard library on the server side.
It is a UI over the existing assessment/verification engine, not a second
implementation of Asimov semantics.
"""
from __future__ import annotations

import json
import secrets
import threading
import urllib.parse
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path
from typing import Any

from .adapter_assistant import AdapterAssistantError, adapter_catalog, generate_adapter, recommendation
from .assessment import (
    AssessmentWorkflowError,
    acknowledge_assessment,
    assessment_status,
    finalize_assessment,
    load_adapter,
    prepare_assessment,
    run_assessment,
    utc_now,
)
from .onboarding import doctor
from .render import render_verification_receipt
from .verification import (
    VerificationError,
    build_public_verification_record,
    embed_public_verification_record,
    sigstore_attest_blob,
    sigstore_sign,
    sigstore_verify,
    verify_package,
    verify_review_attestation,
)

PROVIDER_ISSUERS = {
    "google": "https://accounts.google.com",
    "github": "https://github.com/login/oauth",
    "microsoft": "https://login.microsoftonline.com",
    "github-actions": "https://token.actions.githubusercontent.com",
}

EDITABLE_REVIEW_FIELDS = {
    "reviewer",
    "reviewer_role",
    "reviewer_organization",
    "subject_organization",
    "party_class",
    "role_separated_from_implementation",
    "review_type",
    "relationship_to_target",
    "independence",
    "decision",
    "reviewed_at",
    "rationale",
    "evidence_refs",
    "checklist",
}


class StudioError(ValueError):
    """A request could not be completed safely or consistently."""


def _json_read(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StudioError(f"Cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise StudioError(f"{path} must contain a JSON object")
    return value


def _json_write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".studio.tmp")
    temp.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temp.replace(path)


def _workspace(value: str | Path) -> Path:
    raw = str(value).strip()
    if not raw:
        raise StudioError("Choose a workspace directory.")
    return Path(raw).expanduser().resolve()


def _require_workspace(value: str | Path) -> tuple[Path, dict[str, Any]]:
    root = _workspace(value)
    plan_path = root / "assessment-plan.json"
    if not plan_path.is_file():
        raise StudioError(f"No Asimov assessment workspace found at {root}")
    return root, _json_read(plan_path)


def _review_path(root: Path, item_type: str, item_id: str) -> Path:
    if item_type not in {"requirement", "precondition"}:
        raise StudioError("Review type must be requirement or precondition.")
    if not item_id or any(x in item_id for x in ("/", "\\", "..")):
        raise StudioError("Invalid review item id.")
    folder = "requirements" if item_type == "requirement" else "preconditions"
    return root / "reviews" / folder / f"{item_id}.json"


def _review_summary(path: Path) -> dict[str, Any]:
    record = _json_read(path)
    bundle = path.with_suffix(".sigstore.json")
    return {
        "item_type": record.get("item_type"),
        "item_id": record.get("item_id"),
        "title": record.get("title"),
        "review_requirement": record.get("review_requirement", "HUMAN"),
        "decision": record.get("decision", "PENDING"),
        "reviewer": record.get("reviewer", ""),
        "reviewer_role": record.get("reviewer_role", ""),
        "reviewer_organization": record.get("reviewer_organization", ""),
        "signed": bundle.is_file(),
        "path": str(path),
    }


def workspace_state(value: str | Path) -> dict[str, Any]:
    root = _workspace(value)
    plan_path = root / "assessment-plan.json"
    state: dict[str, Any] = {
        "workspace": str(root),
        "prepared": plan_path.is_file(),
        "exists": root.exists(),
    }
    if not plan_path.is_file():
        return state

    plan = _json_read(plan_path)
    state["plan"] = plan
    try:
        state["status"] = assessment_status(root)
    except (AssessmentWorkflowError, OSError, ValueError) as exc:
        state["status_error"] = str(exc)

    scope_path = root / "scope.json"
    state["scope"] = _json_read(scope_path) if scope_path.is_file() else None

    reviews: list[dict[str, Any]] = []
    for name in plan.get("required_preconditions", []):
        path = _review_path(root, "precondition", str(name))
        if path.is_file():
            reviews.append(_review_summary(path))
    for rid in plan.get("human_review_requirements", []):
        path = _review_path(root, "requirement", str(rid))
        if path.is_file():
            reviews.append(_review_summary(path))
    state["reviews"] = reviews

    technical_path = root / "technical-results.json"
    if technical_path.is_file():
        technical = _json_read(technical_path)
        state["technical"] = {
            "counts": technical.get("counts", {}),
            "results": technical.get("results", []),
        }

    result_path = root / "assessment.result.json"
    state["finalized"] = result_path.is_file()
    if result_path.is_file():
        state["result"] = _json_read(result_path)

    public_path = root / "public-verification.json"
    if public_path.is_file():
        public = _json_read(public_path)
        sig = public.get("sigstore")
        state["report_signature"] = {
            "signed": isinstance(sig, dict),
            "identity": sig.get("certificate_identity") if isinstance(sig, dict) else None,
            "issuer": sig.get("certificate_oidc_issuer") if isinstance(sig, dict) else None,
        }
    else:
        state["report_signature"] = {"signed": False, "identity": None, "issuer": None}

    state["artifacts"] = {
        name: (root / name).is_file()
        for name in (
            "assessment.json",
            "assessment.result.json",
            "report.html",
            "summary.html",
            "evidence-manifest.json",
            "asimov-statement.json",
            "public-verification.json",
            "asimov.sigstore.json",
            "verification-receipt.json",
            "verification-receipt.html",
        )
    }
    return state


def adapter_recommendation_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    resources = payload.get("resources", [])
    evidence = payload.get("evidence", [])
    integrations = payload.get("integrations", [])
    if not isinstance(resources, list) or not all(isinstance(x, str) for x in resources):
        raise StudioError("Resources must be a list of option IDs.")
    if not isinstance(evidence, list) or not all(isinstance(x, str) for x in evidence):
        raise StudioError("Evidence sources must be a list of option IDs.")
    if not isinstance(integrations, list) or not all(isinstance(x, str) for x in integrations):
        raise StudioError("Integrations must be a list of option IDs.")
    return recommendation(
        runtime=str(payload.get("runtime", "")),
        hosting=str(payload.get("hosting") or "") or None,
        authority=str(payload.get("authority") or "") or None,
        resources=resources,
        evidence=evidence,
        integrations=integrations,
    )


def generate_adapter_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    output = str(payload.get("output_dir", "")).strip()
    if not output:
        raise StudioError("Choose an output folder for the starter adapter.")
    resources = payload.get("resources", [])
    evidence = payload.get("evidence", [])
    integrations = payload.get("integrations", [])
    if not isinstance(resources, list) or not all(isinstance(x, str) for x in resources):
        raise StudioError("Resources must be a list of option IDs.")
    if not isinstance(evidence, list) or not all(isinstance(x, str) for x in evidence):
        raise StudioError("Evidence sources must be a list of option IDs.")
    if not isinstance(integrations, list) or not all(isinstance(x, str) for x in integrations):
        raise StudioError("Integrations must be a list of option IDs.")
    try:
        return generate_adapter(
            Path(output),
            runtime=str(payload.get("runtime", "")),
            hosting=str(payload.get("hosting") or "") or None,
            authority=str(payload.get("authority") or "") or None,
            resources=resources,
            evidence=evidence,
            integrations=integrations,
            class_name=str(payload.get("class_name") or "AsimovAdapter"),
            adapter_id=str(payload.get("adapter_id") or "generated-adapter"),
        )
    except AdapterAssistantError as exc:
        raise StudioError(str(exc)) from exc


def prepare_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    root = _workspace(str(payload.get("workspace", "")))
    adapter_spec = str(payload.get("adapter", "")).strip()
    if not adapter_spec:
        raise StudioError("Adapter is required.")
    kwargs = payload.get("adapter_kwargs", {})
    if not isinstance(kwargs, dict):
        raise StudioError("Adapter settings must be a JSON object.")

    adapter = load_adapter(adapter_spec, kwargs)
    try:
        prepare_assessment(
            adapter,
            str(payload.get("level", "A5")),
            root,
            assessor=str(payload.get("assessor", "")),
            mode=str(payload.get("mode", "self_assessment")),
            adapter_spec=adapter_spec,
            subject_organization=str(payload.get("subject_organization", "")),
            assessor_organization=str(payload.get("assessor_organization", "")),
        )
    finally:
        close = getattr(adapter, "close", None)
        if callable(close):
            close()
    return workspace_state(root)


def readiness_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    adapter_spec = str(payload.get("adapter", "")).strip()
    if not adapter_spec:
        raise StudioError("Adapter is required.")
    kwargs = payload.get("adapter_kwargs", {})
    if not isinstance(kwargs, dict):
        raise StudioError("Adapter settings must be a JSON object.")
    adapter = load_adapter(adapter_spec, kwargs)
    try:
        return doctor(adapter, str(payload.get("level", "A5")))
    finally:
        close = getattr(adapter, "close", None)
        if callable(close):
            close()


def acknowledge_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    root, _ = _require_workspace(str(payload.get("workspace", "")))
    acknowledge_assessment(
        root,
        reviewer=str(payload.get("reviewer", "")),
        reviewer_role=str(payload.get("reviewer_role", "")),
    )
    return workspace_state(root)


def run_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    root, plan = _require_workspace(str(payload.get("workspace", "")))
    adapter_spec = str(payload.get("adapter") or plan.get("adapter_spec") or "").strip()
    if not adapter_spec:
        raise StudioError("Adapter is required to run the assessment.")
    kwargs = payload.get("adapter_kwargs", {})
    if not isinstance(kwargs, dict):
        raise StudioError("Adapter settings must be a JSON object.")

    adapter = load_adapter(adapter_spec, kwargs)
    try:
        run_assessment(adapter, root)
    finally:
        close = getattr(adapter, "close", None)
        if callable(close):
            close()
    return workspace_state(root)


def save_scope(payload: dict[str, Any]) -> dict[str, Any]:
    root, _ = _require_workspace(str(payload.get("workspace", "")))
    path = root / "scope.json"
    scope = _json_read(path)
    for key in ("scope_description", "threat_model"):
        if key in payload:
            scope[key] = str(payload[key])
    if "exclusions" in payload:
        exclusions = payload["exclusions"]
        if not isinstance(exclusions, list) or not all(isinstance(x, str) for x in exclusions):
            raise StudioError("Exclusions must be a list of strings.")
        scope["exclusions"] = exclusions
    _json_write(path, scope)
    return workspace_state(root)


def get_review(workspace: str, item_type: str, item_id: str) -> dict[str, Any]:
    root, _ = _require_workspace(workspace)
    path = _review_path(root, item_type, item_id)
    if not path.is_file():
        raise StudioError(f"Review record not found: {item_id}")
    record = _json_read(path)
    record["_studio"] = {
        "signed": path.with_suffix(".sigstore.json").is_file(),
        "path": str(path),
    }
    return record


def save_review(payload: dict[str, Any]) -> dict[str, Any]:
    root, _ = _require_workspace(str(payload.get("workspace", "")))
    item_type = str(payload.get("item_type", ""))
    item_id = str(payload.get("item_id", ""))
    path = _review_path(root, item_type, item_id)
    if not path.is_file():
        raise StudioError(f"Review record not found: {item_id}")
    current = _json_read(path)
    updates = payload.get("record")
    if not isinstance(updates, dict):
        raise StudioError("Review update must be an object.")

    before = json.dumps(current, sort_keys=True, separators=(",", ":"))
    for key in EDITABLE_REVIEW_FIELDS:
        if key in updates:
            current[key] = updates[key]

    decision = current.get("decision")
    if decision in {"PASS", "FAIL", "INCONCLUSIVE"} and not str(current.get("reviewed_at", "")).strip():
        current["reviewed_at"] = utc_now()

    after = json.dumps(current, sort_keys=True, separators=(",", ":"))
    bundle = path.with_suffix(".sigstore.json")
    if before != after and bundle.is_file():
        bundle.unlink()
        signing = current.get("signing_identity")
        if isinstance(signing, dict):
            signing["expected_subject"] = ""
            signing["expected_issuer"] = ""

    _json_write(path, current)
    return get_review(str(root), item_type, item_id)


def _issuer(provider: str, custom: str | None = None) -> str:
    if provider == "custom":
        issuer = (custom or "").strip()
        if not issuer:
            raise StudioError("Custom identity provider requires an OIDC issuer.")
        return issuer
    try:
        return PROVIDER_ISSUERS[provider]
    except KeyError as exc:
        raise StudioError(f"Unsupported identity provider: {provider}") from exc


def sign_review_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    root, _ = _require_workspace(str(payload.get("workspace", "")))
    item_type = str(payload.get("item_type", "requirement"))
    item_id = str(payload.get("item_id", ""))
    path = _review_path(root, item_type, item_id)
    if not path.is_file():
        raise StudioError(f"Review record not found: {item_id}")

    record = _json_read(path)
    if item_type != "requirement":
        raise StudioError("Asimov 0.2 individually attests test-family reviews, not assessment preconditions.")
    if record.get("decision") not in {"PASS", "FAIL"}:
        raise StudioError("Choose PASS or FAIL before signing a family review.")

    identity = str(payload.get("identity", "")).strip()
    if not identity:
        raise StudioError("Signing identity is required.")
    issuer = _issuer(str(payload.get("provider", "google")), payload.get("oidc_issuer"))
    record["signing_identity"] = {
        "type": "sigstore",
        "expected_subject": identity,
        "expected_issuer": issuer,
    }
    _json_write(path, record)

    bundle = path.with_suffix(".sigstore.json")
    code = sigstore_attest_blob(path, path, bundle, yes=True)
    if code != 0:
        record["signing_identity"] = {
            "type": "sigstore",
            "expected_subject": "",
            "expected_issuer": "",
        }
        _json_write(path, record)
        if bundle.exists():
            bundle.unlink()
        raise StudioError(f"Cosign review signing failed with exit code {code}.")
    verified = verify_review_attestation(path, bundle)
    if verified.get("state") != "VERIFIED":
        raise StudioError("The new review attestation did not verify.")
    return {"verification": verified, "state": workspace_state(root)}


def finalize_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    root, _ = _require_workspace(str(payload.get("workspace", "")))
    finalize_assessment(root)
    return workspace_state(root)


def sign_report_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    root, _ = _require_workspace(str(payload.get("workspace", "")))
    report = root / "report.html"
    statement = root / "asimov-statement.json"
    if not report.is_file() or not statement.is_file():
        raise StudioError("Finalize the assessment before signing the report.")

    identity = str(payload.get("identity", "")).strip()
    if not identity:
        raise StudioError("Signing identity is required.")
    issuer = _issuer(str(payload.get("provider", "google")), payload.get("oidc_issuer"))
    bundle = root / "asimov.sigstore.json"

    code = sigstore_sign(statement, bundle, yes=True)
    if code != 0:
        raise StudioError(f"Cosign report signing failed with exit code {code}.")
    ok, detail = sigstore_verify(
        statement,
        bundle,
        certificate_identity=identity,
        certificate_oidc_issuer=issuer,
    )
    if not ok:
        raise StudioError("The new report signature did not verify: " + detail)

    record = build_public_verification_record(
        statement,
        report,
        bundle_path=bundle,
        certificate_identity=identity,
        certificate_oidc_issuer=issuer,
    )
    _json_write(root / "public-verification.json", record)
    embed_public_verification_record(report, record)
    return workspace_state(root)


def verify_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    root, _ = _require_workspace(str(payload.get("workspace", "")))
    assessment = root / "assessment.json"
    manifest = root / "evidence-manifest.json"
    evidence = root / "evidence"
    statement = root / "asimov-statement.json"
    report = root / "report.html"
    required = (assessment, manifest, statement, report)
    missing = [p.name for p in required if not p.is_file()]
    if missing:
        raise StudioError("Finalize the assessment first. Missing: " + ", ".join(missing))

    bundle: Path | None = None
    identity: str | None = None
    issuer: str | None = None
    public_path = root / "public-verification.json"
    if public_path.is_file():
        public = _json_read(public_path)
        sig = public.get("sigstore")
        if isinstance(sig, dict) and (root / "asimov.sigstore.json").is_file():
            bundle = root / "asimov.sigstore.json"
            identity = str(sig.get("certificate_identity") or "")
            issuer = str(sig.get("certificate_oidc_issuer") or "")

    receipt = verify_package(
        assessment_path=assessment,
        evidence_manifest_path=manifest,
        evidence_root=evidence,
        statement_path=statement,
        report_paths=[report],
        bundle_path=bundle,
        certificate_identity=identity or None,
        certificate_oidc_issuer=issuer or None,
    )
    _json_write(root / "verification-receipt.json", receipt)
    (root / "verification-receipt.html").write_text(
        render_verification_receipt(receipt),
        encoding="utf-8",
    )
    return receipt


def _asset(name: str) -> bytes:
    resource = files("asimov_conformance").joinpath("studio_assets", name)
    return resource.read_bytes()


def _valid_host(value: str | None) -> bool:
    if not value:
        return False
    host = value.split(":", 1)[0].strip("[]").lower()
    return host in {"127.0.0.1", "localhost", "::1"}


def make_handler(token: str):
    class StudioHandler(BaseHTTPRequestHandler):
        server_version = "AsimovStudio/0.2"

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _security_headers(self) -> None:
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cross-Origin-Opener-Policy", "same-origin")
            self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                "script-src 'self'; connect-src 'self'; frame-src 'self'; "
                "frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
            )

        def _send_bytes(self, data: bytes, content_type: str, status: int = 200) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self._security_headers()
            self.end_headers()
            self.wfile.write(data)

        def _send_json(self, value: Any, status: int = 200) -> None:
            data = json.dumps(value, ensure_ascii=False).encode("utf-8")
            self._send_bytes(data, "application/json; charset=utf-8", status)

        def _api_token_ok(self, query: dict[str, list[str]]) -> bool:
            supplied = self.headers.get("X-Asimov-Studio-Token")
            if not supplied:
                supplied = (query.get("token") or [""])[0]
            return secrets.compare_digest(str(supplied), token)

        def _guard_api(self, query: dict[str, list[str]]) -> bool:
            if not _valid_host(self.headers.get("Host")) or not self._api_token_ok(query):
                self._send_json({"error": "Studio session authentication failed."}, HTTPStatus.FORBIDDEN)
                return False
            return True

        def _read_payload(self) -> dict[str, Any]:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError as exc:
                raise StudioError("Invalid request size.") from exc
            if length < 0 or length > 2_000_000:
                raise StudioError("Request is too large.")
            data = self.rfile.read(length)
            try:
                value = json.loads(data.decode("utf-8") or "{}")
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise StudioError("Request body must be valid JSON.") from exc
            if not isinstance(value, dict):
                raise StudioError("Request body must be a JSON object.")
            return value

        def do_GET(self) -> None:
            parsed = urllib.parse.urlsplit(self.path)
            query = urllib.parse.parse_qs(parsed.query)

            if parsed.path in {"/", "/index.html"}:
                self._send_bytes(_asset("index.html"), "text/html; charset=utf-8")
                return
            if parsed.path == "/studio.css":
                self._send_bytes(_asset("studio.css"), "text/css; charset=utf-8")
                return
            if parsed.path == "/studio.js":
                self._send_bytes(_asset("studio.js"), "text/javascript; charset=utf-8")
                return
            if parsed.path == "/asimov-mark.svg":
                self._send_bytes(_asset("asimov-mark.svg"), "image/svg+xml")
                return

            if parsed.path.startswith("/api/") or parsed.path == "/report":
                if not self._guard_api(query):
                    return

            try:
                if parsed.path == "/api/catalog":
                    from .gate import catalog
                    self._send_json(catalog())
                    return
                if parsed.path == "/api/adapter-catalog":
                    self._send_json(adapter_catalog())
                    return
                if parsed.path == "/api/state":
                    workspace = (query.get("workspace") or [""])[0]
                    self._send_json(workspace_state(workspace))
                    return
                if parsed.path == "/api/review":
                    workspace = (query.get("workspace") or [""])[0]
                    item_type = (query.get("item_type") or [""])[0]
                    item_id = (query.get("item_id") or [""])[0]
                    self._send_json(get_review(workspace, item_type, item_id))
                    return
                if parsed.path == "/report":
                    root, _ = _require_workspace((query.get("workspace") or [""])[0])
                    report = root / "report.html"
                    if not report.is_file():
                        raise StudioError("No finalized report exists yet.")
                    self._send_bytes(report.read_bytes(), "text/html; charset=utf-8")
                    return
                self._send_json({"error": "Not found."}, HTTPStatus.NOT_FOUND)
            except (StudioError, AdapterAssistantError, AssessmentWorkflowError, VerificationError, OSError, ValueError, ImportError) as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

        def do_POST(self) -> None:
            parsed = urllib.parse.urlsplit(self.path)
            query = urllib.parse.parse_qs(parsed.query)
            if not parsed.path.startswith("/api/"):
                self._send_json({"error": "Not found."}, HTTPStatus.NOT_FOUND)
                return
            if not self._guard_api(query):
                return
            try:
                payload = self._read_payload()
                routes = {
                    "/api/adapter-recommendation": adapter_recommendation_from_payload,
                    "/api/generate-adapter": generate_adapter_from_payload,
                    "/api/prepare": prepare_from_payload,
                    "/api/readiness": readiness_from_payload,
                    "/api/acknowledge": acknowledge_from_payload,
                    "/api/run": run_from_payload,
                    "/api/scope": save_scope,
                    "/api/review": save_review,
                    "/api/sign-review": sign_review_from_payload,
                    "/api/finalize": finalize_from_payload,
                    "/api/sign-report": sign_report_from_payload,
                    "/api/verify": verify_from_payload,
                }
                action = routes.get(parsed.path)
                if action is None:
                    self._send_json({"error": "Not found."}, HTTPStatus.NOT_FOUND)
                    return
                self._send_json(action(payload))
            except (StudioError, AdapterAssistantError, AssessmentWorkflowError, VerificationError, OSError, ValueError, ImportError) as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

    return StudioHandler


def create_server(port: int = 0, *, token: str | None = None) -> tuple[ThreadingHTTPServer, str, str]:
    session_token = token or secrets.token_urlsafe(32)
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(session_token))
    host, bound_port = server.server_address[:2]
    url = f"http://{host}:{bound_port}/?token={urllib.parse.quote(session_token)}"
    return server, url, session_token


def launch_studio(
    *,
    port: int = 0,
    workspace: Path | None = None,
    open_browser: bool = True,
) -> None:
    server, url, _ = create_server(port)
    if workspace is not None:
        separator = "&" if "?" in url else "?"
        url += separator + "workspace=" + urllib.parse.quote(str(workspace.expanduser().resolve()))
    print("ASIMOV STUDIO")
    print("Local only: 127.0.0.1")
    print(f"Open: {url}")
    print("Press Ctrl+C to stop Studio.")

    if open_browser:
        threading.Timer(0.15, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
