"""Asimov verification statements and Sigstore/Cosign integration."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any, Iterable

from .evidence import sha256_file, verify_evidence_manifest, verify_manifest_self_digest
from .gate import SPEC_VERSION, evaluate_report, load_report, validate_report

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://asimov-safety.github.io/asimov/attestation/v0.2"
RECEIPT_VERSION = "asimov-verification-receipt/0.2.0"
PUBLIC_RECORD_VERSION = "asimov-public-verification/0.2.0"
PUBLIC_CAPSULE_START = "<!-- ASIMOV-PUBLIC-VERIFICATION-START -->"
PUBLIC_CAPSULE_END = "<!-- ASIMOV-PUBLIC-VERIFICATION-END -->"
PUBLIC_CAPSULE_ID = "asimov-public-verification"


class VerificationError(ValueError):
    pass


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"cannot read {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise VerificationError(f"{label} must be a JSON object")
    return value


def _strip_public_capsule(text: str) -> str:
    pattern = re.compile(
        re.escape(PUBLIC_CAPSULE_START) + r".*?" + re.escape(PUBLIC_CAPSULE_END),
        re.DOTALL,
    )
    return pattern.sub("", text, count=1)


def public_report_sha256(path: Path) -> str:
    """Digest the public report content while excluding its embedded verification capsule.

    This avoids the cryptographic self-reference problem: the capsule may contain
    the statement and signature material that authenticate the report, while the
    digest remains stable as that capsule is added or updated.
    """
    if not path.is_file():
        raise VerificationError(f"artifact does not exist: {path}")
    if path.suffix.lower() != ".html":
        return sha256_file(path)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise VerificationError(f"cannot read public HTML report: {exc}") from exc
    unsigned = _strip_public_capsule(text)
    return hashlib.sha256(unsigned.encode("utf-8")).hexdigest()


def _subject(name: str, path: Path, *, public_report: bool = False) -> dict[str, Any]:
    if not path.is_file():
        raise VerificationError(f"artifact does not exist: {path}")
    digest = public_report_sha256(path) if public_report else sha256_file(path)
    return {"name": name, "digest": {"sha256": digest}}


def embed_public_verification_record(report_path: Path, record: dict[str, Any]) -> None:
    if report_path.suffix.lower() != ".html":
        raise VerificationError("one-file embedded public verification currently requires an HTML report")
    try:
        text = report_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise VerificationError(f"cannot read public HTML report: {exc}") from exc

    safe_json = json.dumps(record, separators=(",", ":"), ensure_ascii=False).replace("<", "\\u003c")
    block = (
        PUBLIC_CAPSULE_START
        + f'<script type="application/json" id="{PUBLIC_CAPSULE_ID}">'
        + safe_json
        + "</script>"
        + PUBLIC_CAPSULE_END
    )
    if PUBLIC_CAPSULE_START in text and PUBLIC_CAPSULE_END in text:
        pattern = re.compile(
            re.escape(PUBLIC_CAPSULE_START) + r".*?" + re.escape(PUBLIC_CAPSULE_END),
            re.DOTALL,
        )
        text = pattern.sub(lambda _: block, text, count=1)
    else:
        marker = "</body>"
        if marker in text:
            text = text.replace(marker, block + marker, 1)
        else:
            text = text + block
    report_path.write_text(text, encoding="utf-8")


def extract_public_verification_record(report_path: Path) -> dict[str, Any]:
    if report_path.suffix.lower() != ".html":
        raise VerificationError("embedded public verification currently requires an HTML report")
    try:
        text = report_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise VerificationError(f"cannot read public HTML report: {exc}") from exc
    pattern = re.compile(
        re.escape(PUBLIC_CAPSULE_START)
        + r'\s*<script type="application/json" id="'
        + re.escape(PUBLIC_CAPSULE_ID)
        + r'">(.*?)</script>\s*'
        + re.escape(PUBLIC_CAPSULE_END),
        re.DOTALL,
    )
    match = pattern.search(text)
    if match is None:
        raise VerificationError("report does not contain an embedded Asimov public verification capsule")
    try:
        value = json.loads(match.group(1))
    except json.JSONDecodeError as exc:
        raise VerificationError("embedded public verification capsule is invalid JSON") from exc
    if not isinstance(value, dict):
        raise VerificationError("embedded public verification capsule must be a JSON object")
    return value


def build_verification_statement(
    assessment_path: Path,
    evidence_manifest_path: Path,
    report_paths: Iterable[Path] = (),
) -> dict[str, Any]:
    assessment = validate_report(load_report(assessment_path))
    result = evaluate_report(assessment)
    manifest = _load_json(evidence_manifest_path, "evidence manifest")
    manifest_errors = verify_manifest_self_digest(manifest)
    if manifest_errors:
        raise VerificationError("; ".join(manifest_errors))

    subjects = [
        _subject("asimov-assessment", assessment_path),
        _subject("asimov-evidence-manifest", evidence_manifest_path),
    ]
    seen = {row["name"] for row in subjects}
    for path in report_paths:
        name = f"report/{path.name}"
        if name in seen:
            raise VerificationError(f"duplicate report artifact name: {path.name}")
        subjects.append(_subject(name, path, public_report=path.suffix.lower() == ".html"))
        seen.add(name)

    return {
        "_type": STATEMENT_TYPE,
        "subject": subjects,
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "specVersion": SPEC_VERSION,
            "reportId": assessment["report_id"],
            "assessmentMode": assessment["assessment"]["mode"],
            "assessor": assessment["assessment"]["assessor"],
            "assessmentCreatedAt": assessment["created_at"],
            "system": {
                "id": assessment["system"]["id"],
                "configurationSha256": assessment["system"]["configuration_sha256"],
            },
            "requestedProfile": assessment["requested_profile"],
            "reportedOutcome": result["reported_outcome"],
            "scopeManifestSha256": assessment["scope_manifest_sha256"],
            "evidenceManifestSha256": manifest["manifest_sha256"],
        },
    }


def verify_statement_binding(
    statement: dict[str, Any],
    assessment_path: Path,
    evidence_manifest_path: Path,
    report_paths: Iterable[Path] = (),
) -> list[str]:
    errors: list[str] = []
    try:
        expected = build_verification_statement(assessment_path, evidence_manifest_path, report_paths)
    except (VerificationError, ValueError) as exc:
        return [str(exc)]

    if statement.get("_type") != STATEMENT_TYPE:
        errors.append("unexpected statement type")
    if statement.get("predicateType") != PREDICATE_TYPE:
        errors.append("unexpected predicate type")

    supplied_subjects = statement.get("subject")
    if not isinstance(supplied_subjects, list):
        errors.append("statement subject must be an array")
    else:
        supplied = {
            row.get("name"): (row.get("digest") or {}).get("sha256")
            for row in supplied_subjects
            if isinstance(row, dict)
        }
        expected_subjects = {
            row["name"]: row["digest"]["sha256"]
            for row in expected["subject"]
        }
        if supplied != expected_subjects:
            errors.append("artifact subject digests do not match")

    if statement.get("predicate") != expected["predicate"]:
        errors.append("assessment/scope predicate does not match")
    return errors


def build_public_verification_record(
    statement_path: Path,
    report_path: Path,
    *,
    bundle_path: Path | None = None,
    certificate_identity: str | None = None,
    certificate_oidc_issuer: str | None = None,
) -> dict[str, Any]:
    """Build the small sidecar intended to travel with a public report.

    The record deliberately embeds the verification statement and, when
    supplied, the Sigstore bundle. Public readers therefore need only the
    report plus this one JSON file. Full/private evidence is not included.
    """
    statement_text = statement_path.read_text(encoding="utf-8")
    statement = _load_json(statement_path, "verification statement")
    if statement.get("_type") != STATEMENT_TYPE or statement.get("predicateType") != PREDICATE_TYPE:
        raise VerificationError("verification statement has an unsupported type/predicate")

    report_digest = public_report_sha256(report_path)
    report_name = f"report/{report_path.name}"
    matching = [
        row for row in statement.get("subject", [])
        if isinstance(row, dict) and row.get("name") == report_name
    ]
    if len(matching) != 1 or (matching[0].get("digest") or {}).get("sha256") != report_digest:
        raise VerificationError("report is not bound by the supplied verification statement")

    signed = any(x is not None for x in (bundle_path, certificate_identity, certificate_oidc_issuer))
    if signed and not (bundle_path and certificate_identity and certificate_oidc_issuer):
        raise VerificationError(
            "bundle, certificate identity, and OIDC issuer must be supplied together"
        )

    sigstore: dict[str, Any] | None = None
    if signed:
        bundle = _load_json(bundle_path, "Sigstore bundle")
        sigstore = {
            "bundle": bundle,
            "certificate_identity": certificate_identity,
            "certificate_oidc_issuer": certificate_oidc_issuer,
        }

    return {
        "version": PUBLIC_RECORD_VERSION,
        "report": {
            "name": report_path.name,
            "sha256": report_digest,
        },
        "statement": {
            "sha256": sha256_file(statement_path),
            "text": statement_text,
        },
        "sigstore": sigstore,
        "meaning": {
            "local_report_match": (
                "The supplied report bytes match the digest bound in the verification statement."
            ),
            "signed_provenance": (
                "When Sigstore verifies, the exact verification statement was signed by the "
                "expected authenticated identity and externally checkpointed."
            ),
            "semantic_limit": (
                "Cryptographic verification does not determine whether the assessment evidence "
                "or conclusion is substantively correct."
            ),
        },
    }


def verify_public_report(
    report_path: Path,
    record_path: Path | None = None,
    *,
    cosign_bin: str = "cosign",
) -> dict[str, Any]:
    """Verify a public report using its embedded capsule or an optional sidecar."""
    record = (
        _load_json(record_path, "public verification record")
        if record_path is not None
        else extract_public_verification_record(report_path)
    )
    if record.get("version") != PUBLIC_RECORD_VERSION:
        raise VerificationError("unsupported public verification record version")
    report = record.get("report")
    statement_container = record.get("statement")
    if not isinstance(report, dict) or not isinstance(statement_container, dict):
        raise VerificationError("public verification record is missing report/statement data")
    statement_text = statement_container.get("text")
    statement_sha256 = statement_container.get("sha256")
    if not isinstance(statement_text, str) or not isinstance(statement_sha256, str):
        raise VerificationError("public verification record is missing exact statement bytes")
    actual_statement_sha256 = hashlib.sha256(statement_text.encode("utf-8")).hexdigest()
    if actual_statement_sha256 != statement_sha256:
        raise VerificationError("embedded verification statement digest mismatch")
    try:
        statement = json.loads(statement_text)
    except json.JSONDecodeError as exc:
        raise VerificationError("embedded verification statement is invalid JSON") from exc

    actual_digest = public_report_sha256(report_path)
    expected_digest = report.get("sha256")
    subject_name = f"report/{report.get('name', '')}"
    subjects = {
        row.get("name"): (row.get("digest") or {}).get("sha256")
        for row in statement.get("subject", [])
        if isinstance(row, dict)
    }
    local_errors = []
    if actual_digest != expected_digest:
        local_errors.append("report digest does not match the public verification record")
    if subjects.get(subject_name) != actual_digest:
        local_errors.append("verification statement does not bind the supplied report digest")
    if statement.get("_type") != STATEMENT_TYPE:
        local_errors.append("unexpected statement type")
    if statement.get("predicateType") != PREDICATE_TYPE:
        local_errors.append("unexpected predicate type")

    sig = record.get("sigstore")
    sigstore_state = "UNSIGNED"
    sigstore_detail = ""
    signer_identity = None
    oidc_issuer = None
    if isinstance(sig, dict):
        signer_identity = sig.get("certificate_identity")
        oidc_issuer = sig.get("certificate_oidc_issuer")
        bundle = sig.get("bundle")
        if not signer_identity or not oidc_issuer or not isinstance(bundle, dict):
            sigstore_state = "FAILED"
            sigstore_detail = "embedded Sigstore material is incomplete"
        else:
            import tempfile
            with tempfile.TemporaryDirectory(prefix="asimov-public-verify-") as tmp:
                root = Path(tmp)
                statement_path = root / "statement.json"
                bundle_path = root / "bundle.sigstore.json"
                statement_path.write_text(statement_text, encoding="utf-8")
                bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
                try:
                    ok, sigstore_detail = sigstore_verify(
                        statement_path,
                        bundle_path,
                        certificate_identity=signer_identity,
                        certificate_oidc_issuer=oidc_issuer,
                        cosign_bin=cosign_bin,
                    )
                    sigstore_state = "VERIFIED" if ok else "FAILED"
                except VerificationError as exc:
                    sigstore_state = "FAILED"
                    sigstore_detail = str(exc)

    local_state = "VERIFIED" if not local_errors else "FAILED"
    if local_errors or sigstore_state == "FAILED":
        overall = "FAILED"
    elif sigstore_state == "VERIFIED":
        overall = "AUTHENTICATED"
    else:
        overall = "LOCAL_MATCH_ONLY"

    predicate = statement.get("predicate") or {}
    return {
        "version": PUBLIC_RECORD_VERSION,
        "overall": overall,
        "report_integrity": {
            "state": local_state,
            "errors": local_errors,
            "sha256": actual_digest,
        },
        "provenance": {
            "state": sigstore_state,
            "signer_identity": signer_identity,
            "oidc_issuer": oidc_issuer,
            "detail": sigstore_detail,
        },
        "assessment_binding": {
            "report_id": predicate.get("reportId"),
            "system_id": (predicate.get("system") or {}).get("id"),
            "requested_profile": predicate.get("requestedProfile"),
            "reported_outcome": predicate.get("reportedOutcome"),
            "assessment_mode": predicate.get("assessmentMode"),
            "assessment_created_at": predicate.get("assessmentCreatedAt"),
            "configuration_sha256": (predicate.get("system") or {}).get("configurationSha256"),
            "scope_manifest_sha256": predicate.get("scopeManifestSha256"),
            "evidence_manifest_sha256": predicate.get("evidenceManifestSha256"),
        },
        "semantic_assurance": "NOT_ESTABLISHED_BY_CRYPTOGRAPHY",
    }


def _resolve_cosign(cosign_bin: str) -> str:
    if Path(cosign_bin).is_file():
        return str(Path(cosign_bin))
    found = shutil.which(cosign_bin)
    if found is None:
        raise VerificationError(
            "Cosign was not found. Install Cosign from https://docs.sigstore.dev/cosign/system_config/installation/"
        )
    return found


def sigstore_sign(
    statement_path: Path,
    bundle_path: Path,
    *,
    cosign_bin: str = "cosign",
    yes: bool = False,
) -> int:
    binary = _resolve_cosign(cosign_bin)
    cmd = [binary, "sign-blob", str(statement_path), "--bundle", str(bundle_path)]
    if yes:
        cmd.append("--yes")
    return subprocess.run(cmd, check=False).returncode


def sigstore_verify(
    statement_path: Path,
    bundle_path: Path,
    *,
    certificate_identity: str,
    certificate_oidc_issuer: str,
    cosign_bin: str = "cosign",
) -> tuple[bool, str]:
    binary = _resolve_cosign(cosign_bin)
    cmd = [
        binary,
        "verify-blob",
        str(statement_path),
        "--bundle",
        str(bundle_path),
        f"--certificate-identity={certificate_identity}",
        f"--certificate-oidc-issuer={certificate_oidc_issuer}",
    ]
    proc = subprocess.run(cmd, check=False, capture_output=True, text=True)
    message = (proc.stdout + "\n" + proc.stderr).strip()
    return proc.returncode == 0, message


def verify_package(
    *,
    assessment_path: Path,
    evidence_manifest_path: Path,
    evidence_root: Path,
    statement_path: Path,
    report_paths: Iterable[Path] = (),
    bundle_path: Path | None = None,
    certificate_identity: str | None = None,
    certificate_oidc_issuer: str | None = None,
    cosign_bin: str = "cosign",
) -> dict[str, Any]:
    manifest = _load_json(evidence_manifest_path, "evidence manifest")
    statement = _load_json(statement_path, "verification statement")

    integrity_errors = verify_evidence_manifest(manifest, evidence_root)
    binding_errors = verify_statement_binding(
        statement, assessment_path, evidence_manifest_path, report_paths
    )

    sigstore_state = "NOT_CHECKED"
    sigstore_message = ""
    if any(x is not None for x in (bundle_path, certificate_identity, certificate_oidc_issuer)):
        if not (bundle_path and certificate_identity and certificate_oidc_issuer):
            sigstore_state = "FAILED"
            sigstore_message = "bundle, certificate identity, and OIDC issuer must be supplied together"
        else:
            try:
                ok, sigstore_message = sigstore_verify(
                    statement_path,
                    bundle_path,
                    certificate_identity=certificate_identity,
                    certificate_oidc_issuer=certificate_oidc_issuer,
                    cosign_bin=cosign_bin,
                )
                sigstore_state = "VERIFIED" if ok else "FAILED"
            except VerificationError as exc:
                sigstore_state = "FAILED"
                sigstore_message = str(exc)

    local_ok = not integrity_errors and not binding_errors
    if not local_ok or sigstore_state == "FAILED":
        overall = "FAILED"
    elif sigstore_state == "VERIFIED":
        overall = "VERIFIED"
    else:
        overall = "LOCAL_BINDING_VERIFIED"

    assessment = validate_report(load_report(assessment_path))
    result = evaluate_report(assessment)
    return {
        "version": RECEIPT_VERSION,
        "overall": overall,
        "report_id": assessment["report_id"],
        "system_id": assessment["system"]["id"],
        "requested_profile": assessment["requested_profile"],
        "reported_outcome": result["reported_outcome"],
        "checks": {
            "evidence_integrity": {
                "state": "VERIFIED" if not integrity_errors else "FAILED",
                "errors": integrity_errors,
            },
            "artifact_and_scope_binding": {
                "state": "VERIFIED" if not binding_errors else "FAILED",
                "errors": binding_errors,
            },
            "sigstore_identity_and_transparency": {
                "state": sigstore_state,
                "identity": certificate_identity,
                "oidc_issuer": certificate_oidc_issuer,
                "detail": sigstore_message,
            },
            "semantic_assurance": {
                "state": "REVIEW_REQUIRED",
                "detail": "Cryptographic verification does not replace review of whether evidence supports each Constant.",
            },
        },
    }
