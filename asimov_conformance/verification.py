"""Asimov verification statements and Sigstore/Cosign integration."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
from typing import Any, Iterable

from .evidence import sha256_file, verify_evidence_manifest, verify_manifest_self_digest
from .gate import SPEC_VERSION, evaluate_report, load_report, validate_report

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://asimov-safety.github.io/asimov/attestation/v0.2"
RECEIPT_VERSION = "asimov-verification-receipt/0.2.0"


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


def _subject(name: str, path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise VerificationError(f"artifact does not exist: {path}")
    return {"name": name, "digest": {"sha256": sha256_file(path)}}


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
        subjects.append(_subject(name, path))
        seen.add(name)

    return {
        "_type": STATEMENT_TYPE,
        "subject": subjects,
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "specVersion": SPEC_VERSION,
            "reportId": assessment["report_id"],
            "assessmentMode": assessment["assessment"]["mode"],
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
