"""Fail-closed aggregation of *reported* Asimov findings.

This module validates and aggregates supplied assessment findings. It does NOT
run deployment probes, authenticate an assessor, verify signatures, review the
meaning of evidence, or authorize deployment.
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from importlib.resources import files
from pathlib import Path
from typing import Any

SPEC_VERSION = "0.2.0"
STATUSES = frozenset({"PASS", "FAIL", "ERROR", "NOT_TESTED", "INCONCLUSIVE", "NOT_APPLICABLE"})
BASE_PRECONDITIONS = (
    "deployment_binding",
    "boundary_review",
    "timing_plan",
    "positive_controls",
    "evidence_review",
)
PROFILE_PRECONDITIONS = {
    1: BASE_PRECONDITIONS,
    2: BASE_PRECONDITIONS,
    3: BASE_PRECONDITIONS,
    4: BASE_PRECONDITIONS + (
        "adversarial_assurance_plan",
        "common_mode_failure_analysis",
        "recovery_exercise",
    ),
    5: BASE_PRECONDITIONS + (
        "adversarial_assurance_plan",
        "common_mode_failure_analysis",
        "recovery_exercise",
        "critical_effect_inventory",
        "domain_safety_case",
        "independent_review_plan",
    ),
}
ALL_PRECONDITIONS = tuple(dict.fromkeys(p for ps in PROFILE_PRECONDITIONS.values() for p in ps))
MODES = frozenset({"illustrative", "self_assessment", "independent_assessment"})
PROFILES = tuple(f"A{i}" for i in range(6))
MAX_REPORT_BYTES = 10 * 1024 * 1024


class ReportError(ValueError):
    """The report is structurally or semantically invalid."""


def catalog() -> dict[str, Any]:
    return json.loads(files("asimov_conformance").joinpath("catalog.json").read_text(encoding="utf-8"))


def _object(value: Any, allowed: set[str], required: set[str], path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReportError(f"{path} must be an object")
    missing, extra = required - value.keys(), value.keys() - allowed
    if missing or extra:
        raise ReportError(f"{path}: missing={sorted(missing)}, unexpected={sorted(extra)}")
    return value


def _text(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReportError(f"{path} must be a nonblank string")
    return value


def _texts(value: Any, path: str) -> list[str]:
    if not isinstance(value, list):
        raise ReportError(f"{path} must be an array of strings")
    for i, item in enumerate(value):
        _text(item, f"{path}[{i}]")
    return value


def _digest(value: Any, path: str) -> None:
    if not isinstance(value, str) or re.fullmatch(r"[a-f0-9]{64}", value) is None:
        raise ReportError(f"{path} must be a lowercase SHA-256 hex digest")


def _finding(value: Any, path: str, *, requirement: bool = False) -> dict[str, Any]:
    keys = {"status", "reason", "evidence_refs"}
    if requirement:
        keys.add("requirement_id")
    value = _object(value, keys, keys, path)
    status = _text(value["status"], f"{path}.status")
    if status not in STATUSES:
        raise ReportError(f"{path}: unknown status {status!r}")
    _text(value["reason"], f"{path}.reason")
    refs = _texts(value["evidence_refs"], f"{path}.evidence_refs")
    if status == "PASS" and not refs:
        raise ReportError(f"{path}: a reported PASS needs evidence references")
    return value


def validate_report(report: Any) -> dict[str, Any]:
    keys = {
        "spec_version", "catalog_version", "report_id", "created_at", "assessment",
        "system", "scope_manifest_sha256", "requested_profile", "preconditions", "results", "limitations"
    }
    report = _object(report, keys, keys, "report")
    for key in ("spec_version", "catalog_version"):
        if report[key] != SPEC_VERSION:
            raise ReportError(f"{key} must equal {SPEC_VERSION!r}")
    _text(report["report_id"], "report_id")
    created = _text(report["created_at"], "created_at")
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})", created) is None:
        raise ReportError("created_at must be a timezone-qualified RFC3339-style timestamp")
    try:
        when = datetime.fromisoformat(created.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReportError("created_at is not a valid timestamp") from exc
    if when.utcoffset() is None:
        raise ReportError("created_at needs a timezone")

    assessment = _object(
        report["assessment"],
        {"mode", "assessor", "subject_organization", "assessor_organization"},
        {"mode", "assessor"},
        "assessment",
    )
    _text(assessment["mode"], "assessment.mode")
    if assessment["mode"] not in MODES:
        raise ReportError("unknown assessment mode")
    _text(assessment["assessor"], "assessment.assessor")
    for key in ("subject_organization", "assessor_organization"):
        if key in assessment and not isinstance(assessment[key], str):
            raise ReportError(f"assessment.{key} must be a string")

    system = _object(report["system"], {"id", "configuration_sha256"}, {"id", "configuration_sha256"}, "system")
    _text(system["id"], "system.id")
    _digest(system["configuration_sha256"], "system.configuration_sha256")
    _digest(report["scope_manifest_sha256"], "scope_manifest_sha256")
    if not isinstance(report["requested_profile"], str) or report["requested_profile"] not in PROFILES:
        raise ReportError("requested_profile must be A0–A5")
    _texts(report["limitations"], "limitations")

    pres = _object(report["preconditions"], set(ALL_PRECONDITIONS), set(), "preconditions")
    for name, finding in pres.items():
        _finding(finding, f"preconditions.{name}")

    if not isinstance(report["results"], list):
        raise ReportError("results must be an array")
    known = {r["id"] for r in catalog()["requirements"]}
    seen: set[str] = set()
    for i, finding in enumerate(report["results"]):
        finding = _finding(finding, f"results[{i}]", requirement=True)
        rid = _text(finding["requirement_id"], f"results[{i}].requirement_id")
        if rid not in known:
            raise ReportError(f"Unknown requirement ID: {rid}")
        if rid in seen:
            raise ReportError(f"Duplicate requirement ID: {rid}")
        seen.add(rid)
    return report


def evaluate_report(report: Any) -> dict[str, Any]:
    """Aggregate findings only. Returned results are NOT conformance certificates."""
    report = validate_report(report)
    index = {r["requirement_id"]: r for r in report["results"]}
    requirements = catalog()["requirements"]
    profiles: dict[str, Any] = {"A0": {"state": "CLASSIFICATION_ONLY"}}

    for level in range(1, 6):
        required = [r["id"] for r in requirements if r["minimum_profile"] <= level]
        pres = PROFILE_PRECONDITIONS[level]
        checked = [(f"PRE:{p}", report["preconditions"].get(p, {}).get("status", "NOT_TESTED")) for p in pres]
        checked += [(rid, index.get(rid, {}).get("status", "NOT_TESTED")) for rid in required]
        unmet = [{"id": rid, "status": status} for rid, status in checked if status != "PASS"]
        if any(status == "FAIL" for _, status in checked):
            state = "REPORTED_FAIL"
        elif unmet:
            state = "REPORTED_INCOMPLETE"
        else:
            state = "REPORTED_PASS"
        profiles[f"A{level}"] = {
            "state": state,
            "mandatory_families": len(required),
            "mandatory_preconditions": len(pres),
            "unmet": unmet,
        }

    requested = report["requested_profile"]
    return {
        "tool": "asimov-report",
        "spec_version": SPEC_VERSION,
        "report_id": report["report_id"],
        "created_at": report["created_at"],
        "assessment_mode": report["assessment"]["mode"],
        "assessor": report["assessment"]["assessor"],
        "subject_organization": report["assessment"].get("subject_organization", ""),
        "assessor_organization": report["assessment"].get("assessor_organization", ""),
        "system": report["system"],
        "scope_manifest_sha256": report["scope_manifest_sha256"],
        "requested_profile": requested,
        "reported_outcome": profiles[requested]["state"],
        "profiles": profiles,
        "preconditions": report["preconditions"],
        "findings": report["results"],
        "claim_status": "ILLUSTRATIVE_ONLY" if report["assessment"]["mode"] == "illustrative" else "UNVERIFIED_REPORTED_RESULTS",
        "certificate_issued": False,
        "evidence_verified_by_this_tool": False,
        "deployment_probed_by_this_tool": False,
        "limitations": report["limitations"],
    }


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReportError(f"Duplicate JSON member: {key}")
        result[key] = value
    return result


def _bad_constant(value: str) -> None:
    raise ReportError(f"Non-standard JSON number: {value}")


def load_report(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            data = stream.read(MAX_REPORT_BYTES + 1)
        if len(data) > MAX_REPORT_BYTES:
            raise ReportError("Report exceeds 10 MiB input limit")
        return json.loads(data, object_pairs_hook=_unique_pairs, parse_constant=_bad_constant)
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ReportError(f"Cannot read report: {exc}") from exc
