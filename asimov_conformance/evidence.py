"""Deterministic evidence-manifest hashing for the Asimov draft.

This is an integrity primitive, not an identity or timestamp service. For public
verifiability, sign the generated manifest/attestation with a trusted signing
system (for example Sigstore) and retain an independent transparency/timestamp
proof.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

EVIDENCE_MANIFEST_VERSION = "asimov-evidence-manifest/0.2-draft.1"


class EvidenceError(ValueError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def canonical_json_bytes(value: Any) -> bytes:
    # This deterministic encoding is local to the draft prototype. Interchange
    # profiles should use a published canonicalization standard such as JCS.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _safe_files(root: Path) -> list[Path]:
    root = root.resolve()
    rows: list[Path] = []
    for path in sorted(root.rglob("*"), key=lambda p: p.as_posix()):
        if path.is_symlink():
            raise EvidenceError(f"Symlinks are not allowed in an evidence bundle: {path}")
        if path.is_file():
            rows.append(path)
    return rows


def build_evidence_manifest(root: Path) -> dict[str, Any]:
    root = root.resolve()
    if not root.is_dir():
        raise EvidenceError(f"Evidence root is not a directory: {root}")
    files = []
    for path in _safe_files(root):
        rel = path.relative_to(root).as_posix()
        files.append({"path": rel, "sha256": sha256_file(path), "size": path.stat().st_size})
    content = {"version": EVIDENCE_MANIFEST_VERSION, "algorithm": "sha256", "files": files}
    return {**content, "manifest_sha256": sha256_bytes(canonical_json_bytes(content))}


def verify_evidence_manifest(manifest: dict[str, Any], root: Path) -> list[str]:
    root = root.resolve()
    errors: list[str] = []
    if manifest.get("version") != EVIDENCE_MANIFEST_VERSION:
        errors.append("unsupported evidence manifest version")
    if manifest.get("algorithm") != "sha256":
        errors.append("unsupported digest algorithm")
    files = manifest.get("files")
    if not isinstance(files, list):
        return errors + ["files must be an array"]

    seen: set[str] = set()
    for row in files:
        if not isinstance(row, dict) or set(row) != {"path", "sha256", "size"}:
            errors.append("malformed file row")
            continue
        rel = row.get("path")
        if not isinstance(rel, str) or not rel or rel.startswith("/") or ".." in Path(rel).parts:
            errors.append(f"unsafe path: {rel!r}")
            continue
        if rel in seen:
            errors.append(f"duplicate path: {rel}")
            continue
        seen.add(rel)
        path = root / rel
        try:
            if path.is_symlink() or not path.is_file():
                errors.append(f"missing/non-regular file: {rel}")
                continue
            if path.stat().st_size != row.get("size"):
                errors.append(f"size mismatch: {rel}")
            if sha256_file(path) != row.get("sha256"):
                errors.append(f"digest mismatch: {rel}")
        except OSError as exc:
            errors.append(f"cannot inspect {rel}: {exc}")

    content = {"version": manifest.get("version"), "algorithm": manifest.get("algorithm"), "files": files}
    expected = sha256_bytes(canonical_json_bytes(content))
    if expected != manifest.get("manifest_sha256"):
        errors.append("manifest digest mismatch")
    return errors
