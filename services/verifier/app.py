"""Optional Asimov Sigstore verification service."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from asimov_conformance.verification import VerificationError, sigstore_verify

MAX_BYTES = 2 * 1024 * 1024
ALLOWED_ORIGIN = os.environ.get("ASIMOV_ALLOWED_ORIGIN", "https://asimov-safety.github.io")

app = FastAPI(title="Asimov Sigstore Verifier", docs_url=None, redoc_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[ALLOWED_ORIGIN],
    allow_credentials=False,
    allow_methods=["POST"],
    allow_headers=["*"],
)


async def _bounded(upload: UploadFile) -> bytes:
    data = await upload.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise HTTPException(status_code=413, detail="file exceeds 2 MiB limit")
    return data


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/verify-sigstore")
async def verify_sigstore(
    statement: UploadFile = File(...),
    bundle: UploadFile = File(...),
    certificate_identity: str = Form(...),
    certificate_oidc_issuer: str = Form(...),
) -> dict[str, object]:
    statement_bytes, bundle_bytes = await _bounded(statement), await _bounded(bundle)
    with tempfile.TemporaryDirectory(prefix="asimov-verify-") as tmp:
        root = Path(tmp)
        statement_path = root / "statement.json"
        bundle_path = root / "bundle.sigstore.json"
        statement_path.write_bytes(statement_bytes)
        bundle_path.write_bytes(bundle_bytes)
        try:
            ok, detail = sigstore_verify(
                statement_path,
                bundle_path,
                certificate_identity=certificate_identity,
                certificate_oidc_issuer=certificate_oidc_issuer,
            )
        except VerificationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {"verified": ok, "detail": detail[-4000:]}
