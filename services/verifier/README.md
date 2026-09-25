# Asimov verifier service

Optional backend for the website's Sigstore verification step.

The public-first Verify page can check a report and its `public-verification.json` sidecar locally. When that sidecar embeds Sigstore material, the browser sends only the embedded statement/bundle plus expected signer identity/issuer to this service for cryptographic verification. The private assessment evidence is never required.

The browser performs SHA-256 and statement/scope binding locally. This service handles only the Sigstore cryptographic verification step using the official Cosign verifier.

## Requirements

- Python 3.10+
- Cosign installed on PATH
- `pip install -r services/verifier/requirements.txt`

## Run

```bash
export ASIMOV_ALLOWED_ORIGIN=https://asimov-safety.github.io
uvicorn services.verifier.app:app --host 127.0.0.1 --port 8080
```

Set the site's verifier endpoint to:

```text
https://your-verifier.example/verify-sigstore
```

The endpoint receives the public verification statement and Sigstore bundle plus the expected signer identity/issuer. It never needs the private evidence directory.
