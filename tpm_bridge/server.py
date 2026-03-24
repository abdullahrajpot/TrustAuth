"""
Local TPM bridge for the browser UI.

Web pages cannot open the platform TPM directly. This process listens on loopback only
and signs challenges using the same TPMManager stack as the CLI (real TPM when configured).

Run (second terminal, while the API is up):
  python -m tpm_bridge.server

Then open the dashboard; set "TPM bridge" to http://127.0.0.1:8740
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

load_dotenv()

from tpm_manager.tpm_handler import TPMManager

BRIDGE_HOST = os.getenv("TRUSTAUTH_TPM_BRIDGE_HOST", "127.0.0.1")
BRIDGE_PORT = int(os.getenv("TRUSTAUTH_TPM_BRIDGE_PORT", "8740"))
TPM_KEY_PATH = Path(os.getenv("TRUSTAUTH_TPM_KEY_FILE", "trustauth_tpm_key.pem"))

app = FastAPI(title="TrustAuth TPM Bridge", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_tpm: TPMManager | None = None
_public_pem_cache: str | None = None


def _manager() -> TPMManager:
    global _tpm
    if _tpm is None:
        _tpm = TPMManager()
    return _tpm


def _ensure_device_key() -> str:
    """Load or create TPM/software key; return SubjectPublicKeyInfo PEM for registration."""
    global _public_pem_cache
    tpm = _manager()
    if _public_pem_cache:
        return _public_pem_cache
    if TPM_KEY_PATH.is_file():
        try:
            _public_pem_cache = tpm.load_tpm_key_pem(TPM_KEY_PATH.read_bytes())
            return _public_pem_cache
        except RuntimeError:
            pass
    _public_pem_cache = tpm.create_attestation_key()
    try:
        TPM_KEY_PATH.write_bytes(tpm.export_tpm_key_pem())
    except RuntimeError:
        pass
    return _public_pem_cache


class SignBody(BaseModel):
    challenge: str = Field(min_length=1, max_length=4096)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "tpm_mode": os.getenv("TRUSTAUTH_TPM", "auto")}


@app.get("/public-pem")
def public_pem() -> dict:
    try:
        pem = _ensure_device_key()
        return {"public_pem": pem}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/sign")
def sign(body: SignBody) -> dict:
    try:
        _ensure_device_key()
        sig = _manager().sign_challenge(body.challenge)
        if not sig:
            raise HTTPException(status_code=500, detail="Signing failed")
        return {"signature": sig}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("tpm_bridge.server:app", host=BRIDGE_HOST, port=BRIDGE_PORT, reload=False)
