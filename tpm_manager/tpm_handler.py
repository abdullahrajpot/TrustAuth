"""
TPM abstraction for TrustAuth.

- **Software** (default): RSA keys in process memory (cryptography). Works everywhere.
- **Real TPM**: TPM 2.0 via `tpm2-pytss` when `TRUSTAUTH_TPM=real` and the stack is installed.

Environment:
- `TRUSTAUTH_TPM` — `auto` | `software` | `real` (default: `auto`)
- `TRUSTAUTH_TPM_TCTI` — optional TCTI string for tpm2-pytss (e.g. `swtpm:host=127.0.0.1,port=2321`)
"""

from __future__ import annotations

import base64
import os
from typing import Optional, Protocol, runtime_checkable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


@runtime_checkable
class TPMBackend(Protocol):
    is_available: bool

    def create_attestation_key(self) -> str: ...

    def sign_challenge(self, challenge: str) -> Optional[str]: ...

    def get_pcr_values(self) -> list: ...


class SoftwareTPMManager:
    """RSA 2048 in software — same crypto profile as the server verifier."""

    def __init__(self) -> None:
        self._private_key = None
        self._public_key = None
        self.is_available = True

    def create_attestation_key(self) -> str:
        self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._public_key = self._private_key.public_key()
        pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pem.decode("utf-8")

    def sign_challenge(self, challenge: str) -> Optional[str]:
        if not self._private_key:
            return None
        sig = self._private_key.sign(
            challenge.encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return base64.b64encode(sig).decode("utf-8")

    @staticmethod
    def get_pcr_values() -> list:
        return []


class TPMManager:
    """
    Facade used by the client: picks real TPM or software based on env.
    """

    def __init__(self) -> None:
        self._backend: TPMBackend = _select_backend()

    @property
    def is_available(self) -> bool:
        return self._backend.is_available

    def create_attestation_key(self) -> str:
        return self._backend.create_attestation_key()

    def sign_challenge(self, challenge: str) -> Optional[str]:
        return self._backend.sign_challenge(challenge)

    def get_pcr_values(self) -> list:
        return self._backend.get_pcr_values()

    def load_tpm_key_pem(self, pem_bytes: bytes) -> str:
        """Used when restoring a saved tpm2-pytss key (real TPM mode only)."""
        if hasattr(self._backend, "load_from_pem"):
            return self._backend.load_from_pem(pem_bytes)  # type: ignore[attr-defined]
        raise RuntimeError("load_tpm_key_pem is only supported with the real TPM backend")

    def export_tpm_key_pem(self) -> bytes:
        if hasattr(self._backend, "to_pem"):
            return self._backend.to_pem()  # type: ignore[attr-defined]
        raise RuntimeError("export_tpm_key_pem is only supported with the real TPM backend")

    @staticmethod
    def verify_signature(public_key_pem: str, challenge: str, signature_b64: str) -> bool:
        """Server-side verification (used by api.server)."""
        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
            signature = base64.b64decode(signature_b64.encode("utf-8"))
            public_key.verify(
                signature,
                challenge.encode("utf-8"),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            return True
        except (ValueError, TypeError, InvalidSignature):
            return False


def _select_backend() -> TPMBackend:
    mode = os.getenv("TRUSTAUTH_TPM", "auto").strip().lower()
    if mode == "software":
        return SoftwareTPMManager()

    if mode in ("real", "auto"):
        try:
            from tpm_manager.tpm_pytss import Tpm2PytssManager

            return Tpm2PytssManager()
        except Exception:
            if mode == "real":
                raise
            return SoftwareTPMManager()

    return SoftwareTPMManager()
