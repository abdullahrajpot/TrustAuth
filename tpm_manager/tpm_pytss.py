"""
TPM 2.0 backend using tpm2-pytss (Linux / WSL with TPM device or simulator).

Requires: pip install tpm2-pytss (and OS TPM stack: libtss2-esys, device /dev/tpmrm0 or TCTI).

Set TRUSTAUTH_TPM_TCTI to override the default TCTI (e.g. swtpm: host=127.0.0.1,port=2321).
"""

from __future__ import annotations

import base64
import hashlib
import os
from typing import Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from tpm2_pytss import ESAPI
from tpm2_pytss.constants import ESYS_TR, TPM2_ALG
from tpm2_pytss.tsskey import TSSPrivKey
from tpm2_pytss.types import TPM2B_DIGEST, TPM2B_PUBLIC, TPMT_SIG_SCHEME, TPMT_SIGNATURE, TPMT_TK_HASHCHECK


def _rsa_signature_bytes(sig: TPMT_SIGNATURE) -> bytes:
    """Extract raw RSA signature octets from TPMT_SIGNATURE."""
    try:
        return bytes(sig.signature.rsassa.sig)
    except Exception:
        pass
    try:
        return bytes(sig.signature)
    except Exception:
        pass
    raise RuntimeError("Could not read RSA signature from TPM response")


def _tpm_rsa_public_to_pem(pub: TPM2B_PUBLIC) -> str:
    """Build a SubjectPublicKeyInfo PEM from a TPM2 RSA TPM2B_PUBLIC."""
    pa = pub.publicArea
    if int(pa.type) != int(TPM2_ALG.RSA):
        raise ValueError("TrustAuth TPM backend expects an RSA key")

    modulus = int.from_bytes(bytes(pa.unique.rsa), "big")
    exp = int(pa.parameters.rsa.exponent)
    if exp == 0:
        exp = 65537

    numbers = rsa.RSAPublicNumbers(exp, modulus)
    pub_key = numbers.public_key(default_backend())
    return (
        pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
    )


class Tpm2PytssManager:
    """
    Real TPM: RSA 2048 signing key under owner hierarchy via TSSPrivKey.create_rsa.
    Signatures match server verification: PKCS#1 v1.5 with SHA-256 over UTF-8 challenge.
    """

    def __init__(self, tcti: Optional[str] = None) -> None:
        tcti = tcti or os.getenv("TRUSTAUTH_TPM_TCTI")
        self._ectx = ESAPI(tcti) if tcti else ESAPI()
        self._tss: Optional[TSSPrivKey] = None
        self._key_handle: Optional[ESYS_TR] = None
        self.is_available = True

    def close(self) -> None:
        if self._key_handle is not None:
            try:
                self._ectx.flush_context(self._key_handle)
            except Exception:
                pass
            self._key_handle = None
        if self._ectx is not None:
            self._ectx.close()
            self._ectx = None

    def create_attestation_key(self) -> str:
        self._tss = TSSPrivKey.create_rsa(self._ectx, keyBits=2048)
        self._key_handle = self._tss.load(self._ectx)
        return _tpm_rsa_public_to_pem(self._tss.public)

    def load_from_pem(self, pem_data: bytes) -> str:
        """Restore a previously saved TSSPrivKey PEM (same machine TPM)."""
        self._tss = TSSPrivKey.from_pem(pem_data)
        if self._key_handle is not None:
            try:
                self._ectx.flush_context(self._key_handle)
            except Exception:
                pass
        self._key_handle = self._tss.load(self._ectx)
        return _tpm_rsa_public_to_pem(self._tss.public)

    def to_pem(self) -> bytes:
        if not self._tss:
            raise RuntimeError("No TPM key loaded")
        return self._tss.to_pem()

    def sign_challenge(self, challenge: str) -> Optional[str]:
        if self._tss is None or self._key_handle is None:
            return None
        digest = hashlib.sha256(challenge.encode("utf-8")).digest()
        # Key template from TSSPrivKey.create_rsa fixes RSASSA-SHA256; use NULL scheme to inherit.
        scheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG.NULL)
        validation = TPMT_TK_HASHCHECK()
        sig = self._ectx.sign(
            self._key_handle,
            TPM2B_DIGEST(digest),
            scheme,
            validation,
        )
        sig_bytes = _rsa_signature_bytes(sig)
        return base64.b64encode(sig_bytes).decode("utf-8")

    @staticmethod
    def get_pcr_values() -> list:
        return []
