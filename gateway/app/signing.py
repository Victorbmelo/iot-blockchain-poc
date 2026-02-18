"""
Gateway signing module.

Generates an ECDSA key pair on startup and signs the canonical payload hash
of every submitted event. The signature provides non-repudiation at the gateway
level: any verifier holding the public key can confirm that this gateway
produced this specific payload hash.

In production the private key would be stored in an HSM or a secrets manager.
For the prototype it is generated in memory (or loaded from GATEWAY_SIGNING_KEY_FILE).
"""
import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
import base64

_SIGNER_ID = os.getenv("GATEWAY_SIGNER_ID", "audit-gateway-01")
_KEY_FILE = os.getenv("GATEWAY_SIGNING_KEY_FILE", "")


def _load_or_generate_key() -> ec.EllipticCurvePrivateKey:
    if _KEY_FILE and Path(_KEY_FILE).exists():
        pem = Path(_KEY_FILE).read_bytes()
        return serialization.load_pem_private_key(pem, password=None)
    return ec.generate_private_key(ec.SECP256R1())


_private_key: ec.EllipticCurvePrivateKey = _load_or_generate_key()
_public_key = _private_key.public_key()

_cert_fingerprint: str = hashlib.sha256(
    _public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
).hexdigest()[:16]


def sign_payload_hash(payload_hash: str) -> str:
    """Sign the payload hash with the gateway private key.

    Returns a base64-encoded DER signature.
    The verifier needs only the payload_hash and the public key - not the
    original payload - to confirm the signature.
    """
    der_sig = _private_key.sign(
        payload_hash.encode("utf-8"),
        ec.ECDSA(hashes.SHA256()),
    )
    return base64.b64encode(der_sig).decode("ascii")


def verify_signature(payload_hash: str, signature_b64: str) -> bool:
    """Verify a signature produced by this gateway against the stored payload hash."""
    try:
        der_sig = base64.b64decode(signature_b64)
        _public_key.verify(der_sig, payload_hash.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def public_key_pem() -> str:
    return _public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def signer_id() -> str:
    return _SIGNER_ID


def cert_fingerprint() -> str:
    return _cert_fingerprint
