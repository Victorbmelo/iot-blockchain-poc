"""
Unit tests for the signing module.

Tests that signatures round-trip correctly and that a tampered hash fails verification.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gateway.app.signing import sign_payload_hash, verify_signature, cert_fingerprint, signer_id


def test_signature_round_trip():
    payload_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    sig = sign_payload_hash(payload_hash)
    assert isinstance(sig, str)
    assert len(sig) > 0
    assert verify_signature(payload_hash, sig) is True


def test_tampered_hash_fails_verification():
    original_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    tampered_hash = "ba7816bf8f01cfea414140de5dae2268b88c5d2a4a5688d8eb0a6e61ec17be86"
    sig = sign_payload_hash(original_hash)
    assert verify_signature(tampered_hash, sig) is False


def test_cert_fingerprint_is_stable():
    fp1 = cert_fingerprint()
    fp2 = cert_fingerprint()
    assert fp1 == fp2
    assert len(fp1) == 16


def test_signer_id_not_empty():
    assert len(signer_id()) > 0
