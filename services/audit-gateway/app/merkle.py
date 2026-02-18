"""
merkle.py - Binary Merkle tree over SHA-256 event hashes.

The Merkle root summarises N event hashes into one 32-byte value that is
anchored on-chain via storeBatchRoot(). Any event can later be proven to be
part of the batch with O(log N) sibling hashes.

Canonical tree:
  Leaves are sorted before building -> same set of events always produces
  the same root, regardless of submission order.

Hashing:
  Leaf:   bytes.fromhex(event_hash_sha256_hex)
  Node:   SHA-256(min(left,right) + max(left,right))  - sorted pair
  Root:   hex string of final 32-byte value
"""
import hashlib
from typing import Optional


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _hash_pair(a: bytes, b: bytes) -> bytes:
    lo, hi = (a, b) if a <= b else (b, a)
    return _sha256(lo + hi)


def compute_root(event_hashes: list[str]) -> str:
    """Return the Merkle root of a list of SHA-256 hex event hashes.
    Returns '00'*32 for an empty list.
    """
    if not event_hashes:
        return "0" * 64
    layer = sorted(bytes.fromhex(h) for h in event_hashes)
    while len(layer) > 1:
        nxt = []
        for i in range(0, len(layer), 2):
            l, r = layer[i], layer[i + 1] if i + 1 < len(layer) else layer[i]
            nxt.append(_hash_pair(l, r))
        layer = nxt
    return layer[0].hex()


def compute_proof(event_hashes: list[str], target_hash: str) -> Optional[list[str]]:
    """Return Merkle proof for target_hash, or None if not found."""
    if target_hash not in event_hashes:
        return None
    layer = sorted(bytes.fromhex(h) for h in event_hashes)
    target = bytes.fromhex(target_hash)
    proof: list[str] = []
    while len(layer) > 1:
        nxt = []
        new_target = None
        for i in range(0, len(layer), 2):
            l, r = layer[i], layer[i + 1] if i + 1 < len(layer) else layer[i]
            node = _hash_pair(l, r)
            nxt.append(node)
            if l == target and r != l:
                proof.append(r.hex()); new_target = node
            elif r == target:
                proof.append(l.hex()); new_target = node
            elif l == target and r == l:
                new_target = node  # odd leaf duplication
        layer = nxt
        if new_target:
            target = new_target
    return proof


def verify_proof(event_hash: str, proof: list[str], root: str) -> bool:
    """Verify a Merkle inclusion proof against the stored root."""
    cur = bytes.fromhex(event_hash)
    for sib in proof:
        cur = _hash_pair(cur, bytes.fromhex(sib))
    return cur.hex() == root
