// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * AuditAnchor - Immutable batch root registry for the construction site audit layer.
 *
 * Design rationale
 * ----------------
 * The audit gateway accumulates N safety events per time window (default: 5s),
 * computes a Merkle root over their SHA-256 hashes, and stores only that root
 * here. Individual events remain in PostgreSQL; this contract is the tamper-evident
 * witness proving they have not been modified since the anchor was stored.
 *
 * On-chain per batch (≈ 200 bytes):
 *   merkleRoot  - root of SHA-256 event hashes
 *   metaHash    - hash of {batchId, windowStart, windowEnd, eventCount, siteId}
 *   blockTs     - block.timestamp (EVM-set, cannot be forged by caller)
 *   submitter   - gateway address (accountability)
 *
 * Threat mitigations addressed:
 *   T1 delete event    - hash absent from Merkle tree → verify FAIL
 *   T2 tamper payload  - SHA-256 mismatch → verify FAIL
 *   T3 insert fake     - Merkle proof rejects extra leaf
 *   T4 reorder batch   - window bounds in metaHash are immutable
 *   T5 replay          - batchId write-once (second store reverts)
 *   T6 single-org ctrl - authorisedSubmitters RBAC; extensible to multisig
 */
contract AuditAnchor {

    struct Anchor {
        bytes32 merkleRoot;
        bytes32 metaHash;
        uint256 blockTs;
        address submitter;
        bool    exists;
    }

    address public owner;
    mapping(address => bool) public authorisedSubmitters;
    mapping(string  => Anchor) private anchors;
    string[] public batchIds;

    event BatchAnchored(string indexed batchId, bytes32 merkleRoot, bytes32 metaHash,
                        uint256 blockTs, address submitter);
    event SubmitterAdded(address submitter);
    event SubmitterRemoved(address submitter);

    modifier onlyOwner()      { require(msg.sender == owner, "not owner"); _; }
    modifier onlyAuthorised() { require(authorisedSubmitters[msg.sender], "not authorised"); _; }

    constructor() {
        owner = msg.sender;
        authorisedSubmitters[msg.sender] = true;
        emit SubmitterAdded(msg.sender);
    }

    function addSubmitter(address s) external onlyOwner {
        authorisedSubmitters[s] = true;
        emit SubmitterAdded(s);
    }

    function removeSubmitter(address s) external onlyOwner {
        authorisedSubmitters[s] = false;
        emit SubmitterRemoved(s);
    }

    /**
     * storeBatchRoot - write-once anchor.
     * Reverts if batchId already exists (idempotency + tamper-resistance).
     */
    function storeBatchRoot(string calldata batchId,
                            bytes32 merkleRoot,
                            bytes32 metaHash) external onlyAuthorised {
        require(bytes(batchId).length > 0, "empty batchId");
        require(!anchors[batchId].exists,  "batchId already anchored");
        require(merkleRoot != bytes32(0),  "zero merkleRoot");

        anchors[batchId] = Anchor(merkleRoot, metaHash, block.timestamp, msg.sender, true);
        batchIds.push(batchId);
        emit BatchAnchored(batchId, merkleRoot, metaHash, block.timestamp, msg.sender);
    }

    function getAnchor(string calldata batchId)
        external view returns (bytes32, bytes32, uint256, address, bool)
    {
        Anchor storage a = anchors[batchId];
        return (a.merkleRoot, a.metaHash, a.blockTs, a.submitter, a.exists);
    }

    function batchCount() external view returns (uint256) { return batchIds.length; }

    function getBatchIds(uint256 start, uint256 n)
        external view returns (string[] memory)
    {
        uint256 end = start + n > batchIds.length ? batchIds.length : start + n;
        string[] memory r = new string[](end - start);
        for (uint256 i = start; i < end; i++) r[i - start] = batchIds[i];
        return r;
    }
}
