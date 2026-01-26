// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MaterialTracker {
    address public owner;

    event MaterialScanned(
        bytes32 indexed materialIdHash,
        string materialId,
        string cid,
        bytes32 payloadHash,
        address indexed scanner,
        uint256 timestamp
    );

    constructor() {
        owner = msg.sender;
    }

    function scanMaterial(
        string memory materialId,
        string memory cid,
        bytes32 payloadHash
    ) public {
        require(msg.sender == owner, "Not authorized");
        bytes32 materialIdHash = keccak256(bytes(materialId));
        emit MaterialScanned(materialIdHash, materialId, cid, payloadHash, msg.sender, block.timestamp);
    }
}
