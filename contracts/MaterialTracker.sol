// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MaterialTracker {
    address public owner;

    event MaterialScanned(
        string id,
        address indexed scanner,
        uint256 timestamp,
        string location
    );

    constructor() {
        owner = msg.sender;
    }

    function scanMaterial(string memory id, string memory location) public {
        require(msg.sender == owner, "Not authorized");
        emit MaterialScanned(id, msg.sender, block.timestamp, location);
    }
}
