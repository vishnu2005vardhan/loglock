// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title LogAnchor - stores Merkle roots of log batches so they become tamper-evident
/// @notice Each anchor records the Merkle root of a batch of log entries, the range of
///         entries it covers, and the block timestamp. Anchors can never be changed.
contract LogAnchor {
    struct Anchor {
        bytes32 merkleRoot;   // Merkle root of the log batch
        uint64 firstIndex;    // index of the first log entry in the batch
        uint64 lastIndex;     // index of the last log entry in the batch
        uint64 timestamp;     // block time when anchored
        bool panic;           // true if triggered by a suspicious event (panic anchor)
    }

    address public immutable owner;
    mapping(address => bool) public agents;  // authorised log agents
    Anchor[] public anchors;

    event AgentSet(address indexed agent, bool allowed);
    event Anchored(uint256 indexed id, bytes32 merkleRoot, uint64 firstIndex, uint64 lastIndex, bool panic);
    event Heartbeat(address indexed agent, uint64 lastIndex, uint64 timestamp);

    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }
    modifier onlyAgent() { require(agents[msg.sender], "not agent"); _; }

    constructor() { owner = msg.sender; }

    function setAgent(address agent, bool allowed) external onlyOwner {
        agents[agent] = allowed;
        emit AgentSet(agent, allowed);
    }

    /// @notice Anchor a new batch. Batches must be contiguous, so gaps (deleted entries) are detectable.
    function anchor(bytes32 merkleRoot, uint64 firstIndex, uint64 lastIndex, bool panic) external onlyAgent {
        require(lastIndex >= firstIndex, "bad range");
        if (anchors.length > 0) {
            require(firstIndex == anchors[anchors.length - 1].lastIndex + 1, "non-contiguous batch");
        }
        anchors.push(Anchor(merkleRoot, firstIndex, lastIndex, uint64(block.timestamp), panic));
        emit Anchored(anchors.length - 1, merkleRoot, firstIndex, lastIndex, panic);
    }

    /// @notice Liveness signal; a missing heartbeat is itself evidence of tampering.
    function heartbeat(uint64 lastIndex) external onlyAgent {
        emit Heartbeat(msg.sender, lastIndex, uint64(block.timestamp));
    }

    function anchorCount() external view returns (uint256) { return anchors.length; }
}
