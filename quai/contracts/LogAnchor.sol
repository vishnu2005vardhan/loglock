// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/// @title SakshyaLog notary contract (Quai Network, Orchard Cyprus-1)
/// @notice A neutral notary for security logs. It stores ONLY fingerprints
///         (Merkle roots), never log contents, and enforces accountability
///         rules that even the company running the vault cannot overrule:
///   1. Batches of log lines must be continuous: no line range can be skipped.
///   2. Every anchor records its mode (normal / high-alert / panic / manual).
///   3. Public heartbeat: if the logger is silenced, the silence is visible on-chain.
///   4. Agent attestation: the hash of the logging agent's code is recorded,
///      so a swapped or modified agent is detectable.
///   5. Incident registry: when an incident is declared, the contract records
///      the time and the CERT-In 6-hour deadline, and later whether the report
///      was filed on time. The company cannot later claim it "found out late".
contract LogAnchor {
    address public immutable owner; // the vault's wallet
    uint64 public constant CERTIN_DEADLINE = 6 hours;

    enum Mode { Normal, HighAlert, Panic, Manual }

    struct Incident {
        string stream;
        bytes32 snapshotRoot;
        uint64 declaredAt;
        uint64 deadline;
        uint64 reportedAt;
        bytes32 reportHash;
        bool reportedOnTime;
        string note;
    }

    struct Attestation {
        bytes32 codeHash;
        bytes32 keyCommitment;
        uint64 timestamp;
    }

    mapping(bytes32 => uint256) public anchoredAt;      // root => block timestamp
    mapping(bytes32 => uint64) public lastSeq;           // keccak(stream) => last anchored line number
    mapping(bytes32 => uint64) public lastHeartbeat;     // keccak(stream) => block timestamp
    mapping(bytes32 => Attestation[]) private attestations;
    Incident[] private incidents;
    uint256 public batchCount;

    event Anchored(string stream, bytes32 indexed root, uint64 fromSeq, uint64 toSeq, Mode mode, uint256 timestamp);
    event Heartbeat(string stream, uint256 timestamp);
    event AgentAttested(string stream, bytes32 codeHash, bytes32 keyCommitment, bool codeChanged, uint256 timestamp);
    event IncidentDeclared(uint256 indexed id, string stream, bytes32 snapshotRoot, uint64 deadline);
    event IncidentReported(uint256 indexed id, bytes32 reportHash, bool onTime);

    modifier onlyOwner() {
        require(msg.sender == owner, "only the vault");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function anchorBatch(string calldata stream, bytes32 root, uint64 fromSeq, uint64 toSeq, Mode mode)
        external onlyOwner
    {
        bytes32 s = keccak256(bytes(stream));
        require(anchoredAt[root] == 0, "already anchored");
        require(fromSeq == lastSeq[s] + 1, "gap: batches must be continuous");
        require(toSeq >= fromSeq, "bad range");
        lastSeq[s] = toSeq;
        anchoredAt[root] = block.timestamp;
        batchCount++;
        emit Anchored(stream, root, fromSeq, toSeq, mode, block.timestamp);
    }

    function heartbeat(string calldata stream) external onlyOwner {
        lastHeartbeat[keccak256(bytes(stream))] = uint64(block.timestamp);
        emit Heartbeat(stream, block.timestamp);
    }

    function attestAgent(string calldata stream, bytes32 codeHash, bytes32 keyCommitment) external onlyOwner {
        Attestation[] storage list = attestations[keccak256(bytes(stream))];
        bool changed = list.length > 0 && list[0].codeHash != codeHash;
        list.push(Attestation(codeHash, keyCommitment, uint64(block.timestamp)));
        emit AgentAttested(stream, codeHash, keyCommitment, changed, block.timestamp);
    }

    function declareIncident(string calldata stream, bytes32 snapshotRoot, string calldata note)
        external onlyOwner returns (uint256 id)
    {
        id = incidents.length;
        uint64 nowTs = uint64(block.timestamp);
        incidents.push(Incident(stream, snapshotRoot, nowTs, nowTs + CERTIN_DEADLINE, 0, bytes32(0), false, note));
        if (anchoredAt[snapshotRoot] == 0) anchoredAt[snapshotRoot] = block.timestamp;
        emit IncidentDeclared(id, stream, snapshotRoot, nowTs + CERTIN_DEADLINE);
    }

    function markReported(uint256 id, bytes32 reportHash) external onlyOwner {
        Incident storage inc = incidents[id];
        require(inc.reportedAt == 0, "already reported");
        inc.reportedAt = uint64(block.timestamp);
        inc.reportHash = reportHash;
        inc.reportedOnTime = block.timestamp <= inc.deadline;
        emit IncidentReported(id, reportHash, inc.reportedOnTime);
    }

    // ---- read-only helpers for auditors ----
    function incidentCount() external view returns (uint256) { return incidents.length; }

    function getIncident(uint256 id) external view returns (Incident memory) { return incidents[id]; }

    function attestationCount(string calldata stream) external view returns (uint256) {
        return attestations[keccak256(bytes(stream))].length;
    }

    function getAttestation(string calldata stream, uint256 i) external view returns (Attestation memory) {
        return attestations[keccak256(bytes(stream))][i];
    }
}
