// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IZKVerifier {
    function verifyProof(bytes calldata proof) external view returns (bool);
}

contract ReputationOracle {

    struct CIDData {
        uint256 totalScore;
        uint256 reports;
        uint256 avgScore;
        string category;
    }

    // CID reputation
    mapping(bytes32 => CIDData) public cidReputation;

    // prevent duplicate reporter
    mapping(bytes32 => mapping(address => bool)) public reported;

    // prevent proof replay
    mapping(bytes32 => bool) public usedNullifiers;

    IZKVerifier public verifier;

    event CIDReported(
        bytes32 indexed cid,
        uint256 score,
        string category,
        address reporter
    );

    constructor(address _verifier) {
        verifier = IZKVerifier(_verifier);
    }

    function submitReport(
        bytes32 cid,
        uint256 score,
        string calldata category,
        bytes calldata proof,
        bytes32 nullifier
    ) external {

        require(score <= 100, "Score must be 0-100");
        require(!reported[cid][msg.sender], "Already reported");
        require(!usedNullifiers[nullifier], "Proof already used");

        // verify zk proof
        if(address(verifier) != address(0)){
            require(verifier.verifyProof(proof), "Invalid proof");
        }

        usedNullifiers[nullifier] = true;

        CIDData storage data = cidReputation[cid];

        data.totalScore += score;
        data.reports += 1;
        data.avgScore = data.totalScore / data.reports;
        data.category = category;

        reported[cid][msg.sender] = true;

        emit CIDReported(cid, score, category, msg.sender);
    }

    function getReputation(bytes32 cid)
        external
        view
        returns (
            uint256 avgScore,
            uint256 reports,
            string memory category
        )
    {
        CIDData memory data = cidReputation[cid];

        return (
            data.avgScore,
            data.reports,
            data.category
        );
    }
}