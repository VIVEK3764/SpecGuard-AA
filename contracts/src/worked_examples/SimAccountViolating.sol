// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

struct UserOp {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    uint256 callGasLimit;
    uint256 verificationGasLimit;
    uint256 preVerificationGas;
    uint256 maxFeePerGas;
    uint256 maxPriorityFeePerGas;
    bytes paymasterAndData;
    bytes signature;
}

contract SimAccountViolating {
    address public owner;
    uint256 public simMode = 1;

    constructor(address _owner) {
        owner = _owner;
    }

    function toggleSimMode() external {
        simMode = 0;
    }

    function validateUserOp(UserOp calldata op, bytes32 userOpHash) external view returns (uint256) {
        // VIOLATION: Returns 0 during simulation, but returns 1 (FAILED) when simMode is toggled during execution
        if (simMode == 1) {
            return 0; // VALIDATION_SUCCESS in sim
        }
        return 1; // SIG_VALIDATION_FAILED in exec
    }
}
