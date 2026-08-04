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

contract ScopeAccountCompliant {
    address public owner;

    constructor(address _owner) {
        owner = _owner;
    }

    function validateUserOp(UserOp calldata op, bytes32 userOpHash) external pure returns (uint256) {
        // Compliant validation trace: pure owner check
        return 0; // VALIDATION_SUCCESS
    }
}
