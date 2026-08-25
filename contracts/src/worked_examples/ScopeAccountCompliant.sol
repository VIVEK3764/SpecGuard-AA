// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "@account-abstraction/contracts/interfaces/IAccount.sol";
import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";

/// @title ScopeAccountCompliant (v0.7)
/// @notice Compliant ERC-4337 account for scope trace testing.
contract ScopeAccountCompliant is IAccount {
    address public immutable entryPoint;
    address public owner;

    constructor(address _entryPoint, address _owner) {
        entryPoint = _entryPoint;
        owner = _owner;
    }

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external pure override returns (uint256 validationData) {
        return 0; // VALIDATION_SUCCESS
    }
}
